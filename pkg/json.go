package pkg

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type jsonProcessor struct {
	config        AppConfig
	methodFactory func() *masker
}

// newJSONProcessor creates a new processor for JSON files.
func newJSONProcessor(config AppConfig) *jsonProcessor {
	return &jsonProcessor{
		config: config,
		methodFactory: func() *masker {
			return newMasker(config.Masker)
		},
	}
}

func (jp *jsonProcessor) Process(r io.Reader, w io.Writer) error {
	br := newPeekingReader(r)
	firstChar, err := br.PeekFirstChar()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}

	if firstChar == '[' {
		return jp.processRootArray(br, w)
	}

	// Note: -first is not applied for single root object JSON as there is only one "record".
	return jp.processConcurrentObject(br, w)
}

func (jp *jsonProcessor) processRootArray(r io.Reader, w io.Writer) error {
	runner := newConcurrentRunner(jp.methodFactory, jp.config)
	decoder := json.NewDecoder(r)
	decoder.UseNumber()
	_, _ = decoder.Token() // consume '['
	recordCount := 0
	chunkReader := func() (any, error) {
		if jp.config.FirstN > 0 && recordCount >= jp.config.FirstN {
			return nil, io.EOF
		}
		if !decoder.More() {
			_, err := decoder.Token()
			if err != nil && err != io.EOF {
				return nil, err
			}
			return nil, io.EOF
		}
		var chunk any
		err := decoder.Decode(&chunk)
		recordCount++
		return chunk, err
	}
	return runner.Run(w, chunkReader, &jsonAssembler{isRootArray: true})
}

// processConcurrentObject handles the masking of a single root JSON object.
//
// This method intentionally reads the entire object into memory rather than
// streaming it. This is a design trade-off to ensure correctness and simplify the
// implementation, avoiding the complexity and bugs associated with manually
// handling nested structures.
//
// The primary, performance-critical use case—a root-level array of objects—is
// handled by `processRootArray` which *is* fully streaming and concurrent.
// This function serves as a robust fallback for the less common case of a
// single, large root object.
func (jp *jsonProcessor) processConcurrentObject(r io.Reader, w io.Writer) error {
	decoder := json.NewDecoder(r)
	decoder.UseNumber()
	encoder := json.NewEncoder(w)
	encoder.SetIndent("  ", "  ")

	var rawData map[string]any
	if err := decoder.Decode(&rawData); err != nil {
		return fmt.Errorf("error decoding root JSON object: %w", err)
	}

	m := newMasker(jp.config.Masker)
	maskedData := jp.recursiveMask(m, "", rawData)

	if err := encoder.Encode(maskedData); err != nil {
		return fmt.Errorf("error encoding masked JSON object: %w", err)
	}

	return nil
}

type jsonAssembler struct {
	isRootArray bool
}

func (a *jsonAssembler) WriteStart(w io.Writer) error {
	if a.isRootArray {
		_, err := w.Write([]byte("["))
		return err
	}
	return nil
}

func (a *jsonAssembler) WriteItem(w io.Writer, item any, isFirst bool) error {
	if !isFirst {
		if _, err := w.Write([]byte(",")); err != nil {
			return err
		}
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("  ", "  ")
	return encoder.Encode(item)
}

func (a *jsonAssembler) WriteEnd(w io.Writer) error {
	if a.isRootArray {
		_, err := w.Write([]byte("]\n"))
		return err
	}
	return nil
}

type peekingReader struct {
	r    io.Reader
	peek []byte
	err  error
}

func newPeekingReader(r io.Reader) *peekingReader { return &peekingReader{r: r} }

func (pr *peekingReader) Read(p []byte) (n int, err error) {
	if len(pr.peek) > 0 {
		n = copy(p, pr.peek)
		pr.peek = pr.peek[n:]
		return n, nil
	}
	if pr.err != nil {
		return 0, pr.err
	}
	return pr.r.Read(p)
}
func (pr *peekingReader) PeekFirstChar() (byte, error) {
	if pr.err != nil {
		return 0, pr.err
	}
	if len(pr.peek) > 0 {
		for i, c := range pr.peek {
			if !isWhitespace(c) {
				pr.peek = pr.peek[i:]
				return c, nil
			}
		}
	}
	buf := make([]byte, 128)
	for {
		n, err := pr.r.Read(buf)
		if err != nil {
			pr.err = err
			return 0, err
		}
		for i := range n {
			c := buf[i]
			if !isWhitespace(c) {
				pr.peek = buf[i:n]
				return c, nil
			}
		}
	}
}
func isWhitespace(c byte) bool { return c == ' ' || c == '\n' || c == '\r' || c == '\t' }

func (jp *jsonProcessor) recursiveMask(m *masker, key string, data any) any {
	switch v := data.(type) {
	case json.Number:
		if shouldMask(key, jp.config.IncludeGlobs, jp.config.ExcludeGlobs) {
			s := v.String()
			var masked any
			if strings.Contains(s, ".") {
				parts := strings.Split(s, ".")
				template := strings.Repeat("#", len(parts[0])) + "." + strings.Repeat("#", len(parts[1]))
				masked = json.Number(m.faker.Numerify(template))
			} else {
				masked = json.Number(m.faker.Numerify(strings.Repeat("#", len(s))))
			}
			return m.maybePrefixMasked(masked)
		}
		return v
	case string, bool, nil:
		if shouldMask(key, jp.config.IncludeGlobs, jp.config.ExcludeGlobs) {
			return m.mask(v)
		}
		return v
	case map[string]any:
		maskedMap := make(map[string]any, len(v))
		for k, value := range v {
			fullKey := k
			if key != "" {
				fullKey = key + "." + k
			}
			maskedMap[k] = jp.recursiveMask(m, fullKey, value)
		}
		return maskedMap
	case []any:
		maskedSlice := make([]any, len(v))
		for i, value := range v {
			maskedSlice[i] = jp.recursiveMask(m, key, value)
		}
		return maskedSlice
	default:
		return v
	}
}
