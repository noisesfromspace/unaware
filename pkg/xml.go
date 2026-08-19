package pkg

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
)

type xmlProcessor struct {
	config        AppConfig
	methodFactory func() *masker
}

func newXMLProcessor(config AppConfig) *xmlProcessor {
	return &xmlProcessor{
		config: config,
		methodFactory: func() *masker {
			return newMasker(config.Masker)
		},
	}
}

// Process determines if the XML can be processed concurrently or if it should
// fall back to a serial approach. Concurrency is only possible if the XML
// consists of a simple list of repeating elements directly under the root.
func (xp *xmlProcessor) Process(r io.Reader, w io.Writer) error {
	var buf bytes.Buffer
	tee := io.TeeReader(r, &buf)

	decoder := xml.NewDecoder(tee)
	root, firstChild, _, ok := detectXMLListPattern(decoder)

	// We must combine the buffer (which was consumed by the pattern detector)
	// with the original reader to provide the full XML stream to the next stage.
	combinedReader := io.MultiReader(&buf, r)

	if ok {
		// If a repeating pattern is found, process the elements concurrently.
		runner := newConcurrentRunner(xp.methodFactory, xp.config)
		runner.Root = root.Name.Local
		chunkDecoder := xml.NewDecoder(combinedReader)
		chunkReader := xp.createXMLChunkReader(chunkDecoder, root.Name, firstChild.Name, xp.config.FirstN)
		assembler := &xmlAssembler{Root: root}
		return runner.Run(w, chunkReader, assembler)
	}

	// For complex or non-list XML, fall back to a serial, streaming processor.
	// Note: Subsetting with -first is not supported in this mode.
	serialDecoder := xml.NewDecoder(combinedReader)
	return xp.processSerially(serialDecoder, w)
}

type xmlAssembler struct {
	Root    xml.StartElement
	encoder *xml.Encoder
}

func (a *xmlAssembler) WriteStart(w io.Writer) error {
	a.encoder = xml.NewEncoder(w)
	a.encoder.Indent("", "  ")
	if _, err := w.Write([]byte(xml.Header)); err != nil {
		return err
	}
	return a.encoder.EncodeToken(a.Root)
}

func (a *xmlAssembler) WriteItem(w io.Writer, item any, isFirst bool) error {
	itemMap, ok := item.(map[string]any)
	if !ok {
		return fmt.Errorf("xml assembler expected map[string]any, but got %T", item)
	}
	for key, val := range itemMap {
		if valMap, ok := val.(map[string]any); ok {
			return mapToXML(key, valMap, a.encoder)
		}
	}
	return fmt.Errorf("unexpected structure in item map for XML assembler")
}

func (a *xmlAssembler) WriteEnd(w io.Writer) error {
	if err := a.encoder.EncodeToken(a.Root.End()); err != nil {
		return err
	}
	return a.encoder.Flush()
}

func mapToXML(key string, m map[string]any, enc *xml.Encoder) error {
	start := xml.StartElement{Name: xml.Name{Local: key}}
	for k, v := range m {
		if after, ok := strings.CutPrefix(k, "-"); ok {
			attrName := after
			start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: attrName}, Value: fmt.Sprintf("%v", v)})
		}
	}
	if err := enc.EncodeToken(start); err != nil {
		return err
	}
	if text, ok := m["#text"]; ok {
		if err := enc.EncodeToken(xml.CharData(fmt.Sprintf("%v", text))); err != nil {
			return err
		}
	}
	for k, v := range m {
		if !strings.HasPrefix(k, "-") && k != "#text" {
			if slice, ok := v.([]any); ok {
				for _, item := range slice {
					if itemMap, ok := item.(map[string]any); ok {
						if err := mapToXML(k, itemMap, enc); err != nil {
							return err
						}
					}
				}
			} else if nestedMap, ok := v.(map[string]any); ok {
				if err := mapToXML(k, nestedMap, enc); err != nil {
					return err
				}
			} else {
				if err := mapToXML(k, map[string]any{"#text": v}, enc); err != nil {
					return err
				}
			}
		}
	}
	return enc.EncodeToken(start.End())
}

// detectXMLListPattern heuristically checks if an XML document is a simple list.
// It does this by checking if the first two elements directly under the root have
// the same tag name. This is an optimization to enable concurrent processing for
// simple list-like XML structures while gracefully falling back to a serial
// processor for more complex ones. It does not parse the full document.
func detectXMLListPattern(decoder *xml.Decoder) (xml.StartElement, xml.StartElement, xml.StartElement, bool) {
	var root, firstChild, secondChild xml.StartElement
	depth := 0
	for {
		token, err := decoder.Token()
		if err != nil {
			return root, firstChild, secondChild, false
		}
		switch se := token.(type) {
		case xml.StartElement:
			depth++
			switch depth {
			case 1:
				root = se.Copy()
			case 2:
				if firstChild.Name.Local == "" {
					firstChild = se.Copy()
				} else {
					secondChild = se.Copy()
					// If the first two children have the same name, we assume it's a list.
					if firstChild.Name.Local == secondChild.Name.Local {
						return root, firstChild, secondChild, true
					}
					return root, firstChild, secondChild, false
				}
			}
		case xml.EndElement:
			depth--
			if depth < 1 {
				return root, firstChild, secondChild, false
			}
		}
	}
}

func (xp *xmlProcessor) createXMLChunkReader(decoder *xml.Decoder, rootName, listItemName xml.Name, firstN int) chunkReader {
	var started bool
	recordCount := 0
	return func() (any, error) {
		for {
			if firstN > 0 && recordCount >= firstN {
				return nil, io.EOF
			}
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			switch se := token.(type) {
			case xml.StartElement:
				if !started {
					if se.Name.Local == rootName.Local && se.Name.Space == rootName.Space {
						started = true
						continue
					}
				}
				if se.Name.Local == listItemName.Local {
					elementMap, err := decodeElementToMap(decoder, se)
					if err != nil {
						return nil, err
					}
					recordCount++
					return map[string]any{se.Name.Local: elementMap}, nil
				}
			case xml.EndElement:
				if se.Name.Local == rootName.Local && se.Name.Space == rootName.Space {
					return nil, io.EOF
				}
			}
		}
	}
}

func decodeElementToMap(decoder *xml.Decoder, start xml.StartElement) (map[string]any, error) {
	m := make(map[string]any)
	for _, attr := range start.Attr {
		m["-"+attr.Name.Local] = attr.Value
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch se := token.(type) {
		case xml.StartElement:
			nestedMap, err := decodeElementToMap(decoder, se)
			if err != nil {
				return nil, err
			}
			key := se.Name.Local
			if existing, ok := m[key]; ok {
				if slice, ok := existing.([]any); ok {
					m[key] = append(slice, nestedMap)
				} else {
					m[key] = []any{existing, nestedMap}
				}
			} else {
				m[key] = nestedMap
			}
		case xml.CharData:
			text := strings.TrimSpace(string(se))
			if text != "" {
				m["#text"] = text
			}
		case xml.EndElement:
			if se.Name.Local == start.Name.Local && se.Name.Space == start.Name.Space {
				return m, nil
			}
		}
	}
}

func (xp *xmlProcessor) processSerially(decoder *xml.Decoder, w io.Writer) error {
	encoder := xml.NewEncoder(w)
	encoder.Indent("", "  ")
	serialMasker := newMasker(xp.config.Masker)
	var path []string
	var attrSegs [][]string
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch se := token.(type) {
		case xml.StartElement:
			path = append(path, se.Name.Local)
			segs := make([]string, 0, len(se.Attr))
			for _, attr := range se.Attr {
				segs = append(segs, attr.Name.Local+"="+attr.Value)
			}
			sort.Strings(segs)
			attrSegs = append(attrSegs, segs)
			startElem := se.Copy()
			for i := range startElem.Attr {
				attr := &startElem.Attr[i]
				fullKey := strings.Join(path, ".") + "." + attr.Name.Local
				if shouldMask(fullKey, xp.config.IncludeGlobs, xp.config.ExcludeGlobs) {
					maskedValue := serialMasker.mask(attr.Value)
					attr.Value = fmt.Sprintf("%v", maskedValue)
				}
			}
			if err := encoder.EncodeToken(startElem); err != nil {
				return err
			}
		case xml.CharData:
			trimmedData := strings.TrimSpace(string(se))
			if len(trimmedData) > 0 {
				fullKey := strings.Join(path, ".")
				if shouldMaskAny([]string{fullKey, xmlPathWithAttrs(path, attrSegs)}, xp.config.IncludeGlobs, xp.config.ExcludeGlobs) {
					maskedValue := serialMasker.mask(trimmedData)
					maskedString := fmt.Sprintf("%v", maskedValue)
					if err := encoder.EncodeToken(xml.CharData(maskedString)); err != nil {
						return err
					}
				} else {
					if err := encoder.EncodeToken(se); err != nil {
						return err
					}
				}
			} else {
				if err := encoder.EncodeToken(se); err != nil {
					return err
				}
			}
		case xml.EndElement:
			if len(path) > 0 {
				path = path[:len(path)-1]
				attrSegs = attrSegs[:len(attrSegs)-1]
			}
			if err := encoder.EncodeToken(token); err != nil {
				return err
			}
		default:
			if err := encoder.EncodeToken(token); err != nil {
				return err
			}
		}
	}
	return encoder.Flush()
}

// xmlPathWithAttrs builds a key where each element's attributes are appended as
// "attrName=attrValue" segments after the element name. For example, the element
// <field name="Body"> nested as Message/field/value yields
// "Message.field.name=Body.value". This lets glob patterns match on attribute
// values, not just element names.
func xmlPathWithAttrs(path []string, attrSegs [][]string) string {
	parts := make([]string, 0, len(path)*2)
	for i, name := range path {
		parts = append(parts, name)
		if i < len(attrSegs) {
			parts = append(parts, attrSegs[i]...)
		}
	}
	return strings.Join(parts, ".")
}
