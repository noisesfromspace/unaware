package pkg

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

type chunkReader func() (any, error)
type assembler interface {
	WriteStart(w io.Writer) error
	WriteItem(w io.Writer, item any, isFirst bool) error
	WriteEnd(w io.Writer) error
}

type job struct {
	index int
	data  any
}

type result struct {
	index int
	data  any
}

// Run orchestrates the concurrent masking process.
func (cr *concurrentRunner) Run(w io.Writer, crr chunkReader, a assembler) error {
	jobs := make(chan job)
	results := make(chan result)

	var wg sync.WaitGroup
	for range cr.config.CPUCount {
		wg.Add(1)
		go cr.worker(&wg, jobs, results)
	}

	var dispatchErr error
	go func() {
		jobIndex := 0
		for {
			dataChunk, err := crr()
			if err == io.EOF {
				break
			}
			if err != nil {
				dispatchErr = err
				break
			}
			jobs <- job{index: jobIndex, data: dataChunk}
			jobIndex++
		}
		close(jobs)
	}()

	go func() { wg.Wait(); close(results) }()

	if err := a.WriteStart(w); err != nil {
		return err
	}

	resultsBuffer := make(map[int]any)
	nextIndexToWrite := 0
	isFirst := true

	for res := range results {
		resultsBuffer[res.index] = res.data
		for {
			maskedData, ok := resultsBuffer[nextIndexToWrite]
			if !ok {
				break
			}
			if err := a.WriteItem(w, maskedData, isFirst); err != nil {
				return err
			}
			isFirst = false
			delete(resultsBuffer, nextIndexToWrite)
			nextIndexToWrite++
		}
	}

	if dispatchErr != nil {
		return dispatchErr
	}

	return a.WriteEnd(w)
}

func (cr *concurrentRunner) worker(wg *sync.WaitGroup, jobs <-chan job, results chan<- result) {
	defer wg.Done()
	workerMasker := cr.methodFactory()
	for j := range jobs {
		results <- result{index: j.index, data: cr.recursiveMask(workerMasker, cr.Root, cr.Root, j.data)}
	}
}

func (cr *concurrentRunner) recursiveMask(m *masker, key, enrichedKey string, data any) any {
	switch v := data.(type) {
	case json.Number, string, bool, nil:
		if shouldMaskAny([]string{key, enrichedKey}, cr.config.IncludeGlobs, cr.config.ExcludeGlobs) {
			return m.mask(v)
		}
		return v
	case map[string]any:
		// Attributes from the XML decoder are prefixed with '-'. Collect them as
		// "attrName=attrValue" segments so globs can match on attribute values.
		var attrSegs []string
		for k, val := range v {
			if name, ok := strings.CutPrefix(k, "-"); ok {
				attrSegs = append(attrSegs, name+"="+fmt.Sprintf("%v", val))
			}
		}
		sort.Strings(attrSegs)
		attrJoin := strings.Join(attrSegs, ".")
		maskedMap := make(map[string]any, len(v))
		for k, value := range v {
			if k == "#text" {
				// This is the text content of the parent element (e.g., the "2002" in <year>2002</year>).
				// The key for filtering is the parent's key, which is already in the 'key' variable.
				if shouldMaskAny([]string{key, enrichedKey}, cr.config.IncludeGlobs, cr.config.ExcludeGlobs) {
					maskedMap[k] = m.mask(value)
				} else {
					maskedMap[k] = value
				}
			} else {
				// This is a nested element or an attribute.
				// Attributes from the XML decoder are prefixed with '-'.
				isAttr := strings.HasPrefix(k, "-")
				nestedKey := strings.TrimPrefix(k, "-")
				fullKey := nestedKey
				enrichedFullKey := nestedKey
				if key != "" {
					fullKey = key + "." + nestedKey
				}
				if enrichedKey != "" {
					enrichedFullKey = enrichedKey + "." + nestedKey
					if !isAttr && attrJoin != "" {
						enrichedFullKey = enrichedKey + "." + attrJoin + "." + nestedKey
					}
				}
				maskedMap[k] = cr.recursiveMask(m, fullKey, enrichedFullKey, value)
			}
		}
		return maskedMap
	case []any:
		maskedSlice := make([]any, len(v))
		for i, value := range v {
			maskedSlice[i] = cr.recursiveMask(m, key, enrichedKey, value)
		}
		return maskedSlice
	default:
		if shouldMaskAny([]string{key, enrichedKey}, cr.config.IncludeGlobs, cr.config.ExcludeGlobs) {
			return m.mask(v)
		}
		return v
	}
}
