package pkg

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/dgraph-io/ristretto"
	"github.com/gobwas/glob"
	"github.com/google/uuid"
	"github.com/jacoelho/banking/iban"
	"github.com/nyaruka/phonenumbers"
	"github.com/theplant/luhn"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/araddon/dateparse"
)

var Now = time.Now

// AppConfig holds the complete configuration for a masking operation.
type AppConfig struct {
	Format       string   `json:"format"`
	CPUCount     int      `json:"cpu_count"`
	Include      []string `json:"include"`
	Exclude      []string `json:"exclude"`
	FirstN       int      `json:"first_n"`
	Masker       MaskerConfig
	IncludeGlobs []glob.Glob `json:"-"`
	ExcludeGlobs []glob.Glob `json:"-"`
}

type processor interface {
	Process(r io.Reader, w io.Writer) error
}

// MaskingMethod is an enum for the available masking methods.
type MaskingMethod string

const (
	MethodRandom        MaskingMethod = "random"
	MethodDeterministic MaskingMethod = "deterministic"
)

// MaskerConfig holds all the configuration for a masker.
type MaskerConfig struct {
	Method       MaskingMethod
	Salt         []byte // Only used for deterministic method
	PrefixMasked bool
}

// Start initiates the masking process based on the provided configuration.
func Start(r io.Reader, w io.Writer, config AppConfig) error {
	// Pre-compile glob patterns once at startup for performance during masking.
	// This avoids re-parsing the patterns for every key in the input data.
	for _, pattern := range config.Include {
		g, err := glob.Compile(pattern, '.')
		if err != nil {
			return fmt.Errorf("invalid include pattern %q: %w", pattern, err)
		}
		config.IncludeGlobs = append(config.IncludeGlobs, g)
	}
	for _, pattern := range config.Exclude {
		g, err := glob.Compile(pattern, '.')
		if err != nil {
			return fmt.Errorf("invalid exclude pattern %q: %w", pattern, err)
		}
		config.ExcludeGlobs = append(config.ExcludeGlobs, g)
	}

	config.Masker.PrefixMasked = len(config.Exclude) > 0

	var p processor
	switch config.Format {
	case "json":
		p = newJSONProcessor(config)
	case "xml":
		p = newXMLProcessor(config)
	case "csv":
		p = newCSVProcessor(config)
	case "text":
		p = newTextProcessor(config)
	default:
		return fmt.Errorf("unsupported format: %s", config.Format)
	}

	return p.Process(r, w)
}

func shouldMask(key string, include, exclude []glob.Glob) bool {
	return shouldMaskAny([]string{key}, include, exclude)
}

// shouldMaskAny is like shouldMask but tests a field against multiple candidate
// keys. A value is masked if any key matches an include pattern (or no include
// patterns are set) and no key matches an exclude pattern. Exclude always wins.
func shouldMaskAny(keys []string, include, exclude []glob.Glob) bool {
	matches := func(globs []glob.Glob) bool {
		for _, k := range keys {
			for _, g := range globs {
				if g.Match(k) {
					return true
				}
			}
		}
		return false
	}
	if len(exclude) > 0 && matches(exclude) {
		return false
	}
	if len(include) > 0 {
		return matches(include)
	}
	return true
}

type seeder interface {
	SeedFaker(f *gofakeit.Faker, input any)
	SeedFakerForWord(f *gofakeit.Faker, word string)
}

type deterministicSeeder struct{ salt []byte }

func (ds *deterministicSeeder) SeedFaker(f *gofakeit.Faker, input any) {
	var seedInput string
	switch v := input.(type) {
	case string:
		seedInput = v
	case json.Number:
		seedInput = v.String()
	case bool:
		seedInput = strconv.FormatBool(v)
	default:
		seedInput = "[UNSUPPORTED]"
	}
	f.Rand.Seed(ds.createSeed(seedInput))
}

func (ds *deterministicSeeder) SeedFakerForWord(f *gofakeit.Faker, word string) {
	f.Rand.Seed(ds.createSeed(word))
}

// createSeed generates a deterministic seed using HMAC-SHA256 with input truncation.
// This ensures strong collision resistance for privacy, while the truncation
// provides a performance optimization for very long inputs.
func (ds *deterministicSeeder) createSeed(s string) int64 {
	// Truncate the input string to limit hashing overhead for long inputs.
	if len(s) > 64 {
		s = s[:64]
	}

	mac := hmac.New(sha256.New, ds.salt)
	mac.Write([]byte(s))
	seedBytes := mac.Sum(nil)
	return int64(binary.BigEndian.Uint64(seedBytes))
}

type randomSeeder struct{}

func (rs *randomSeeder) SeedFaker(f *gofakeit.Faker, input any)          { /* No-op */ }
func (rs *randomSeeder) SeedFakerForWord(f *gofakeit.Faker, word string) { /* No-op */ }

// concurrentRunner orchestrates concurrent processing of data chunks.
type concurrentRunner struct {
	methodFactory func() *masker
	config        AppConfig // The entire AppConfig is now passed
	Root          string    // Used for XML to define the root element name for chunking
}

// newConcurrentRunner creates a new concurrentRunner.
func newConcurrentRunner(methodFactory func() *masker, config AppConfig) *concurrentRunner {
	return &concurrentRunner{
		methodFactory: methodFactory,
		config:        config,
	}
}

type masker struct {
	faker           *gofakeit.Faker
	seeder          seeder
	cache           *ristretto.Cache
	prefixMasked    bool
	dateLayouts     []string
	emailRegex      *regexp.Regexp
	numLikeRegex    *regexp.Regexp
	ulidRegex       *regexp.Regexp
	ksuidRegex      *regexp.Regexp
	creditCardRegex *regexp.Regexp
	currencyRegex   *regexp.Regexp
}

func newMasker(config MaskerConfig) *masker {
	m := &masker{
		dateLayouts: []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02 15:04:05",
			"2006-01-02",
			"2006-01",
			"01/02/2006",
			time.RFC1123,
		},
		emailRegex:      regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`),
		numLikeRegex:    regexp.MustCompile(`^[\d\s-]+$`),
		ulidRegex:       regexp.MustCompile(`(?i)^[0-7][0-9a-hjkmnp-tv-z]{25}$`),
		ksuidRegex:      regexp.MustCompile(`^[a-zA-Z0-9]{27}$`),
		creditCardRegex: regexp.MustCompile(`^(?:\d[ -]*?){13,16}$`),
		currencyRegex:   regexp.MustCompile(`^(\$|€|£|USD|EUR|GBP)\s*(\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?)$`),
	}

	switch config.Method {
	case MethodDeterministic:
		m.seeder = &deterministicSeeder{salt: config.Salt}
		cache, err := ristretto.NewCache(&ristretto.Config{
			NumCounters: 1e7,     // number of keys to track frequency of (10M).
			MaxCost:     1 << 30, // maximum cost of cache (1GB).
			BufferItems: 64,      // number of keys per Get buffer.
		})
		if err != nil {
			panic(err)
		}
		m.cache = cache
		m.faker = gofakeit.NewUnlocked(1)
	case MethodRandom:
		m.seeder = &randomSeeder{}
		m.faker = gofakeit.New(0)
	default:
		panic("unknown masking method") // Should not happen with validation
	}

	m.prefixMasked = config.PrefixMasked

	return m
}

func (m *masker) mask(value any) any {
	if value == nil {
		return nil
	}

	// Use cache for deterministic masking to avoid re-computing for the same input.
	if m.cache != nil {
		cacheKey := m.getCacheKey(value)
		if maskedValue, ok := m.cache.Get(cacheKey); ok {
			return maskedValue
		}
	}

	maskedValue := m.maybePrefixMasked(m.maskUncached(value))

	if m.cache != nil {
		cacheKey := m.getCacheKey(value)
		m.cache.Set(cacheKey, maskedValue, 1)
	}

	return maskedValue
}

func (m *masker) maybePrefixMasked(masked any) any {
	if !m.prefixMasked || masked == nil {
		return masked
	}
	switch v := masked.(type) {
	case string:
		if strings.HasPrefix(v, "mask-") {
			return v
		}
		return "mask-" + v
	default:
		return "mask-" + fmt.Sprintf("%v", masked)
	}
}

func (m *masker) getCacheKey(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	default:
		return "" // Should not happen for supported types
	}
}
func (m *masker) generateAlphanumericN(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[m.faker.Rand.Intn(len(charset))]
	}
	generated := string(b)
	return generated
}

func (m *masker) maskUncached(value any) any {
	m.seeder.SeedFaker(m.faker, value)
	switch v := value.(type) {
	case string:
		s := v
		if strings.TrimSpace(s) == "" {
			return s
		}
		if _, err := uuid.Parse(s); err == nil {
			return m.faker.UUID()
		}
		if err := iban.Validate(strings.ReplaceAll(s, " ", "")); err == nil {
			// Generate a fake IBAN that looks plausible
			return m.faker.Regex(`[A-Z]{2}\d{2}[A-Z\d]{4}\d{7,12}`)
		}
		if m.creditCardRegex.MatchString(s) {
			// Clean the string of any separators before Luhn check
			if num, err := strconv.Atoi(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "-", "")); err == nil && luhn.Valid(num) {
				return m.faker.CreditCardNumber(nil)
			}
		}
		if _, err := phonenumbers.Parse(s, ""); err == nil {
			return m.faker.Phone()
		}
		if m.currencyRegex.MatchString(s) {
			matches := m.currencyRegex.FindStringSubmatch(s)
			if len(matches) == 3 {
				currencySymbol := matches[1]
				// Generate a new random amount
				newAmount := fmt.Sprintf("%.2f", m.faker.Price(0, 1000))
				return currencySymbol + " " + newAmount
			}
		}
		if m.ulidRegex.MatchString(s) {
			return m.faker.Regex(`[0-7][0-9A-HJKMNP-TV-Z]{25}`)
		}
		if m.ksuidRegex.MatchString(s) {
			return m.generateAlphanumericN(27)
		}
		if _, err := url.ParseRequestURI(s); err == nil {
			return m.faker.URL()
		}
		if m.emailRegex.MatchString(s) {
			return m.faker.Email()
		}
		if _, err := net.ParseMAC(s); err == nil {
			return m.faker.MacAddress()
		}
		if ip := net.ParseIP(s); ip != nil {
			if ip.To4() != nil {
				return m.faker.IPv4Address()
			}
			return m.faker.IPv6Address()
		}
		if _, err := strconv.ParseInt(s, 10, 64); err == nil {
			return m.faker.Numerify(strings.Repeat("#", len(s)))
		}
		if _, err := strconv.ParseFloat(s, 64); err == nil {
			parts := strings.Split(s, ".")
			integerPart := parts[0]
			fractionalPart := ""
			if len(parts) > 1 {
				fractionalPart = parts[1]
			}
			template := strings.Repeat("#", len(integerPart))
			if fractionalPart != "" {
				template += "." + strings.Repeat("#", len(fractionalPart))
			}
			return m.faker.Numerify(template)
		}
		for _, layout := range m.dateLayouts {
			if _, err := time.Parse(layout, s); err == nil {
				return m.faker.DateRange(Now().AddDate(-5, 0, 0), Now()).Format(layout)
			}
		}
		if m.numLikeRegex.MatchString(s) {
			var result strings.Builder
			for _, char := range s {
				if char >= '0' && char <= '9' {
					result.WriteString(strconv.Itoa(m.faker.Rand.Intn(10)))
				} else {
					result.WriteRune(char)
				}
			}
			return result.String()
		}
		if _, err := dateparse.ParseAny(s); err == nil {
			return m.faker.DateRange(Now().AddDate(-5, 0, 0), Now()).Format(time.RFC3339)
		}
		words := strings.Split(s, " ")
		maskedWords := make([]string, len(words))
		caser := cases.Title(language.English)
		for i, word := range words {
			m.seeder.SeedFakerForWord(m.faker, word)
			maskedWord := m.faker.Word()
			if len(word) > 0 && word[0] >= 'A' && word[0] <= 'Z' {
				maskedWords[i] = caser.String(maskedWord)
			} else {
				maskedWords[i] = maskedWord
			}
		}
		return strings.Join(maskedWords, " ")
	case json.Number:
		s := v.String()
		if strings.Contains(s, ".") {
			parts := strings.Split(s, ".")
			template := strings.Repeat("#", len(parts[0])) + "." + strings.Repeat("#", len(parts[1]))
			return json.Number(m.faker.Numerify(template))
		}
		return json.Number(m.faker.Numerify(strings.Repeat("#", len(s))))
	case bool:
		return m.faker.Bool()
	}
	return "[MASKED UNSUPPORTED TYPE]"
}
