package test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"unaware/pkg"
)

func init() {
	pkg.Now = func() time.Time {
		return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	}
}

func TestFilteringScenarios(t *testing.T) {
	deterministicMaskerConfig := pkg.MaskerConfig{
		Method: pkg.MethodDeterministic,
		Salt:   []byte("static-salt"),
	}

	jsonInput := `{
	"user": {
		"id": "user-123",
		"personal": {
			"name": "John Doe",
			"email": "john.doe@example.com"
		},
		"metadata": {
			"last_login": "2023-10-27T10:00:00Z",
			"ip_address": "203.0.113.195"
		}
	},
	"transaction_id": "txn-abc-456"
}`

	xmlInput := `<root>
	<user id="user-xyz">
		<personal>
			<name>Jane Doe</name>
			<email>jane.doe@example.com</email>
		</personal>
		<metadata>
			<last_login>2023-11-01T12:30:00Z</last_login>
			<ip_address>198.51.100.22</ip_address>
		</metadata>
	</user>
	<transaction_id>txn-def-789</transaction_id>
</root>`

	testCases := []struct {
		name        string
		format      string
		input       string
		include     []string
		exclude     []string
		expected    []string // Substrings to check for in the output
		notExpected []string // Substrings that should NOT be in the output
	}{
		// JSON Scenarios
		{
			name:   "JSON - No Flags (Mask All)",
			format: "json",
			input:  jsonInput,
			expected: []string{
				`"id": "chapter"`,
				`"name": "Cute His"`,
				`"email": "clevelandsenger@sawayn.io"`,
				`"last_login": "2023-01-26T11:37:04Z"`,
				`"ip_address": "113.186.161.194"`,
				`"transaction_id": "without"`,
			},
			notExpected: []string{
				`"id": "user-123"`,
				`"name": "John Doe"`,
			},
		},
		{
			name:    "JSON - Exclude Only (Blacklist)",
			format:  "json",
			input:   jsonInput,
			exclude: []string{"**.id", "**.ip_address"},
			expected: []string{
				`"id": "user-123"`,
				`"ip_address": "203.0.113.195"`,
				`"name": "mask-Cute His"`,
				`"transaction_id": "mask-without"`,
			},
		},
		{
			name: "JSON - Include Only (Whitelist)", format: "json",
			input:   jsonInput,
			include: []string{"user.personal.*"},
			expected: []string{
				`"id": "user-123"`,
				`"name": "Cute His"`,
				`"email": "clevelandsenger@sawayn.io"`,
				`"ip_address": "203.0.113.195"`,
			},
		},
		{
			name:    "JSON - Combined Include and Exclude",
			format:  "json",
			input:   jsonInput,
			include: []string{"user.*", "user.personal.*", "user.metadata.*"},
			exclude: []string{"user.id", "user.metadata.last_login"},
			expected: []string{
				`"id": "user-123"`,
				`"name": "mask-Cute His"`,
				`"last_login": "2023-10-27T10:00:00Z"`,
				`"transaction_id": "txn-abc-456"`,
			},
		},
		// XML Scenarios
		{
			name:   "XML - No Flags (Mask All)",
			format: "xml",
			input:  xmlInput,
			expected: []string{
				`<user id="constantly">`,
				`<name>Finally His</name>`,
				`<email>alfredofritsch@dickinson.net</email>`,
				`<last_login>2023-01-13T21:11:17Z</last_login>`, `<ip_address>238.108.102.226</ip_address>`,
				`<transaction_id>her</transaction_id>`,
			},
		},
		{
			name:    "XML - Exclude Attributes and Elements",
			format:  "xml",
			input:   xmlInput,
			exclude: []string{"root.user.id", "root.user.personal.name"},
			expected: []string{
				`<user id="user-xyz">`, // Not masked
				`<name>Jane Doe</name>`,
				`<email>mask-alfredofritsch@dickinson.net</email>`,
			},
		},
		{
			name:    "XML - Include with Wildcard",
			format:  "xml",
			input:   xmlInput,
			include: []string{"root.user.metadata.*"},
			expected: []string{
				`<name>Jane Doe</name>`,
				`<last_login>2023-01-13T21:11:17Z</last_login>`,
				`<ip_address>238.108.102.226</ip_address>`,
			},
		},
		{
			name:    "XML - Combined Include and Exclude",
			format:  "xml",
			input:   xmlInput,
			include: []string{"root.user.*", "root.user.personal.*", "root.user.metadata.*"},
			exclude: []string{"root.user.id", "root.user.metadata.ip_address"},
			expected: []string{
				`<user id="user-xyz">`,
				`<name>mask-Finally His</name>`,
				`<ip_address>198.51.100.22</ip_address>`,
				`<transaction_id>txn-def-789</transaction_id>`,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			appConfig := pkg.AppConfig{
				Format:   tc.format,
				CPUCount: 1,
				Include:  tc.include,
				Exclude:  tc.exclude,
				Masker:   deterministicMaskerConfig,
			}

			var buf bytes.Buffer
			err := pkg.Start(strings.NewReader(tc.input), &buf, appConfig)
			require.NoError(t, err)

			output := buf.String()
			for _, expected := range tc.expected {
				require.Contains(t, output, expected, "Output should contain expected substring")
			}
			for _, notExpected := range tc.notExpected {
				require.NotContains(t, output, notExpected, "Output should not contain unexpected substring")
			}
		})
	}
}
