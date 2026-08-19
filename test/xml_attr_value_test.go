package test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"unaware/pkg"
)

// TestXMLValueBasedMatching verifies that glob patterns can match on XML
// attribute values using the "attrName=attrValue" path segment convention.
func TestXMLValueBasedMatching(t *testing.T) {
	salt := []byte("xml-attr-value-salt")

	// Repeating children -> concurrent path.
	listInput := `<Message>
  <field name="Header"><value>header-secret-111</value></field>
  <field name="Body"><value>body-secret-222</value></field>
  <field name="Footer"><value>footer-secret-333</value></field>
</Message>`

	// First two children differ -> serial path.
	serialInput := `<Message>
  <field name="Body"><value>body-secret-222</value></field>
  <other name="X"><value>other-secret-999</value></other>
</Message>`

	for _, tc := range []struct {
		name, input string
		keep        []string
	}{
		{"concurrent", listInput, []string{"header-secret-111", "footer-secret-333"}},
		{"serial", serialInput, []string{"other-secret-999"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			appConfig := pkg.AppConfig{
				Format:   "xml",
				CPUCount: 1,
				Include:  []string{"Message.field.name=Body.value"},
				Masker: pkg.MaskerConfig{
					Method: pkg.MethodDeterministic,
					Salt:   salt,
				},
			}

			var buf bytes.Buffer
			err := pkg.Start(strings.NewReader(tc.input), &buf, appConfig)
			require.NoError(t, err)
			out := buf.String()

			require.NotContains(t, out, "body-secret-222", "Body's value should be masked")
			require.Contains(t, out, `name="Body"`, "the name attribute value itself should be preserved")
			for _, v := range tc.keep {
				require.Contains(t, out, v, "unrelated value %q should be kept", v)
			}
		})
	}
}
