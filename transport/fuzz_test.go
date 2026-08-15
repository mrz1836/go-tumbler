package transport

import (
	"testing"
)

// FuzzDecodeResponse asserts decodeResponse never panics and that any output it
// accepts decodes to the fixed 20-byte HMAC-SHA1 response length.
func FuzzDecodeResponse(f *testing.F) {
	f.Add(string(respHex()))
	f.Add("")
	f.Add("zz23456789abcdef0123456789abcdef01234567") // 40 chars, non-hex
	f.Add("ABCDEF0123456789ABCDEF0123456789ABCDEF01") // 40 chars, uppercase

	f.Fuzz(func(t *testing.T, s string) {
		resp, err := decodeResponse([]byte(s))
		if err != nil {
			return
		}
		if len(resp) != 20 {
			t.Fatalf("accepted response decoded to %d bytes, want 20", len(resp))
		}
	})
}

// FuzzParseYkmanVersion asserts parseYkmanVersion never panics on arbitrary
// tool output; when it succeeds the version is a plausible triple.
func FuzzParseYkmanVersion(f *testing.F) {
	f.Add("5.9.2")
	f.Add("YubiKey Manager (ykman) version: 5.10.0")
	f.Add("no version here")
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		v, err := parseYkmanVersion(s)
		if err != nil {
			return
		}
		for i, n := range v {
			if n < 0 {
				t.Fatalf("parsed negative version component v[%d]=%d", i, n)
			}
		}
	})
}
