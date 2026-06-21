package hdwallet

import "testing"

func TestParsePathTable(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		wantLen int
		wantErr bool
	}{
		{"standard", "m/44'/60'/0'/0/0", 5, false},
		{"lowercase h hardened", "m/44h/60h/0h/0/0", 5, false},
		{"uppercase H hardened", "m/44H/0H/0H/0/0", 5, false},
		{"bare root", "m", 0, false},
		{"out of range element", "m/2147483648", 0, true},
		{"non-numeric element", "m/abc/0", 0, true},
		{"missing m prefix", "44'/60'/0'", 0, true},
		{"empty string", "", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePath(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parsePath(%q) = %v, want error", tc.path, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePath(%q) unexpected error: %v", tc.path, err)
			}
			if len(got) != tc.wantLen {
				t.Errorf("parsePath(%q) len = %d, want %d", tc.path, len(got), tc.wantLen)
			}
		})
	}
}

// FuzzParsePath asserts parsePath never panics on arbitrary input; it may return
// an error, but a malformed path must never crash the deriver.
func FuzzParsePath(f *testing.F) {
	for _, seed := range []string{
		"m/44'/60'/0'/0/0",
		"m/0h/0H",
		"m",
		"",
		"m/2147483648",
		"m//0",
		"x/1/2",
		"m/-1",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, path string) {
		_, _ = parsePath(path) // must not panic
	})
}
