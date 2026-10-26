package credenshare

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"unicode"
)

// The EFF publishes this digest's file; the generator must draw from exactly that list.
const effLargeWordListSHA256 = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"

func TestTheWordListIsTheEFFsByteForByte(t *testing.T) {
	sum := sha256.Sum256([]byte(effLargeWordList))
	if got := hex.EncodeToString(sum[:]); got != effLargeWordListSHA256 {
		t.Fatalf("eff_large_wordlist.txt digest %s, want %s", got, effLargeWordListSHA256)
	}
	list := wordList()
	if len(list) != 7776 || list[0] != "abacus" || list[7775] != "zoom" {
		t.Fatalf("%d words, %q .. %q", len(list), list[0], list[len(list)-1])
	}
}

// The same strength table is asserted in all four SDKs, and matches the app and the CLI: bits
// to four places, and the label.
func TestStrengthMatchesTheAppAndTheOtherSDKs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bits  float64
		want  string
		label string
	}{
		{"password 20, all four sets (94)", 20 * math.Log2(94), "131.0918", "Very Strong"},
		{"password 8, lowercase only (26)", 8 * math.Log2(26), "37.6035", "Weak"},
		{"password 12, letters and numbers (62)", 12 * math.Log2(62), "71.4504", "Strong"},
		{"password 10, numbers and symbols (42)", 10 * math.Log2(42), "53.9232", "Fair"},
		{"passphrase 5 words", passphraseBits(7776, 5, false), "64.6241", "Strong"},
		{"passphrase 3 words", passphraseBits(7776, 3, false), "38.7744", "Weak"},
		{"passphrase 4 words with a digit", passphraseBits(7776, 4, true), "57.0212", "Fair"},
		{"passphrase 7 words", passphraseBits(7776, 7, false), "90.4737", "Very Strong"},
		{"pin 6", 6 * math.Log2(10), "19.9316", "Weak"},
		{"pin 12", 12 * math.Log2(10), "39.8631", "Weak"},
	} {
		if got := fmt.Sprintf("%.4f", tc.bits); got != tc.want {
			t.Errorf("%s: %s bits, want %s", tc.name, got, tc.want)
		}
		if got := StrengthOf(tc.bits); got != tc.label {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.label)
		}
	}
}

func TestTheDefaultPasswordIsTheApps(t *testing.T) {
	g, err := GeneratePassword(PasswordOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Value) != 20 || g.Strength != "Very Strong" || math.Abs(g.Bits-20*math.Log2(94)) > 1e-9 {
		t.Fatalf("%d chars, %.4f bits, %s", len(g.Value), g.Bits, g.Strength)
	}
	pool := passwordUppercase + passwordLowercase + passwordNumbers + PasswordSymbols
	if len(pool) != 94 {
		t.Fatalf("the default pool is %d characters, want 94", len(pool))
	}
	for _, c := range g.Value {
		if !strings.ContainsRune(pool, c) {
			t.Fatalf("%q is outside the pool", c)
		}
	}
}

func TestPasswordOptionsShapeThePool(t *testing.T) {
	g, err := GeneratePassword(PasswordOptions{Length: 64, NoUppercase: true, NoSymbols: true, Exclude: "0123abc"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range g.Value {
		if unicode.IsUpper(c) || strings.ContainsRune(PasswordSymbols+"0123abc", c) {
			t.Fatalf("%q should have been left out", c)
		}
	}
	// 26 lower + 10 digits, less the 7 excluded.
	if math.Abs(g.Bits-64*math.Log2(29)) > 1e-9 {
		t.Fatalf("bits %.4f", g.Bits)
	}
}

func TestPasswordOptionsOutOfRangeAreRefused(t *testing.T) {
	for _, opts := range []PasswordOptions{
		{Length: 7}, {Length: 129}, {Length: -1},
		{NoUppercase: true, NoLowercase: true, NoNumbers: true, NoSymbols: true},
		{NoUppercase: true, NoLowercase: true, NoSymbols: true, Exclude: "0123456789"},
	} {
		if _, err := GeneratePassword(opts); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("%+v gave %v", opts, err)
		}
	}
}

func TestTheDefaultPassphraseIsFiveHyphenatedWords(t *testing.T) {
	g, err := GeneratePassphrase(PassphraseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Four EFF words carry a hyphen of their own (drop-down, felt-tip, t-shirt, yo-yo), so a
	// hyphenated passphrase can split into more than five parts, never fewer.
	if strings.Count(g.Value, "-") < 4 || g.Strength != "Strong" || math.Abs(g.Bits-5*math.Log2(7776)) > 1e-9 {
		t.Fatalf("%q, %.4f bits, %s", g.Value, g.Bits, g.Strength)
	}
	known := map[string]bool{}
	for _, w := range wordList() {
		known[w] = true
	}
	spaced, err := GeneratePassphrase(PassphraseOptions{Words: 12, Separator: "space"})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range strings.Split(spaced.Value, " ") {
		if !known[w] {
			t.Fatalf("%q is not on the list", w)
		}
	}
}

func TestPassphraseOptions(t *testing.T) {
	g, err := GeneratePassphrase(PassphraseOptions{
		Words: 4, Separator: "space", Capitalize: true, IncludeNumber: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Split(g.Value, " ")
	if len(words) < 4 {
		t.Fatalf("%q", g.Value)
	}
	digits := 0
	for _, w := range words {
		if !unicode.IsUpper([]rune(w)[0]) {
			t.Fatalf("%q is not capitalised", w)
		}
	}
	for _, c := range g.Value {
		if unicode.IsDigit(c) {
			digits++
		}
	}
	if digits != 1 || g.Strength != "Fair" {
		t.Fatalf("%q: %d digits, %s", g.Value, digits, g.Strength)
	}
	for name, sep := range passphraseSeparators {
		g, err := GeneratePassphrase(PassphraseOptions{Words: 3, Separator: name})
		if err != nil {
			t.Fatal(err)
		}
		if sep != "" && strings.Count(g.Value, sep) < 2 {
			t.Fatalf("%s: %q", name, g.Value)
		}
	}
}

func TestPassphraseOptionsOutOfRangeAreRefused(t *testing.T) {
	for _, opts := range []PassphraseOptions{{Words: 2}, {Words: 13}, {Separator: "comma"}} {
		if _, err := GeneratePassphrase(opts); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("%+v gave %v", opts, err)
		}
	}
}

func TestPINs(t *testing.T) {
	g, err := GeneratePIN(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Value) != 6 || strings.Trim(g.Value, "0123456789") != "" || g.Strength != "Weak" {
		t.Fatalf("%q, %s", g.Value, g.Strength)
	}
	for _, n := range []int{3, 13, -2} {
		if _, err := GeneratePIN(n); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("%d gave %v", n, err)
		}
	}
}

func TestDrawsAreUniform(t *testing.T) {
	// A % reduction of random bytes would skew this. 60,000 digits: each should come up about
	// 6,000 times, and 20% either way is far outside what chance produces at this size.
	counts := map[rune]int{}
	for i := 0; i < 5000; i++ {
		g, err := GeneratePIN(12)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range g.Value {
			counts[c]++
		}
	}
	for d := '0'; d <= '9'; d++ {
		if counts[d] < 4800 || counts[d] > 7200 {
			t.Fatalf("digit %c came up %d times in 60,000", d, counts[d])
		}
	}
}

func TestAGeneratedValueIsWithheldFromPrinting(t *testing.T) {
	g, err := GeneratePassword(PasswordOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{g.String(), g.GoString()} {
		if strings.Contains(rendered, g.Value) {
			t.Fatalf("%s contains the value", rendered)
		}
	}
}
