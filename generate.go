package credenshare

// A local generator for passwords, passphrases and PINs (Gitea #404): the app's three modes and
// the CLI's, with nothing sent anywhere. A generated secret never leaves this process unless the
// caller sends it.

import (
	"crypto/rand"
	_ "embed"
	"fmt"
	"math"
	"math/big"
	"strings"
	"sync"
	"unicode"
)

// The character sets of the app's generator, so the three produce the same kind of password and
// report the same strength for it.
const (
	passwordUppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	passwordLowercase = "abcdefghijklmnopqrstuvwxyz"
	passwordNumbers   = "0123456789"

	// PasswordSymbols are the symbols a password may draw from.
	PasswordSymbols = "!@#$%^&*()_+-=[]{}|;:,.<>?`\"~/\\'"
)

// A Generated secret, with its strength. Value is the secret itself.
type Generated struct {
	Value string
	// Bits is the entropy of what the options generate, not of this one value.
	Bits float64
	// Strength is StrengthOf(Bits): Weak, Fair, Strong or Very Strong.
	Strength string
}

// String withholds the value, so printing a Generated does not spill the secret into a log.
func (g Generated) String() string {
	return fmt.Sprintf("<Generated %s, %.0f bits (value withheld)>", g.Strength, g.Bits)
}

// GoString covers %#v, which would otherwise print Value.
func (g Generated) GoString() string { return g.String() }

// PasswordOptions shape GeneratePassword. The zero value is the app's default: 20 characters
// from upper and lower case, numbers and symbols.
type PasswordOptions struct {
	// Length is 8 to 128. Zero means 20.
	Length int

	NoUppercase bool
	NoLowercase bool
	NoNumbers   bool
	NoSymbols   bool

	// Exclude lists characters to leave out, such as "0Ol1" for a password read aloud.
	Exclude string
}

// GeneratePassword draws a password uniformly from the chosen characters.
func GeneratePassword(opts PasswordOptions) (Generated, error) {
	n := opts.Length
	if n == 0 {
		n = 20
	}
	if n < 8 || n > 128 {
		return Generated{}, fmt.Errorf("%w: a password is 8 to 128 characters, got %d", ErrInvalidArgument, n)
	}
	var pool []rune
	for _, set := range []struct {
		off   bool
		chars string
	}{
		{opts.NoUppercase, passwordUppercase}, {opts.NoLowercase, passwordLowercase},
		{opts.NoNumbers, passwordNumbers}, {opts.NoSymbols, PasswordSymbols},
	} {
		if set.off {
			continue
		}
		for _, c := range set.chars {
			if !strings.ContainsRune(opts.Exclude, c) {
				pool = append(pool, c)
			}
		}
	}
	if len(pool) == 0 {
		return Generated{}, fmt.Errorf("%w: those options leave no characters to choose from", ErrInvalidArgument)
	}
	value, err := randomRunes(pool, n)
	if err != nil {
		return Generated{}, err
	}
	return generated(value, float64(n)*math.Log2(float64(len(pool)))), nil
}

// passphraseSeparators are the separators by the names the app and the CLI use.
var passphraseSeparators = map[string]string{
	"hyphen": "-", "space": " ", "period": ".", "underscore": "_", "none": "",
}

// PassphraseOptions shape GeneratePassphrase. The zero value is the app's default: five words
// joined by hyphens.
type PassphraseOptions struct {
	// Words is 3 to 12. Zero means 5.
	Words int

	// Separator is "hyphen", "space", "period", "underscore" or "none". Empty means hyphen.
	Separator string

	// Capitalize upper-cases each word's first letter. It changes the look, not the strength:
	// every word gets one, so it is not random.
	Capitalize bool

	// IncludeNumber appends one random digit to one random word.
	IncludeNumber bool
}

// GeneratePassphrase draws words uniformly from the EFF long word list (7,776 words, 12.9 bits
// each).
func GeneratePassphrase(opts PassphraseOptions) (Generated, error) {
	n := opts.Words
	if n == 0 {
		n = 5
	}
	if n < 3 || n > 12 {
		return Generated{}, fmt.Errorf("%w: a passphrase is 3 to 12 words, got %d", ErrInvalidArgument, n)
	}
	name := opts.Separator
	if name == "" {
		name = "hyphen"
	}
	separator, ok := passphraseSeparators[name]
	if !ok {
		return Generated{}, fmt.Errorf("%w: Separator is hyphen, space, period, underscore or none, not %q",
			ErrInvalidArgument, name)
	}

	list := wordList()
	picked := make([]string, n)
	for i := range picked {
		j, err := randomIndex(len(list))
		if err != nil {
			return Generated{}, err
		}
		word := list[j]
		if opts.Capitalize {
			runes := []rune(word)
			runes[0] = unicode.ToUpper(runes[0])
			word = string(runes)
		}
		picked[i] = word
	}
	if opts.IncludeNumber {
		where, err := randomIndex(n)
		if err != nil {
			return Generated{}, err
		}
		digit, err := randomIndex(10)
		if err != nil {
			return Generated{}, err
		}
		picked[where] += fmt.Sprint(digit)
	}
	return generated(strings.Join(picked, separator), passphraseBits(len(list), n, opts.IncludeNumber)), nil
}

// passphraseBits counts each word as log2 of the list; the digit adds log2(10) and its position
// log2(words).
func passphraseBits(listSize, n int, withNumber bool) float64 {
	bits := float64(n) * math.Log2(float64(listSize))
	if withNumber {
		bits += math.Log2(10) + math.Log2(float64(n))
	}
	return bits
}

// GeneratePIN draws a PIN of length digits, 4 to 12. Zero means 6.
func GeneratePIN(length int) (Generated, error) {
	if length == 0 {
		length = 6
	}
	if length < 4 || length > 12 {
		return Generated{}, fmt.Errorf("%w: a PIN is 4 to 12 digits, got %d", ErrInvalidArgument, length)
	}
	value, err := randomRunes([]rune(passwordNumbers), length)
	if err != nil {
		return Generated{}, err
	}
	return generated(value, float64(length)*math.Log2(10)), nil
}

// StrengthOf is the app generator's label for a number of bits.
func StrengthOf(bits float64) string {
	switch {
	case bits < 40:
		return "Weak"
	case bits < 60:
		return "Fair"
	case bits < 80:
		return "Strong"
	}
	return "Very Strong"
}

func generated(value string, bits float64) Generated {
	return Generated{Value: value, Bits: bits, Strength: StrengthOf(bits)}
}

// randomIndex draws uniformly from [0, n). crypto/rand.Int rejection-samples, so there is no
// modulo bias: 2^32 mod 94 is not 0, and a plain % would favour the first characters.
func randomIndex(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("reading randomness: %w", err)
	}
	return int(v.Int64()), nil
}

func randomRunes(pool []rune, n int) (string, error) {
	var b strings.Builder
	for i := 0; i < n; i++ {
		j, err := randomIndex(len(pool))
		if err != nil {
			return "", err
		}
		b.WriteRune(pool[j])
	}
	return b.String(), nil
}

// The EFF long word list, byte-for-byte as the EFF publishes it (dice numbers, a tab, the word).
// By the Electronic Frontier Foundation, licensed under CC BY 3.0 US; see NOTICE.
//
//go:embed eff_large_wordlist.txt
var effLargeWordList string

var wordList = sync.OnceValue(func() []string {
	lines := strings.Split(strings.TrimSpace(effLargeWordList), "\n")
	list := make([]string, 0, len(lines))
	for _, line := range lines {
		if _, word, ok := strings.Cut(strings.TrimSpace(line), "\t"); ok {
			list = append(list, word)
		}
	}
	return list
})
