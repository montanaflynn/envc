// Package resolve converts resolved config values to KEY=value text and back,
// using the .env encoding described in the README.
package resolve

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Vars is a resolved environment: export name → value.
type Vars map[string]string

var (
	// plainValue is the set of values that need no quoting.
	plainValue = regexp.MustCompile(`^[A-Za-z0-9_./:@+-]+$`)
	// keyPattern is the allowed export name (same as envfile.KeyPattern; this
	// package imports nothing else from the module).
	keyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Encode renders vars as .env text, keys sorted, trailing newline.
func Encode(v Vars) string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(EncodeLine(k, v[k]))
		b.WriteByte('\n')
	}
	return b.String()
}

// EncodeLine renders one KEY=value line (no newline). Unquoted when the value
// matches ^[A-Za-z0-9_./:@+-]+$, otherwise double-quoted with \n \r \t \\ \"
// escapes.
func EncodeLine(key, value string) string {
	if plainValue.MatchString(value) {
		return key + "=" + value
	}
	var b strings.Builder
	b.WriteString(key)
	b.WriteString(`="`)
	for _, r := range value {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Parse reads .env text: blank lines and # comments ignored, optional
// "export " prefix, single- or double-quoted or bare values, the escapes
// EncodeLine produces. Later keys win.
//
// Hand-written conventions are accepted too: a UTF-8 BOM, CRLF line endings,
// whitespace around "=", a trailing "# comment" after a bare value when
// preceded by whitespace, single-quoted values (no escapes), and
// double-quoted values spanning multiple lines. Malformed lines are errors
// that name the line number.
func Parse(text string) (Vars, error) {
	text = strings.TrimPrefix(text, "\ufeff")
	lines := strings.Split(text, "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	vars := Vars{}
	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		line := strings.TrimLeft(lines[i], " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "export"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			line = strings.TrimLeft(rest, " \t")
		}
		key, rest, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: malformed line (expected KEY=value)", lineNo)
		}
		key = strings.TrimRight(key, " \t")
		if !keyPattern.MatchString(key) {
			return nil, fmt.Errorf("line %d: invalid key %q", lineNo, key)
		}
		rest = strings.TrimLeft(rest, " \t")

		var value string
		switch {
		case strings.HasPrefix(rest, `"`):
			var tail string
			var err error
			value, tail, i, err = parseDoubleQuoted(lines, i, rest[1:])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
			if err := checkTail(tail); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
		case strings.HasPrefix(rest, `'`):
			end := strings.IndexByte(rest[1:], '\'')
			if end < 0 {
				return nil, fmt.Errorf("line %d: unterminated single-quoted value", lineNo)
			}
			value = rest[1 : 1+end]
			if err := checkTail(rest[2+end:]); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
		default:
			value = stripComment(rest)
		}
		vars[key] = value
	}
	return vars, nil
}

// parseDoubleQuoted consumes a double-quoted value whose opening quote has
// already been removed from body (the remainder of lines[i]). It may span
// lines. It returns the decoded value, the text after the closing quote, and
// the index of the line holding the closing quote.
func parseDoubleQuoted(lines []string, i int, body string) (value, tail string, endLine int, err error) {
	var b strings.Builder
	for {
		for j := 0; j < len(body); j++ {
			c := body[j]
			switch c {
			case '"':
				return b.String(), body[j+1:], i, nil
			case '\\':
				if j+1 >= len(body) {
					b.WriteByte(c)
					continue
				}
				j++
				switch body[j] {
				case 'n':
					b.WriteByte('\n')
				case 'r':
					b.WriteByte('\r')
				case 't':
					b.WriteByte('\t')
				case '\\':
					b.WriteByte('\\')
				case '"':
					b.WriteByte('"')
				default:
					b.WriteByte('\\')
					b.WriteByte(body[j])
				}
			default:
				b.WriteByte(c)
			}
		}
		i++
		if i >= len(lines) {
			return "", "", i, fmt.Errorf("unterminated double-quoted value")
		}
		b.WriteByte('\n')
		body = lines[i]
	}
}

// checkTail verifies that only whitespace or a comment follows a closing quote.
func checkTail(tail string) error {
	t := strings.TrimLeft(tail, " \t")
	if t == "" || strings.HasPrefix(t, "#") {
		return nil
	}
	return fmt.Errorf("unexpected text after quoted value: %q", strings.TrimRight(tail, " \t"))
}

// stripComment removes a trailing "# comment" from a bare value when the "#"
// is preceded by whitespace, then trims trailing whitespace.
func stripComment(s string) string {
	for j := 0; j < len(s); j++ {
		if s[j] == '#' && j > 0 && (s[j-1] == ' ' || s[j-1] == '\t') {
			s = s[:j]
			break
		}
	}
	return strings.TrimRight(s, " \t")
}

// Merge returns a new Vars where later arguments win.
func Merge(layers ...Vars) Vars {
	out := Vars{}
	for _, layer := range layers {
		for k, v := range layer {
			out[k] = v
		}
	}
	return out
}
