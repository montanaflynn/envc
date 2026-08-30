package resolve

import (
	"reflect"
	"strings"
	"testing"
)

func TestEncodeLine(t *testing.T) {
	tests := []struct {
		name, key, value, want string
	}{
		{"simple", "A", "b", "A=b"},
		{"empty", "A", "", `A=""`},
		{"url", "URL", "https://my-app.vercel.app/path?x=1", `URL="https://my-app.vercel.app/path?x=1"`},
		{"url plain", "URL", "https://my-app.vercel.app/path", "URL=https://my-app.vercel.app/path"},
		{"postgres", "DB", "postgres://postgres:postgres@localhost:5432/app", "DB=postgres://postgres:postgres@localhost:5432/app"},
		{"all safe chars", "K", "AZaz09_./:@+-", "K=AZaz09_./:@+-"},
		{"space", "K", "hello world", `K="hello world"`},
		{"hash", "K", "a#b", `K="a#b"`},
		{"equals", "K", "a=b", `K="a=b"`},
		{"newline", "K", "line1\nline2", `K="line1\nline2"`},
		{"cr tab", "K", "a\rb\tc", `K="a\rb\tc"`},
		{"backslash", "K", `C:\path`, `K="C:\\path"`},
		{"double quote", "K", `say "hi"`, `K="say \"hi\""`},
		{"single quote", "K", "it's", `K="it's"`},
		{"dollar", "K", "$HOME", `K="$HOME"`},
		{"unicode", "K", "héllo", `K="héllo"`},
		{"pem", "K", "-----BEGIN-----\nabc\n-----END-----\n", `K="-----BEGIN-----\nabc\n-----END-----\n"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EncodeLine(tt.key, tt.value); got != tt.want {
				t.Errorf("EncodeLine(%q, %q) = %s, want %s", tt.key, tt.value, got, tt.want)
			}
		})
	}
}

func TestEncode(t *testing.T) {
	tests := []struct {
		name string
		v    Vars
		want string
	}{
		{"nil", nil, ""},
		{"empty", Vars{}, ""},
		{"one", Vars{"A": "1"}, "A=1\n"},
		{"sorted", Vars{"Z": "1", "A": "2", "M": "x y"}, "A=2\nM=\"x y\"\nZ=1\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Encode(tt.v); got != tt.want {
				t.Errorf("Encode = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		want    Vars
		wantErr string
	}{
		{"empty", "", Vars{}, ""},
		{"only comments and blanks", "# hi\n\n   \n\t# there\n", Vars{}, ""},
		{"bare", "A=b\n", Vars{"A": "b"}, ""},
		{"no trailing newline", "A=b", Vars{"A": "b"}, ""},
		{"empty value", "A=\n", Vars{"A": ""}, ""},
		{"empty quoted", `A=""`, Vars{"A": ""}, ""},
		{"export prefix", "export A=b\nexport  B=c\n", Vars{"A": "b", "B": "c"}, ""},
		{"key named export", "export=1\n", Vars{"export": "1"}, ""},
		{"leading whitespace", "  A=b\n\tB=c\n", Vars{"A": "b", "B": "c"}, ""},
		{"spaces around equals", "A = b\n", Vars{"A": "b"}, ""},
		{"bare trailing whitespace trimmed", "A=b   \n", Vars{"A": "b"}, ""},
		{"bare with inner spaces", "A=hello world\n", Vars{"A": "hello world"}, ""},
		{"bare trailing comment", "A=b # comment\n", Vars{"A": "b"}, ""},
		{"bare tab comment", "A=b\t# comment\n", Vars{"A": "b"}, ""},
		{"bare hash without space is value", "A=a#b\n", Vars{"A": "a#b"}, ""},
		{"bare with equals", "A=b=c\n", Vars{"A": "b=c"}, ""},
		{"double quoted", `A="hello world"`, Vars{"A": "hello world"}, ""},
		{"double quoted escapes", `A="l1\nl2\rx\ty\\z\"q"`, Vars{"A": "l1\nl2\rx\ty\\z\"q"}, ""},
		{"double quoted unknown escape kept", `A="a\$b"`, Vars{"A": `a\$b`}, ""},
		{"double quoted hash inside", `A="a # b"`, Vars{"A": "a # b"}, ""},
		{"double quoted trailing comment", `A="b" # c`, Vars{"A": "b"}, ""},
		{"double quoted trailing comment no space", `A="b"#c`, Vars{"A": "b"}, ""},
		{"double quoted multiline", "A=\"l1\nl2\"\nB=2\n", Vars{"A": "l1\nl2", "B": "2"}, ""},
		{"single quoted", `A='hello world'`, Vars{"A": "hello world"}, ""},
		{"single quoted no escapes", `A='a\nb\\c'`, Vars{"A": `a\nb\\c`}, ""},
		{"single quoted hash inside", `A='a # b'`, Vars{"A": "a # b"}, ""},
		{"single quoted double inside", `A='say "hi"'`, Vars{"A": `say "hi"`}, ""},
		{"double quoted single inside", `A="it's"`, Vars{"A": "it's"}, ""},
		{"bare apostrophe", "A=it's\n", Vars{"A": "it's"}, ""},
		{"later wins", "A=1\nA=2\n", Vars{"A": "2"}, ""},
		{"crlf", "A=1\r\nB=\"x\"\r\n", Vars{"A": "1", "B": "x"}, ""},
		{"bom", "\ufeffA=1\n", Vars{"A": "1"}, ""},
		{"comment after export line", "export A=1 # c\n", Vars{"A": "1"}, ""},
		{"underscore keys", "_A1=x\n", Vars{"_A1": "x"}, ""},
		{"missing equals", "A\n", nil, "line 1"},
		{"missing equals later", "A=1\n\nB\n", nil, "line 3"},
		{"bad key", "1A=x\n", nil, "line 1"},
		{"key with dash", "A-B=x\n", nil, "line 1"},
		{"empty key", "=x\n", nil, "line 1"},
		{"unterminated double quote", "A=\"abc\n", nil, "line 1"},
		{"unterminated single quote", "A='abc\nB=1\n", nil, "line 1"},
		{"garbage after double quote", `A="b" c`, nil, "line 1"},
		{"garbage after single quote", `A='b'c`, nil, "line 1"},
		{"garbage line number", "A=1\nB=2\nC=\"x\" y\n", nil, "line 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.text)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not mention %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got == nil {
				t.Fatal("Parse returned nil Vars")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse(%q) = %#v, want %#v", tt.text, got, tt.want)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	v := Vars{
		"SIMPLE":   "abc",
		"EMPTY":    "",
		"SPACES":   "  lead and trail  ",
		"HASH":     "a # b",
		"QUOTES":   `she said "it's"`,
		"ESCAPES":  "a\nb\rc\td\\e",
		"PEM":      "-----BEGIN-----\nMIIB\n-----END-----\n",
		"UNICODE":  "héllo wörld ✓",
		"DOLLAR":   "${HOME}/x",
		"EQUALS":   "a=b=c",
		"BACKSL":   `\n literal`,
		"TRAILING": "x ",
	}
	text := Encode(v)
	got, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse(Encode(v)): %v\n%s", err, text)
	}
	if !reflect.DeepEqual(got, v) {
		t.Errorf("round trip mismatch:\n got %#v\nwant %#v\ntext:\n%s", got, v, text)
	}
}

func TestMerge(t *testing.T) {
	a := Vars{"A": "1", "B": "1"}
	b := Vars{"B": "2", "C": "2"}
	got := Merge(a, nil, b)
	want := Vars{"A": "1", "B": "2", "C": "2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Merge = %v, want %v", got, want)
	}
	if a["B"] != "1" {
		t.Error("Merge mutated its input")
	}
	if got := Merge(); got == nil || len(got) != 0 {
		t.Errorf("Merge() = %#v, want empty non-nil", got)
	}
	got["A"] = "changed"
	if a["A"] != "1" {
		t.Error("Merge result aliases input")
	}
}
