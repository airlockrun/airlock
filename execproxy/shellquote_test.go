package execproxy

import "testing"

func TestShellQuote(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "''"},
		{"hello", "hello"},
		{"with space", "'with space'"},
		{"a/b/c.txt", "a/b/c.txt"},
		{"--flag=value", "--flag=value"},
		{"don't", `'don'\''t'`},
		{"$VAR", "'$VAR'"},
		{"a|b", "'a|b'"},
		{"a;b", "'a;b'"},
		{"a&b", "'a&b'"},
		{"`cmd`", "'`cmd`'"},
		{"a*b", "'a*b'"},
		{"~user", "'~user'"},
	}
	for _, c := range cases {
		got := ShellQuote(c.in)
		if got != c.want {
			t.Errorf("ShellQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestJoinCommand(t *testing.T) {
	cases := []struct {
		cmd  string
		args []string
		want string
	}{
		{"ls", nil, "ls"},
		{"ls", []string{"-la"}, "ls -la"},
		{"ls", []string{"-la", "my dir"}, "ls -la 'my dir'"},
		{"echo a | grep b", nil, "echo a | grep b"},
		{"kubectl", []string{"get", "pods", "-o", "json"}, "kubectl get pods -o json"},
	}
	for _, c := range cases {
		got := JoinCommand(c.cmd, c.args)
		if got != c.want {
			t.Errorf("JoinCommand(%q, %v) = %q, want %q", c.cmd, c.args, got, c.want)
		}
	}
}
