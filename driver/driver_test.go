package driver

import "testing"

func TestNormalizeMainProcessRestartPolicy(t *testing.T) {
	tests := []struct {
		input string
		want  string
		bad   bool
	}{
		{input: "", want: "never"},
		{input: "Never", want: "never"},
		{input: "ON-FAILURE", want: "on-failure"},
		{input: "always", want: "always"},
		{input: "sometimes", bad: true},
	}
	for _, tt := range tests {
		got, err := NormalizeMainProcessRestartPolicy(tt.input)
		if tt.bad {
			if err == nil {
				t.Errorf("NormalizeMainProcessRestartPolicy(%q) accepted invalid value", tt.input)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("NormalizeMainProcessRestartPolicy(%q)=(%q,%v), want %q", tt.input, got, err, tt.want)
		}
	}
}
