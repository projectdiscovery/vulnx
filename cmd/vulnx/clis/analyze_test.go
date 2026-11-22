package clis

import "testing"

func TestAnalyzeArgs(t *testing.T) {
	for _, c := range []struct {
		args    []string
		wantErr bool
	}{
		{nil, false},
		{[]string{"help"}, false},
		{[]string{"is_kev:true"}, true},
		{[]string{"help", "x"}, true},
	} {
		if err := analyzeCmd.Args(analyzeCmd, c.args); (err != nil) != c.wantErr {
			t.Errorf("%q: %v, wantErr %v", c.args, err, c.wantErr)
		}
	}
}
