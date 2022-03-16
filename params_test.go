package pqringct

import (
	"testing"
)

func TestPublicParameter_reduce(t *testing.T) {

	type args struct {
		a int64
	}
	tests := []struct {
		name   string
		args   args
		want   int32
	}{
		{
			name: "1",
			args: args{a: 1},
			want:1,
		},
		{
			name: "4294962690",
			args: args{a: 4294962690},
			want:1,
		},
		{
			name: "-1",
			args: args{a: -1},
			want:-1,
		},
		{
			name: "-4294962690",
			args: args{a: -4294962690},
			want:-1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pp := DefaultPP
			if got := pp.reduce(tt.args.a); got != tt.want {
				t.Errorf("reduceBigInt() = %v, want %v", got, tt.want)
			}
		})
	}
}
