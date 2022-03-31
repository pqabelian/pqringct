package pqringct

import (
	"testing"
)

func Test_rejectionUniformWithQc(t *testing.T) {
	type args struct {
		seed   []byte
		length int
	}
	tests := []struct {
		name string
		args args
		want []int32
	}{
		{
			"Test1",
			args{
				seed:   []byte("This is the seed for testing"),
				length: DefaultPP.paramDC,
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rejectionUniformWithQc(tt.args.seed, tt.args.length)
			//if !reflect.DeepEqual(got, tt.want) {
			//	t.Errorf("rejectionUniformWithQc() = %v, want %v", got, tt.want)
			//}
			for i := 0; i < len(got); i++ {
				if got[i] < -(DefaultPP.paramQC-1)>>1 || got[i] > (DefaultPP.paramQC-1)>>1 {
					t.Errorf("rejectionUniformWithQc() sample a value %v", got[i])
				}
			}
		})
	}
}

func Test_rejectionUniformWithQa(t *testing.T) {
	type args struct {
		seed   []byte
		length int
	}
	tests := []struct {
		name string
		args args
		want []int32
	}{
		{
			"Test1",
			args{
				seed:   []byte("This is the seed for testing"),
				length: DefaultPP.paramDA,
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rejectionUniformWithQa(tt.args.seed, tt.args.length, DefaultPP.paramQA)
			//if !reflect.DeepEqual(got, tt.want) {
			//	t.Errorf("rejectionUniformWithQc() = %v, want %v", got, tt.want)
			//}
			for i := 0; i < len(got); i++ {
				tmp := (DefaultPP.paramQA - 1) >> 1
				if got[i] < -tmp || got[i] > tmp {
					t.Errorf("rejectionUniformWithQc() sample a value %v", got[i])
				}
			}
		})
	}
}
