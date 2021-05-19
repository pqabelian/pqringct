package pqringct

import (
	"reflect"
	"testing"
)

func Test_randomnessFromProbabilityDistributions(t *testing.T) {
	type args struct {
		seed   []byte
		length int
	}
	tests := []struct {
		name    string
		args    args
		want    []int32
		wantErr bool
	}{
		{
			name: "one",
			args: args{
				seed:   []byte{0b0000_0001, 0b0010_0011, 0b0100_0101, 0b0110_0111, 0b1000_1001, 0b1010_1011, 0b1100_1101, 0b1110_1111},
				length: 16,
			},
			want:    []int32{-1, 0, 1, -1, 0, 1, -1, 0, 0, 1, -1, 0, 1, -1, 0, 1},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := randomnessFromProbabilityDistributions(tt.args.seed, tt.args.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("randomnessFromProbabilityDistributions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("randomnessFromProbabilityDistributions() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_randomnessFromChallengeSpace(t *testing.T) {
	type args struct {
		seed   []byte
		length int
	}
	tests := []struct {
		name    string
		args    args
		want    []int32
		wantErr bool
	}{
		{
			name: "test",
			args: args{
				seed:   []byte{0b00_01_10_11},
				length: 4,
			},
			want:    []int32{0, -1, 1, 0},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := randomnessFromChallengeSpace(tt.args.seed, tt.args.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("randomnessFromChallengeSpace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("randomnessFromChallengeSpace() got = %v, want %v", got, tt.want)
			}
		})
	}
}