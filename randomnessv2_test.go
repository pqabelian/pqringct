package pqringct

import (
	"testing"
)

func Test_randomnessFromGammaAv2(t *testing.T) {
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
			"Test1",
			args{
				seed:   RandomBytes(32),
				length: DefaultPP.paramDA,
			},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := randomnessFromGammaA5(tt.args.seed, tt.args.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("randomnessFromGammaA5() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got); i++ {
				if got[i] < int64(-DefaultPP.paramGammaA) || got[i] > int64(DefaultPP.paramGammaA) {
					t.Errorf("randomnessFromGammaA5() sample a value %v", got[i])
				}
			}
		})
	}
}

func Test_randomnessFromEtaAv2(t *testing.T) {
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
			"Test1",
			args{
				seed:   RandomBytes(32),
				length: DefaultPP.paramDA,
			},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := randomnessFromEtaAv2(tt.args.seed, tt.args.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("randomnessFromGammaA5() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got); i++ {
				if got[i] < int64(-DefaultPP.paramEtaA) || got[i] > int64(DefaultPP.paramEtaA) {
					t.Errorf("randomnessFromEtaAv2() sample a value %v", got[i])
				}
			}
		})
	}
}

func Test_randomnessFromZetaC2v2(t *testing.T) {
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
			"Test1",
			args{
				seed:   RandomBytes(32),
				length: DefaultPP.paramDA,
			},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := randomnessFromZetaC2v2(tt.args.seed, tt.args.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("randomnessFromZetaC2v2() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got); i++ {
				if got[i] < -(DefaultPP.paramEtaC-int64(DefaultPP.paramBetaC)) || got[i] > (DefaultPP.paramEtaC-int64(DefaultPP.paramBetaC)) {
					t.Errorf("randomnessFromZetaC2v2() sample a value %v", got[i])
				}
			}
		})
	}
}

func Test_randomnessFromZetaAv2(t *testing.T) {
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
			"Test1",
			args{
				seed:   RandomBytes(32),
				length: DefaultPP.paramDA,
			},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := randomnessFromZetaAv2(tt.args.seed, tt.args.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("randomnessFromZetaC2v2() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got); i++ {
				if got[i] < -(DefaultPP.paramEtaA-int64(DefaultPP.paramThetaA*DefaultPP.paramGammaA)) || got[i] > DefaultPP.paramEtaA-int64(DefaultPP.paramThetaA*DefaultPP.paramGammaA) {
					t.Errorf("randomnessFromZetaC2v2() sample a value %v", got[i])
				}
			}
		})
	}
}

func Test_randomnessFromEtaCv2(t *testing.T) {
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
			"Test1",
			args{
				seed:   RandomBytes(32),
				length: DefaultPP.paramDA,
			},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := randomnessFromEtaCv2(tt.args.seed, tt.args.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("randomnessFromZetaC2v2() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got); i++ {
				if got[i] < -(DefaultPP.paramEtaC) || got[i] > (DefaultPP.paramEtaC) {
					t.Errorf("randomnessFromZetaC2v2() sample a value %v", got[i])
				}
			}
		})
	}
}
