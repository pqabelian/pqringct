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
				seed:   randomBytes(32),
				length: DefaultPPV2.paramDA,
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
				if got[i] < int64(-DefaultPPV2.paramGammaA) || got[i] > int64(DefaultPPV2.paramGammaA) {
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
				seed:   randomBytes(32),
				length: DefaultPPV2.paramDA,
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
				if got[i] < int64(-DefaultPPV2.paramEtaA) || got[i] > int64(DefaultPPV2.paramEtaA) {
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
				seed:   randomBytes(32),
				length: DefaultPPV2.paramDA,
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
				if got[i] < -(DefaultPPV2.paramEtaC-int64(DefaultPPV2.paramBetaC)) || got[i] > (DefaultPPV2.paramEtaC-int64(DefaultPPV2.paramBetaC)) {
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
				seed:   randomBytes(32),
				length: DefaultPPV2.paramDA,
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
				if got[i] < int64(-(DefaultPPV2.paramEtaA-int64(DefaultPPV2.paramBetaA))) || got[i] > int64(DefaultPPV2.paramEtaA-int64(DefaultPPV2.paramBetaA)) {
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
				seed:   randomBytes(32),
				length: DefaultPPV2.paramDA,
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
				if got[i] < -(DefaultPPV2.paramEtaC) || got[i] > (DefaultPPV2.paramEtaC) {
					t.Errorf("randomnessFromZetaC2v2() sample a value %v", got[i])
				}
			}
		})
	}
}
