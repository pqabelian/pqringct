package pqringct

import (
	"testing"
)

func Test_randomPolyAinGammaA5(t *testing.T) {
	pp := DefaultPP
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
			got, err := pp.randomPolyAinGammaA5(tt.args.seed)
			if (err != nil) != tt.wantErr {
				t.Errorf("randomPolyAinGammaA5() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got.coeffs); i++ {
				if got.coeffs[i] < int64(-DefaultPP.paramGammaA) || got.coeffs[i] > int64(DefaultPP.paramGammaA) {
					t.Errorf("randomPolyAinGammaA5() sample a value %v", got.coeffs[i])
				}
			}
		})
	}
}

func Test_sampleMaskingVecA(t *testing.T) {
	pp := DefaultPP
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
			got, err := pp.randomPolyAinEtaA()
			if (err != nil) != tt.wantErr {
				t.Errorf("randomPolyAinGammaA5() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got.coeffs); i++ {
				if got.coeffs[i] < int64(-DefaultPP.paramEtaA) || got.coeffs[i] > int64(DefaultPP.paramEtaA) {
					t.Errorf("randomPolyAinEtaA() sample a value %v", got.coeffs[i])
				}
			}
		})
	}
}

func Test_randomnessPolyCForResponseZetaC(t *testing.T) {
	pp := DefaultPP
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
			got, err := pp.randomnessPolyCForResponseZetaC()
			if (err != nil) != tt.wantErr {
				t.Errorf("randomnessPolyCForResponseZetaC() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got.coeffs); i++ {
				if got.coeffs[i] < -(DefaultPP.paramEtaC-int64(DefaultPP.paramBetaC)) || got.coeffs[i] > (DefaultPP.paramEtaC-int64(DefaultPP.paramBetaC)) {
					t.Errorf("randomnessPolyCForResponseZetaC() sample a value %v", got.coeffs[i])
				}
			}
		})
	}
}

func Test_randomnessFromZetaAv2(t *testing.T) {
	pp := DefaultPP

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
			got, err := pp.randomnessPolyAForResponseZetaA()
			if (err != nil) != tt.wantErr {
				t.Errorf("randomnessPolyAForResponseZetaA() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got.coeffs); i++ {
				if got.coeffs[i] < -(DefaultPP.paramEtaA-int64(DefaultPP.paramThetaA*DefaultPP.paramGammaA)) || got.coeffs[i] > DefaultPP.paramEtaA-int64(DefaultPP.paramThetaA*DefaultPP.paramGammaA) {
					t.Errorf("randomnessPolyAForResponseZetaA() sample a value %v", got.coeffs[i])
				}
			}
		})
	}
}

func Test_randomPolyCinEtaC(t *testing.T) {
	pp := DefaultPP
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
			got, err := pp.randomPolyCinEtaC()
			if (err != nil) != tt.wantErr {
				t.Errorf("randomPolyCinEtaC() error = %v, wantErr %v", err, tt.wantErr)
			}
			for i := 0; i < len(got.coeffs); i++ {
				if got.coeffs[i] < -(DefaultPP.paramEtaC) || got.coeffs[i] > (DefaultPP.paramEtaC) {
					t.Errorf("randomPolyCinEtaC() sample a value %v", got.coeffs[i])
				}
			}
		})
	}
}
