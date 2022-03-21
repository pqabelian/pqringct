package pqringct

import (
	"testing"
)

func TestPublicParameterv2_CoinbaseTxGenAndCoinbaseTxVerify(t *testing.T) {
	// generate key pair
	//seed1 := []byte{
	//	2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 1,
	//	33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64}
	//seed2 := []byte{
	//	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	//	33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
	//}
	pp := DefaultPPV2
	seed1 := RandomBytes(pp.paramSeedBytesLen)
	apk1, _, _ := pp.AddressKeyGen(seed1)
	serializedVPk1, _, _ := pp.ValueKeyGen(seed1)
	serializedAPk1, _ := pp.AddressPublicKeySerialize(apk1)
	seed2 := RandomBytes(pp.paramSeedBytesLen)
	apk2, _, _ := pp.AddressKeyGen(seed2)
	serializedVPk2, _, _ := pp.ValueKeyGen(seed2)
	serializedAPk2, _ := pp.AddressPublicKeySerialize(apk2)

	type cbtxGenArgs struct {
		vin           uint64
		txOutputDescs []*TxOutputDescv2
	}
	tests := []struct {
		name    string
		args    cbtxGenArgs
		wantErr bool
		want    bool
	}{
		{
			"test one",
			cbtxGenArgs{
				vin: 512,
				txOutputDescs: []*TxOutputDescv2{
					{
						serializedAPk: serializedAPk1,
						serializedVPk: serializedVPk1,
						value:         512,
					},
				},
			},
			false,
			true,
		},
		{
			"test two",
			cbtxGenArgs{
				vin: 512,
				txOutputDescs: []*TxOutputDescv2{
					{
						serializedAPk: serializedAPk1,
						serializedVPk: serializedVPk1,
						value:         500,
					},
					{
						serializedAPk: serializedAPk2,
						serializedVPk: serializedVPk2,
						value:         12,
					},
				},
			},
			false,
			true,
		},
	}
	var cbTx *CoinbaseTxv2
	var err error
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cbTx, err = pp.CoinbaseTxGen(tt.args.vin, tt.args.txOutputDescs)
			if (err != nil) != tt.wantErr {
				t.Errorf("CoinbaseTxGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got := pp.CoinbaseTxVerify(cbTx); got != tt.want {
				t.Errorf("CoinbaseTxVerify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicParameterV2_TransferTxGen(t *testing.T) {
	pp := DefaultPPV2
	type args struct {
		inputDescs  []*TxInputDescv2
		outputDescs []*TxOutputDescv2
		fee         uint64
		txMemo      []byte
	}
	//seed1 := []byte{
	//	2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 1,
	//	33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64}
	//seed2 := []byte{
	//	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	//	33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
	//}
	seed1 := RandomBytes(pp.paramSeedBytesLen)
	apk1, ask1, _ := pp.AddressKeyGen(seed1)
	serializedVPk1, serializedVSk1, _ := pp.ValueKeyGen(seed1)
	serializedAPk1, _ := pp.AddressPublicKeySerialize(apk1)
	serializedASksp1, serializedASksn1, _ := pp.AddressSecretKeySerialize(ask1)
	seed2 := RandomBytes(pp.paramSeedBytesLen)
	apk2, _, _ := pp.AddressKeyGen(seed2)
	serializedVPk2, _, _ := pp.ValueKeyGen(seed2)
	serializedAPk2, _ := pp.AddressPublicKeySerialize(apk2)

	cbTx1, err := pp.CoinbaseTxGen(512, []*TxOutputDescv2{
		{
			serializedAPk: serializedAPk1,
			serializedVPk: serializedVPk1,
			value:         500,
		},
		{
			serializedAPk: serializedAPk2,
			serializedVPk: serializedVPk2,
			value:         12,
		},
	})
	if err != nil {
		t.Errorf(err.Error())
	}
	cbTx2, err := pp.CoinbaseTxGen(512, []*TxOutputDescv2{
		{
			serializedAPk: serializedAPk1,
			serializedVPk: serializedVPk1,
			value:         500,
		},
		{
			serializedAPk: serializedAPk2,
			serializedVPk: serializedVPk2,
			value:         12,
		},
	})

	if err != nil {
		t.Errorf(err.Error())
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    bool
	}{
		// TODO: Add test cases.
		{
			name: "test 1",
			args: args{
				inputDescs: []*TxInputDescv2{
					{
						txoList: []*LgrTxo{
							{
								Txo: *cbTx1.OutputTxos[0],
								Id:  []byte{1},
							},
							{
								Txo: *cbTx1.OutputTxos[1],
								Id:  []byte{2},
							},
						},
						sidx:            0,
						serializedASksp: serializedASksp1,
						serializedASksn: serializedASksn1,
						serializedVPk:   serializedVPk1,
						serializedVSk:   serializedVSk1,
						value:           500,
					},
				},
				outputDescs: []*TxOutputDescv2{
					{
						serializedAPk: serializedAPk1,
						serializedVPk: serializedVPk1,
						value:         400,
					},
					{
						serializedAPk: serializedAPk2,
						serializedVPk: serializedVPk2,
						value:         90,
					},
				},
				fee:    10,
				txMemo: []byte{},
			},
			wantErr: false,
			want:    true,
		},
		{
			name: "test 2",
			args: args{
				inputDescs: []*TxInputDescv2{
					{
						txoList: []*LgrTxo{
							{
								Txo: *cbTx1.OutputTxos[0],
								Id:  []byte{1},
							},
							{
								Txo: *cbTx1.OutputTxos[1],
								Id:  []byte{2},
							},
						},
						sidx:            0,
						serializedASksp: serializedASksp1,
						serializedASksn: serializedASksn1,
						serializedVPk:   serializedVPk1,
						serializedVSk:   serializedVSk1,
						value:           500,
					},
					{
						txoList: []*LgrTxo{
							{
								Txo: *cbTx2.OutputTxos[0],
								Id:  []byte{1},
							},
							{
								Txo: *cbTx2.OutputTxos[1],
								Id:  []byte{2},
							},
						},
						sidx:            0,
						serializedASksp: serializedASksp1,
						serializedASksn: serializedASksn1,
						serializedVPk:   serializedVPk1,
						serializedVSk:   serializedVSk1,
						value:           500,
					},
				},
				outputDescs: []*TxOutputDescv2{
					{
						serializedAPk: serializedAPk1,
						serializedVPk: serializedVPk1,
						value:         800,
					},
					{
						serializedAPk: serializedAPk2,
						serializedVPk: serializedVPk2,
						value:         190,
					},
				},
				fee:    10,
				txMemo: []byte{},
			},
			wantErr: false,
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTrTx, err := pp.TransferTxGen(tt.args.inputDescs, tt.args.outputDescs, tt.args.fee, tt.args.txMemo)
			if (err != nil) != tt.wantErr {
				t.Errorf("TransferTxGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got := pp.TransferTxVerify(gotTrTx); got != tt.want {
				t.Errorf("TransferTxVerify() = %v, want %v", got, tt.want)
			}
		})
	}
}
