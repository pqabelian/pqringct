package pqringct

import (
	"testing"
)

func TestPublicParameterv2_ComGen(t *testing.T) {
	pp := DefaultPPV2
	v := uint64(100)
	cmt, r, err := pp.ComGen(v)
	if err != nil {
		t.Errorf("error in pp.ComGen with %v", v)
	}
	if !pp.ComVerify(cmt, r, v) {
		t.Errorf("Not matching for pp.ComGen and pp.ComVerify with %v", v)
	}
}
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
	_, pk1, _, _ := pp.KeyGen(randomBytes(pp.paramSeedBytesLen))
	_, pk2, _, _ := pp.KeyGen(randomBytes(pp.paramSeedBytesLen))

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
						pk:    pk1,
						value: 512,
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
						pk:    pk1,
						value: 500,
					},
					{
						pk:    pk2,
						value: 12,
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
	_, pk1, sk1, _ := pp.KeyGen(randomBytes(pp.paramSeedBytesLen))
	_, pk2, _, _ := pp.KeyGen(randomBytes(pp.paramSeedBytesLen))
	cbTx1, err := pp.CoinbaseTxGen(512, []*TxOutputDescv2{
		{
			pk:    pk1,
			value: 500,
		},
		{
			pk:    pk2,
			value: 12,
		},
	})
	cbTx2, err := pp.CoinbaseTxGen(512, []*TxOutputDescv2{
		{
			pk:    pk1,
			value: 500,
		},
		{
			pk:    pk2,
			value: 12,
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
					&TxInputDescv2{
						txoList: []*LGRTXO{
							{
								TXOv2: *cbTx1.OutputTxos[0],
								id:    []byte{1},
							},
							{
								TXOv2: *cbTx1.OutputTxos[1],
								id:    []byte{2},
							},
						},
						sidx:  0,
						sk:    sk1,
						value: 500,
						r:     cbTx1.TxWitness.cmt_rs[0],
					},
				},
				outputDescs: []*TxOutputDescv2{
					{
						pk:    pk1,
						value: 400,
					},
					{
						pk:    pk2,
						value: 90,
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
					&TxInputDescv2{
						txoList: []*LGRTXO{
							{
								TXOv2: *cbTx1.OutputTxos[0],
								id:    []byte{1},
							},
							{
								TXOv2: *cbTx1.OutputTxos[1],
								id:    []byte{2},
							},
						},
						sidx:  0,
						sk:    sk1,
						value: 500,
						r:     cbTx1.TxWitness.cmt_rs[0],
					},
					&TxInputDescv2{
						txoList: []*LGRTXO{
							{
								TXOv2: *cbTx2.OutputTxos[0],
								id:    []byte{1},
							},
							{
								TXOv2: *cbTx2.OutputTxos[1],
								id:    []byte{2},
							},
						},
						sidx:  0,
						sk:    sk1,
						value: 500,
						r:     cbTx2.TxWitness.cmt_rs[0],
					},
				},
				outputDescs: []*TxOutputDescv2{
					{
						pk:    pk1,
						value: 800,
					},
					{
						pk:    pk2,
						value: 190,
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
