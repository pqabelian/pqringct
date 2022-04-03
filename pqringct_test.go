package pqringct

import (
	"fmt"
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
	pp := DefaultPP
	seed1 := RandomBytes(pp.paramSeedBytesLen)
	apk1, _, _ := pp.AddressKeyGen(seed1)
	serializedVPk1, _, _ := pp.ValueKeyGen(seed1)
	serializedAPk1, _ := pp.SerializeAddressPublicKey(apk1)
	seed2 := RandomBytes(pp.paramSeedBytesLen)
	apk2, _, _ := pp.AddressKeyGen(seed2)
	serializedVPk2, _, _ := pp.ValueKeyGen(seed2)
	serializedAPk2, _ := pp.SerializeAddressPublicKey(apk2)

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
			cbTx, err = pp.CoinbaseTxGen(tt.args.vin, tt.args.txOutputDescs, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("CoinbaseTxGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got, err := pp.CoinbaseTxVerify(cbTx)
			if (err != nil) != tt.wantErr {
				t.Errorf("CoinbaseTxGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CoinbaseTxVerify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicParameterV2_TransferTxGen(t *testing.T) {
	pp := DefaultPP
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
	serializedVSk1C0 := make([]byte, len(serializedVSk1))
	copy(serializedVSk1C0, serializedVSk1)
	serializedVSk1C1 := make([]byte, len(serializedVSk1))
	copy(serializedVSk1C1, serializedVSk1)
	serializedVSk1C2 := make([]byte, len(serializedVSk1))
	copy(serializedVSk1C2, serializedVSk1)
	serializedAPk1, _ := pp.SerializeAddressPublicKey(apk1)
	serializedASksp1, _ := pp.SerializeAddressSecretKeySp(ask1.AddressSecretKeySp)
	serializedASksn1, _ := pp.SerializeAddressSecretKeySn(ask1.AddressSecretKeySn)
	seed2 := RandomBytes(pp.paramSeedBytesLen)
	apk2, _, _ := pp.AddressKeyGen(seed2)
	serializedVPk2, _, _ := pp.ValueKeyGen(seed2)
	serializedAPk2, _ := pp.SerializeAddressPublicKey(apk2)

	cbTx0, err := pp.CoinbaseTxGen(512, []*TxOutputDescv2{
		{
			serializedAPk: serializedAPk1,
			serializedVPk: serializedVPk1,
			value:         512,
		},
	}, nil)
	if err != nil {
		t.Errorf(err.Error())
	}
	cbTx0Serialized, err := pp.SerializeCoinbaseTx(cbTx0, true)
	if err != nil {
		t.Errorf(err.Error())
	}
	cbTx0Deser, err := pp.DeserializeCoinbaseTx(cbTx0Serialized, true)
	if err != nil {
		t.Errorf(err.Error())
	}
	validCbTx0, err := pp.CoinbaseTxVerify(cbTx0Deser)
	if err != nil {
		t.Errorf(err.Error())
	}
	if validCbTx0 {
		fmt.Println("CbTx0 (J=1) serialze and deserialize Pass")
	}

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
	}, nil)
	if err != nil {
		t.Errorf(err.Error())
	}

	cbTx1Serialized, err := pp.SerializeCoinbaseTx(cbTx1, true)
	if err != nil {
		t.Errorf(err.Error())
	}
	cbTx1Deser, err := pp.DeserializeCoinbaseTx(cbTx1Serialized, true)
	if err != nil {
		t.Errorf(err.Error())
	}
	validCbTx1, err := pp.CoinbaseTxVerify(cbTx1Deser)
	if err != nil {
		t.Errorf(err.Error())
	}
	if validCbTx1 {
		fmt.Println("CbTx1 (J=2) serialze and deserialize Pass")
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
	}, nil)

	if err != nil {
		t.Errorf(err.Error())
	}

	cbTx2Serialized, err := pp.SerializeCoinbaseTx(cbTx2, true)
	if err != nil {
		t.Errorf(err.Error())
	}
	cbTx2Deser, err := pp.DeserializeCoinbaseTx(cbTx2Serialized, true)
	if err != nil {
		t.Errorf(err.Error())
	}
	validCbTx2, err := pp.CoinbaseTxVerify(cbTx2Deser)
	if err != nil {
		t.Errorf(err.Error())
	}
	if validCbTx2 {
		fmt.Println("CbTx2 (J=2) serialze and deserialize Pass")
	}

	fmt.Println("CbTxWitnessJ1SizeApprox:", pp.CbTxWitnessJ1SerializeSizeApprox())
	fmt.Println("CbTxWitnessJ1SizeExact:", pp.CbTxWitnessJ1SerializeSize(cbTx0.TxWitnessJ1))
	fmt.Println("CbTxWitnessJ2SizeApprox(J=2):", pp.CbTxWitnessJ2SerializeSizeApprox(2))
	fmt.Println("CbTxWitnessJ2SizeExact(J=2):", pp.CbTxWitnessJ2SerializeSize(cbTx1.TxWitnessJ2))

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
						lgrTxoList: []*LgrTxo{
							{
								Txo: cbTx1.OutputTxos[0],
								Id:  make([]byte, HashBytesLen),
							},
							{
								Txo: cbTx1.OutputTxos[1],
								Id:  make([]byte, HashBytesLen),
							},
						},
						sidx:            0,
						serializedASksp: serializedASksp1,
						serializedASksn: serializedASksn1,
						serializedVPk:   serializedVPk1,
						serializedVSk:   serializedVSk1C0,
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
						lgrTxoList: []*LgrTxo{
							{
								Txo: cbTx1.OutputTxos[0],
								Id:  make([]byte, HashBytesLen),
							},
							{
								Txo: cbTx1.OutputTxos[1],
								Id:  make([]byte, HashBytesLen),
							},
						},
						sidx:            0,
						serializedASksp: serializedASksp1,
						serializedASksn: serializedASksn1,
						serializedVPk:   serializedVPk1,
						serializedVSk:   serializedVSk1C1,
						value:           500,
					},
					{
						lgrTxoList: []*LgrTxo{
							{
								Txo: cbTx2.OutputTxos[0],
								Id:  make([]byte, HashBytesLen),
							},
							{
								Txo: cbTx2.OutputTxos[1],
								Id:  make([]byte, HashBytesLen),
							},
						},
						sidx:            0,
						serializedASksp: serializedASksp1,
						serializedASksn: serializedASksn1,
						serializedVPk:   serializedVPk1,
						serializedVSk:   serializedVSk1C2,
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

			gotTrTxSerialized, err := pp.SerializeTransferTx(gotTrTx, true)
			if err != nil {
				t.Errorf(err.Error())
			}
			gotTrTxDeser, err := pp.DeserializeTransferTx(gotTrTxSerialized, true)
			if err != nil {
				t.Errorf(err.Error())
			}

			ringSizes := make([]int, len(gotTrTx.Inputs))
			for i := 0; i < len(gotTrTx.Inputs); i++ {
				ringSizes[i] = 2
			}
			fmt.Println("TrTxWitnessSizeApprox:", pp.TrTxWitnessSerializeSizeApprox(ringSizes, len(gotTrTx.OutputTxos)))
			fmt.Println("TrTxWitnessSizeExact:", pp.TrTxWitnessSerializeSize(gotTrTx.TxWitness))

			got, err := pp.TransferTxVerify(gotTrTxDeser)
			if (err != nil) != tt.wantErr {
				t.Errorf("TransferTxGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("TransferTxVerify() = %v, want %v", got, tt.want)
			}
		})
	}
}
