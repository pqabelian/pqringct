package pqringct

import (
	"bytes"
	"fmt"
	"testing"
)

func ledgerTxoIdGen(ringHash []byte, index uint8) []byte {
	w := bytes.NewBuffer(make([]byte, 0, HashOutputBytesLen+1))
	var err error
	// ringHash
	_, err = w.Write(ringHash)
	if err != nil {
		return nil
	}
	// index
	err = w.WriteByte(index >> 0)
	if err != nil {
		return nil
	}
	rst, err := Hash(w.Bytes())
	if err != nil {
		return nil
	}
	return rst
}

func TestPublicParameter_TransferTxGen_TransferTxVerify(t *testing.T) {
	pp := DefaultPP
	type args struct {
		inputDescs  []*TxInputDesc
		outputDescs []*TxOutputDesc
		fee         uint64
		txMemo      []byte
	}

	ehash := make([]byte, HashOutputBytesLen)

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

	cbTx1, err := pp.CoinbaseTxGen(512, []*TxOutputDesc{
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

	cbTx2, err := pp.CoinbaseTxGen(512, []*TxOutputDesc{
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

	//fmt.Println("CbTxWitnessJ2SizeApprox(J=2):", pp.CbTxWitnessJ2SerializeSizeApprox(2))
	//fmt.Println("CbTxWitnessJ2SizeExact(J=2):", pp.CbTxWitnessJ2SerializeSize(cbTx1.TxWitnessJ2))

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
				inputDescs: []*TxInputDesc{
					{
						lgrTxoList: []*LgrTxo{
							{
								txo: cbTx1.OutputTxos[0],
								id:  ledgerTxoIdGen(ehash, 0),
							},
							{
								txo: cbTx1.OutputTxos[1],
								id:  ledgerTxoIdGen(ehash, 1),
							},
							{
								txo: cbTx2.OutputTxos[0],
								id:  ledgerTxoIdGen(ehash, 2),
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
				outputDescs: []*TxOutputDesc{
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
				inputDescs: []*TxInputDesc{
					{
						lgrTxoList: []*LgrTxo{
							{
								txo: cbTx1.OutputTxos[0],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx1.OutputTxos[1],
								id:  make([]byte, HashOutputBytesLen),
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
								txo: cbTx2.OutputTxos[0],
								id:  make([]byte, HashOutputBytesLen),
							},
							{
								txo: cbTx2.OutputTxos[1],
								id:  make([]byte, HashOutputBytesLen),
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
				outputDescs: []*TxOutputDesc{
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
