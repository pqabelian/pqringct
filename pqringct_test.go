package pqringct

import (
	"fmt"
	"reflect"
	"testing"
)

func TestPublicParameter_MasterKeyGen(t *testing.T) {
	type args struct {
		seed []byte
	}
	tests := []struct {
		name        string
		args        args
		wantRetSeed []byte
		wantErr     bool
	}{
		{
			"test one",
			args{
				seed: []byte{
					1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
					33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
				}},
			[]byte{
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
				33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pp := DefaultPP
			gotRetSeed, mpk1, msvk1, mssk1, err := pp.MasterKeyGen(tt.args.seed)
			if (err != nil) != tt.wantErr {
				t.Errorf("MasterKeyGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotRetSeed, tt.wantRetSeed) {
				t.Errorf("MasterKeyGen() gotRetSeed = %v, want %v", gotRetSeed, tt.wantRetSeed)
			}
			_, mpk2, msvk2, mssk2, _ := pp.MasterKeyGen(gotRetSeed)
			if !reflect.DeepEqual(mpk1, mpk2) {
				t.Errorf("MasterKeyGen() mpk1 = %v, mpk2= %v", mpk1, mpk2)
			}
			if !reflect.DeepEqual(msvk1, msvk2) {
				t.Errorf("MasterKeyGen() msvk1 = %v, msvk2 = %v", msvk1, msvk2)
			}
			if !reflect.DeepEqual(mssk1, mssk2) {
				t.Errorf("MasterKeyGen() mssk1 = %v, mssk2 = %v", mssk1, mssk2)
			}
		})
	}
}

func TestPublicParameter_txoGenAndTxoReceive(t *testing.T) {
	type genArgs struct {
		mpk *MasterPublicKey
		vin uint64
	}
	tests := []struct {
		name    string
		genArgs genArgs
		wantErr bool
	}{
		{
			"test one",
			genArgs{
				mpk: nil,
				vin: 10,
			},
			false,
		},
	}
	seed := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
	}
	pp := DefaultPP
	_, mpk, msvk, mssk, err := pp.MasterKeyGen(seed)
	var txo *TXO
	//var r *PolyNTTVec
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.genArgs.mpk = mpk
			txo, _, err = pp.txoGen(tt.genArgs.mpk, tt.genArgs.vin)
			if (err != nil) != tt.wantErr {
				t.Errorf("txoGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			//if !reflect.DeepEqual(gotTxo, tt.wantTxo) {
			//	t.Errorf("txoGen() gotTxo = %v, want %v", gotTxo, tt.wantTxo)
			//}
			//if !reflect.DeepEqual(gotR, tt.wantR) {
			//	t.Errorf("txoGen() gotR = %v, want %v", gotR, tt.wantR)
			//}
		})
	}

	type receiveArgs struct {
		txo  *TXO
		mpk  *MasterPublicKey
		msvk *MasterSecretViewKey
	}
	receiveTests := []struct {
		name         string
		receiveArgs  receiveArgs
		wantValid    bool
		wantCoinvale uint64
		wantErr      bool
	}{
		{
			name: "test one",
			receiveArgs: receiveArgs{
				txo:  txo,
				mpk:  mpk,
				msvk: msvk,
			},
			wantValid:    true,
			wantCoinvale: 10,
			wantErr:      false,
		},
	}
	for _, tt := range receiveTests {
		t.Run(tt.name, func(t *testing.T) {
			pp := DefaultPP
			gotValid, gotCoinvale := pp.TxoCoinReceive(tt.receiveArgs.txo, tt.receiveArgs.mpk, tt.receiveArgs.msvk)
			if gotValid != tt.wantValid {
				t.Errorf("TxoCoinReceive() gotValid = %v, want %v", gotValid, tt.wantValid)
			}
			if gotCoinvale != tt.wantCoinvale {
				t.Errorf("TxoCoinReceive() gotCoinvale = %v, want %v", gotCoinvale, tt.wantCoinvale)
			}
		})
	}
	type snGenArgs struct {
		txo  *TXO
		mpk  *MasterPublicKey
		msvk *MasterSecretViewKey
		mssk *MasterSecretSignKey
	}
	snGenTests := []struct {
		name    string
		args    snGenArgs
		wantErr bool
	}{
		{
			name: "test one",
			args: snGenArgs{
				txo:  txo,
				mpk:  mpk,
				msvk: msvk,
				mssk: mssk,
			},
			wantErr: false,
		},
	}
	for _, tt := range snGenTests {
		t.Run(tt.name, func(t *testing.T) {
			pp := DefaultPP
			gotSn, err := pp.TxoSerialNumberGen(tt.args.txo, tt.args.mpk, tt.args.msvk, tt.args.mssk)
			if (err != nil) != tt.wantErr {
				t.Errorf("TxoSerialNumberGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fmt.Println(gotSn)
			//if !reflect.DeepEqual(gotSn, tt.wantSn) {
			//	t.Errorf("TxoSerialNumberGen() gotSn = %v, want %v", gotSn, tt.wantSn)
			//}
		})
	}
}

func TestPublicParameter_CoinbaseTxGenAndCoinbaseTxVerify(t *testing.T) {
	// generate key pair
	seed1 := []byte{
		2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 1,
		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64}
	seed2 := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
	}
	pp := DefaultPP
	_, mpk1, _, _, _ := pp.MasterKeyGen(seed1)
	_, mpk2, _, _, _ := pp.MasterKeyGen(seed2)
	type cbtxGenArgs struct {
		vin           uint64
		txOutputDescs []*TxOutputDesc
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
				txOutputDescs: []*TxOutputDesc{
					{
						mpk:   mpk1,
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
				txOutputDescs: []*TxOutputDesc{
					{
						mpk:   mpk1,
						value: 500,
					},
					{
						mpk:   mpk2,
						value: 12,
					},
				},
			},
			false,
			true,
		},
	}
	var cbTx *CoinbaseTx
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

func TestPublicParameter_TransferTxGen(t *testing.T) {
	pp := DefaultPP
	type args struct {
		inputDescs  []*TxInputDesc
		outputDescs []*TxOutputDesc
		fee         uint64
		txMemo      []byte
	}
	seed1 := []byte{
		2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 1,
		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64}
	seed2 := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
	}
	_, mpk1, msvk1, mssk1, _ := pp.MasterKeyGen(seed1)
	_, mpk2, _, _, _ := pp.MasterKeyGen(seed2)
	cbTx1,err:=pp.CoinbaseTxGen(512,[]*TxOutputDesc{
		{
			mpk: mpk1,
			value: 500,
		},
		{
			mpk:mpk2,
			value:12,
		},
	})
	cbTx2,err:=pp.CoinbaseTxGen(512,[]*TxOutputDesc{
		{
			mpk: mpk1,
			value: 500,
		},
		{
			mpk:mpk2,
			value:12,
		},
	})

	if err!=nil{
		t.Errorf(err.Error())
	}
	tests := []struct {
		name     string
		args     args
		wantErr  bool
		want    bool
	}{
		// TODO: Add test cases.
		{
			name: "test 1",
			args: args{
				inputDescs: []*TxInputDesc{
					&TxInputDesc{
						txoList: cbTx1.OutputTxos,
						sidx:    0,
						mpk:     mpk1,
						msvk:    msvk1,
						mssk:    mssk1,
						value:   500,
					},
				},
				outputDescs: []*TxOutputDesc{
					{
						mpk:   mpk1,
						value: 400,
					},
					{
						mpk:   mpk2,
						value: 90,
					},
				},
				fee:         10,
				txMemo:      []byte{},
			},
			wantErr: false,
			want:true,
		},
		{
			name: "test 2",
			args: args{
				inputDescs: []*TxInputDesc{
					&TxInputDesc{
						txoList: cbTx1.OutputTxos,
						sidx:    0,
						mpk:     mpk1,
						msvk:    msvk1,
						mssk:    mssk1,
						value:   500,
					},
					&TxInputDesc{
						txoList: cbTx2.OutputTxos,
						sidx:    0,
						mpk:     mpk1,
						msvk:    msvk1,
						mssk:    mssk1,
						value:   500,
					},
				},
				outputDescs: []*TxOutputDesc{
					{
						mpk:   mpk1,
						value: 800,
					},
					{
						mpk:   mpk2,
						value: 190,
					},
				},
				fee:         10,
				txMemo:      []byte{},
			},
			wantErr: false,
			want:true,
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
				t.Errorf("CoinbaseTxVerify() = %v, want %v", got, tt.want)
			}
		})
	}
}
