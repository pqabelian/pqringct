package pqringct

//func TestPublicParameter_MasterKeyGen(t *testing.T) {
//	type args struct {
//		seed []byte
//	}
//	tests := []struct {
//		name        string
//		args        args
//		wantRetSeed []byte
//		wantErr     bool
//	}{
//		{
//			"test one",
//			args{
//				seed: []byte{
//					1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
//					33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
//				}},
//			[]byte{
//				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
//				33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
//			},
//			false,
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			pp := DefaultPP
//			gotRetSeed, mpk1, msvk1, mssk1, err := pp.MasterKeyGen(tt.args.seed)
//			if (err != nil) != tt.wantErr {
//				t.Errorf("MasterKeyGen() error = %v, wantErr %v", err, tt.wantErr)
//				return
//			}
//			// using for mining
//			bytesss := mpk1.Serialize()
//			fmt.Println(mpk1.SerializeSize())
//			fmt.Println()
//			b := make([]byte, 2+len(bytesss))
//			binary.BigEndian.PutUint16(b, uint16(1))
//			copy(b[2:], bytesss[:])
//			first := sha256.Sum256(b)
//			second := sha256.Sum256(first[:])
//			fmt.Println(hex.EncodeToString(append(b, second[:]...)))
//			if !reflect.DeepEqual(gotRetSeed, tt.wantRetSeed) {
//				t.Errorf("MasterKeyGen() gotRetSeed = %v, want %v", gotRetSeed, tt.wantRetSeed)
//			}
//			_, mpk2, msvk2, mssk2, _ := pp.MasterKeyGen(gotRetSeed)
//			if !reflect.DeepEqual(mpk1, mpk2) {
//				t.Errorf("MasterKeyGen() mpk1 = %v, mpk2= %v", mpk1, mpk2)
//			}
//			if !reflect.DeepEqual(msvk1, msvk2) {
//				t.Errorf("MasterKeyGen() msvk1 = %v, msvk2 = %v", msvk1, msvk2)
//			}
//			if !reflect.DeepEqual(mssk1, mssk2) {
//				t.Errorf("MasterKeyGen() mssk1 = %v, mssk2 = %v", mssk1, mssk2)
//			}
//		})
//	}
//}
//
//func TestPublicParameter_txoGenAndTxoReceive(t *testing.T) {
//	type genArgs struct {
//		mpk *MasterPublicKey
//		vin uint64
//	}
//	tests := []struct {
//		name    string
//		genArgs genArgs
//		wantErr bool
//	}{
//		{
//			"test one",
//			genArgs{
//				mpk: nil,
//				vin: 10,
//			},
//			false,
//		},
//	}
//	seed := []byte{
//		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
//		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
//	}
//	pp := DefaultPP
//	_, mpk, msvk, mssk, err := pp.MasterKeyGen(seed)
//	var txo *TXO
//	//var r *PolyNTTVec
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			tt.genArgs.mpk = mpk
//			txo, _, err = pp.txoGen(tt.genArgs.mpk, tt.genArgs.vin)
//			if (err != nil) != tt.wantErr {
//				t.Errorf("txoGen() error = %v, wantErr %v", err, tt.wantErr)
//				return
//			}
//			//if !reflect.DeepEqual(gotTxo, tt.wantTxo) {
//			//	t.Errorf("txoGen() gotTxo = %v, want %v", gotTxo, tt.wantTxo)
//			//}
//			//if !reflect.DeepEqual(gotR, tt.wantR) {
//			//	t.Errorf("txoGen() gotR = %v, want %v", gotR, tt.wantR)
//			//}
//		})
//	}
//
//	type receiveArgs struct {
//		txo  *TXO
//		mpk  *MasterPublicKey
//		msvk *MasterSecretViewKey
//	}
//	receiveTests := []struct {
//		name         string
//		receiveArgs  receiveArgs
//		wantValid    bool
//		wantCoinvale uint64
//		wantErr      bool
//	}{
//		{
//			name: "test one",
//			receiveArgs: receiveArgs{
//				txo:  txo,
//				mpk:  mpk,
//				msvk: msvk,
//			},
//			wantValid:    true,
//			wantCoinvale: 10,
//			wantErr:      false,
//		},
//	}
//	for _, tt := range receiveTests {
//		t.Run(tt.name, func(t *testing.T) {
//			pp := DefaultPP
//			gotValid, gotCoinvale := pp.TxoCoinReceive(tt.receiveArgs.txo, tt.receiveArgs.mpk, tt.receiveArgs.msvk)
//			if gotValid != tt.wantValid {
//				t.Errorf("TxoCoinReceive() gotValid = %v, want %v", gotValid, tt.wantValid)
//			}
//			if gotCoinvale != tt.wantCoinvale {
//				t.Errorf("TxoCoinReceive() gotCoinvale = %v, want %v", gotCoinvale, tt.wantCoinvale)
//			}
//		})
//	}
//	type snGenArgs struct {
//		txo  *TXO
//		mpk  *MasterPublicKey
//		msvk *MasterSecretViewKey
//		mssk *MasterSecretSignKey
//	}
//	snGenTests := []struct {
//		name    string
//		args    snGenArgs
//		wantErr bool
//	}{
//		{
//			name: "test one",
//			args: snGenArgs{
//				txo:  txo,
//				mpk:  mpk,
//				msvk: msvk,
//				mssk: mssk,
//			},
//			wantErr: false,
//		},
//	}
//	for _, tt := range snGenTests {
//		t.Run(tt.name, func(t *testing.T) {
//			pp := DefaultPP
//			gotSn, err := pp.TxoSerialNumberGen(tt.args.txo, tt.args.mpk, tt.args.msvk, tt.args.mssk)
//			if (err != nil) != tt.wantErr {
//				t.Errorf("TxoSerialNumberGen() error = %v, wantErr %v", err, tt.wantErr)
//				return
//			}
//			fmt.Println(gotSn)
//			//if !reflect.DeepEqual(gotSn, tt.wantSn) {
//			//	t.Errorf("TxoSerialNumberGen() gotSn = %v, want %v", gotSn, tt.wantSn)
//			//}
//		})
//	}
//}
//
//func TestPublicParameter_CoinbaseTxGenAndCoinbaseTxVerify(t *testing.T) {
//	// generate key pair
//	seed1 := []byte{
//		2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 1,
//		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64}
//	seed2 := []byte{
//		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
//		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
//	}
//	pp := DefaultPP
//	_, mpk1, _, _, _ := pp.MasterKeyGen(seed1)
//	_, mpk2, _, _, _ := pp.MasterKeyGen(seed2)
//	type cbtxGenArgs struct {
//		vin           uint64
//		txOutputDescs []*TxOutputDesc
//	}
//	tests := []struct {
//		name    string
//		args    cbtxGenArgs
//		wantErr bool
//		want    bool
//	}{
//		{
//			"test one",
//			cbtxGenArgs{
//				vin: 512,
//				txOutputDescs: []*TxOutputDesc{
//					{
//						mpk:   mpk1,
//						value: 512,
//					},
//				},
//			},
//			false,
//			true,
//		},
//		{
//			"test two",
//			cbtxGenArgs{
//				vin: 512,
//				txOutputDescs: []*TxOutputDesc{
//					{
//						mpk:   mpk1,
//						value: 500,
//					},
//					{
//						mpk:   mpk2,
//						value: 12,
//					},
//				},
//			},
//			false,
//			true,
//		},
//	}
//	var cbTx *CoinbaseTx
//	var err error
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			cbTx, err = pp.CoinbaseTxGen(tt.args.vin, tt.args.txOutputDescs)
//			if (err != nil) != tt.wantErr {
//				t.Errorf("CoinbaseTxGen() error = %v, wantErr %v", err, tt.wantErr)
//				return
//			}
//			if got := pp.CoinbaseTxVerify(cbTx); got != tt.want {
//				t.Errorf("CoinbaseTxVerify() = %v, want %v", got, tt.want)
//			}
//		})
//	}
//}
//
//func TestPublicParameter_TransferTxGen(t *testing.T) {
//	pp := DefaultPP
//	type args struct {
//		inputDescs  []*TxInputDesc
//		outputDescs []*TxOutputDesc
//		fee         uint64
//		txMemo      []byte
//	}
//	seed1 := []byte{
//		2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 1,
//		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64}
//	seed2 := []byte{
//		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
//		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
//	}
//	_, mpk1, msvk1, mssk1, _ := pp.MasterKeyGen(seed1)
//	_, mpk2, _, _, _ := pp.MasterKeyGen(seed2)
//	cbTx1, err := pp.CoinbaseTxGen(512, []*TxOutputDesc{
//		{
//			mpk:   mpk1,
//			value: 500,
//		},
//		{
//			mpk:   mpk2,
//			value: 12,
//		},
//	})
//	cbTx2, err := pp.CoinbaseTxGen(512, []*TxOutputDesc{
//		{
//			mpk:   mpk1,
//			value: 500,
//		},
//		{
//			mpk:   mpk2,
//			value: 12,
//		},
//	})
//
//	if err != nil {
//		t.Errorf(err.Error())
//	}
//	tests := []struct {
//		name    string
//		args    args
//		wantErr bool
//		want    bool
//	}{
//		// TODO: Add test cases.
//		{
//			name: "test 1",
//			args: args{
//				inputDescs: []*TxInputDesc{
//					&TxInputDesc{
//						txoList: cbTx1.OutputTxos,
//						sidx:    0,
//						mpk:     mpk1,
//						msvk:    msvk1,
//						mssk:    mssk1,
//						value:   500,
//					},
//				},
//				outputDescs: []*TxOutputDesc{
//					{
//						mpk:   mpk1,
//						value: 400,
//					},
//					{
//						mpk:   mpk2,
//						value: 90,
//					},
//				},
//				fee:    10,
//				txMemo: []byte{},
//			},
//			wantErr: false,
//			want:    true,
//		},
//		{
//			name: "test 2",
//			args: args{
//				inputDescs: []*TxInputDesc{
//					&TxInputDesc{
//						txoList: cbTx1.OutputTxos,
//						sidx:    0,
//						mpk:     mpk1,
//						msvk:    msvk1,
//						mssk:    mssk1,
//						value:   500,
//					},
//					&TxInputDesc{
//						txoList: cbTx2.OutputTxos,
//						sidx:    0,
//						mpk:     mpk1,
//						msvk:    msvk1,
//						mssk:    mssk1,
//						value:   500,
//					},
//				},
//				outputDescs: []*TxOutputDesc{
//					{
//						mpk:   mpk1,
//						value: 800,
//					},
//					{
//						mpk:   mpk2,
//						value: 190,
//					},
//				},
//				fee:    10,
//				txMemo: []byte{},
//			},
//			wantErr: false,
//			want:    true,
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			gotTrTx, err := pp.TransferTxGen(tt.args.inputDescs, tt.args.outputDescs, tt.args.fee, tt.args.txMemo)
//			if (err != nil) != tt.wantErr {
//				t.Errorf("TransferTxGen() error = %v, wantErr %v", err, tt.wantErr)
//				return
//			}
//			if got := pp.TransferTxVerify(gotTrTx); got != tt.want {
//				t.Errorf("CoinbaseTxVerify() = %v, want %v", got, tt.want)
//			}
//		})
//	}
//}
//
//func TestMasterPublicKey_Serialize(t *testing.T) {
//	pp := DefaultPP
//	seed := []byte{
//		2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 1,
//		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64}
//	_, mpk, _, _, _ := pp.MasterKeyGen(seed)
//	mpk2 := new(MasterPublicKey)
//	_ = mpk2.Deserialize(mpk.Serialize())
//	if !reflect.DeepEqual(mpk2, mpk) {
//		t.Errorf("Serialize() and Deserialize() do not match")
//	}
//}
//
//func TestTransactions(t *testing.T) {
//	pp := DefaultPP
//	seeds := make([][]byte, 3)
//	mpks := make([]*MasterPublicKey, 3)
//	msvks := make([]*MasterSecretViewKey, 3)
//	mssks := make([]*MasterSecretSignKey, 3)
//
//	var err error
//	for i := 0; i < 3; i++ {
//		seeds[i], mpks[i], msvks[i], mssks[i], err = pp.MasterKeyGen(nil)
//		if err != nil {
//			return
//		}
//	}
//
//	txoutputDescs := make([]*TxOutputDesc, 3)
//	txoutputDescs[0] = &TxOutputDesc{
//		mpks[0],
//		20,
//	}
//
//	txoutputDescs[1] = &TxOutputDesc{
//		mpks[1],
//		30,
//	}
//
//	txoutputDescs[2] = &TxOutputDesc{
//		mpks[2],
//		50,
//	}
//
//	cbtx, err := pp.CoinbaseTxGen(100, txoutputDescs)
//	if err != nil {
//		return
//	}
//	fmt.Println(cbtx)
//
//	bl := pp.CoinbaseTxVerify(cbtx)
//	if bl {
//		fmt.Println("CoinbaseTx Gen and Verify Pass")
//	}
//
//	// TxoCoinReceive
//	for i := 0; i < 3; i++ {
//		bl, v := pp.TxoCoinReceive(cbtx.OutputTxos[i], mpks[i], msvks[i])
//		if bl {
//			fmt.Println("value:", i, v)
//		} else {
//			fmt.Println("false:", i)
//		}
//	}
//
//	// TransferGen 1vs3
//	// 0: 20, 1:30, 2: 50
//	// 2: 50 --> 0:10, 1:30, 2:9, fee: 1
//	txInputDescs := make([]*TxInputDesc, 1)
//	txoList := make([]*TXO, 3)
//	txoList[0] = cbtx.OutputTxos[0]
//	txoList[1] = cbtx.OutputTxos[1]
//	txoList[2] = cbtx.OutputTxos[2]
//	txInputDescs[0] = &TxInputDesc{
//		txoList,
//		2,
//		mpks[2],
//		msvks[2],
//		mssks[2],
//		50,
//	}
//
//	txoutputDescs = make([]*TxOutputDesc, 3)
//
//	txoutputDescs[0] = &TxOutputDesc{
//		mpks[0],
//		10,
//	}
//
//	txoutputDescs[1] = &TxOutputDesc{
//		mpks[1],
//		30,
//	}
//
//	txoutputDescs[2] = &TxOutputDesc{
//		mpks[2],
//		9,
//	}
//
//	memo := []byte{1, 2, 3}
//
//	trTx, err := pp.TransferTxGen(txInputDescs, txoutputDescs, 1, memo)
//	if err != nil {
//		fmt.Println("false")
//	}
//	fmt.Println(trTx.Fee)
//	fmt.Println(trTx.TxMemo)
//
//	trTxbl := pp.TransferTxVerify(trTx)
//
//	if trTxbl {
//		fmt.Println("TransferTx Gen and Verify: 1v3 Pass")
//	}
//
//	// TransferGen 2vs3
//	// 0: 20, 1:30, 2: 50
//	// 2: 50 --> 0:10, 1:30, 2:9, fee: 1
//
//	//	{0:20, 1:30, 2: 50}, 0:20
//	//	{0:10, 1:30, 2:9}, 1:30
//	//	--> 0: 23, 1:15, 2:10, fee: 2
//	txInputDescs = make([]*TxInputDesc, 2)
//	txoList0 := make([]*TXO, 3)
//	txoList0[0] = cbtx.OutputTxos[0]
//	txoList0[1] = cbtx.OutputTxos[1]
//	txoList0[2] = cbtx.OutputTxos[2]
//	txInputDescs[0] = &TxInputDesc{
//		txoList0,
//		0,
//		mpks[0],
//		msvks[0],
//		mssks[0],
//		20,
//	}
//	txoList1 := make([]*TXO, 3)
//	txoList1[0] = trTx.OutputTxos[0]
//	txoList1[1] = trTx.OutputTxos[1]
//	txoList1[2] = trTx.OutputTxos[2]
//	txInputDescs[1] = &TxInputDesc{
//		txoList1,
//		1,
//		mpks[1],
//		msvks[1],
//		mssks[1],
//		30,
//	}
//
//	txoutputDescs = make([]*TxOutputDesc, 3)
//
//	txoutputDescs[0] = &TxOutputDesc{
//		mpks[0],
//		23,
//	}
//
//	txoutputDescs[1] = &TxOutputDesc{
//		mpks[1],
//		15,
//	}
//
//	txoutputDescs[2] = &TxOutputDesc{
//		mpks[2],
//		10,
//	}
//
//	trTx2v3, err := pp.TransferTxGen(txInputDescs, txoutputDescs, 2, nil)
//	if err != nil {
//		fmt.Println("false")
//	}
//	trTxbl2v3 := pp.TransferTxVerify(trTx2v3)
//
//	if trTxbl2v3 {
//		fmt.Println("TransferTx Gen and Verify: 2v3 Pass")
//	}
//
//}
//
//func TestCoinbase1out(t *testing.T) {
//	pp := DefaultPP
//	seed1, mpk1, _, _, err1 := pp.MasterKeyGen(nil)
//	if err1 != nil {
//		return
//	}
//	fmt.Println("seed1:", seed1)
//
//	txoutputDescs := make([]*TxOutputDesc, 1)
//	txoutputDescs[0] = &TxOutputDesc{
//		mpk1,
//		25,
//	}
//
//	cbtx, err := pp.CoinbaseTxGen(25, txoutputDescs)
//	if err != nil {
//		return
//	}
//	fmt.Println(cbtx)
//
//	bl := pp.CoinbaseTxVerify(cbtx)
//	if bl {
//		fmt.Println("OK")
//	}
//}
//
//func TestMasterKey_SerializeAndDeserialize(t *testing.T) {
//	tests := []struct {
//		name string
//		seed []byte
//	}{
//		// TODO: Add test cases.
//		{
//			name: "test 1",
//			seed: []byte{
//				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
//				33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
//			}},
//	}
//
//	for _, tt := range tests {
//		pp := DefaultPP
//		_, mpk, msvk, mssk, err := pp.MasterKeyGen(tt.seed)
//		if err != nil {
//			t.Errorf("MasterKeyGen() error")
//		}
//		t.Run(tt.name, func(t *testing.T) {
//			gotMpkBytes := mpk.Serialize()
//			newmpk := new(MasterPublicKey)
//			_ = newmpk.Deserialize(gotMpkBytes)
//			if !reflect.DeepEqual(mpk, newmpk) {
//				t.Errorf("Master Public Key Serialize() and Deserialize() do not match")
//			}
//
//			gotMsvkBytes := msvk.Serialize()
//			newmsvk := new(MasterSecretViewKey)
//			_ = newmsvk.Deserialize(gotMsvkBytes)
//			if !reflect.DeepEqual(msvk, newmsvk) {
//				t.Errorf("Master Secret View Key Serialize() and Deserialize() do not match")
//			}
//
//			gotMsskBytes := mssk.Serialize()
//			newmssk := new(MasterSecretSignKey)
//			_ = newmssk.Deserialize(gotMsskBytes)
//			if !reflect.DeepEqual(mssk, newmssk) {
//				t.Errorf("Master Secret Sign Key Serialize() and Deserialize() do not match")
//			}
//
//		})
//	}
//}
