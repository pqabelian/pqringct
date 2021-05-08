package pqringct

const (
	PP_N = 51 //	N defines the value of V by V=2^N - 1
	PP_I = 5  //	PP_I defines the maximum number of consumed coins of a transfer transaction
	PP_J = 5  //	PP_J defines the maximum number of generated coins of a transaction

	PP_d   = 128
	PP_q   = 4294962689 //	q=11111111111111111110111000000001 is a 32-bit prime such that q = 1 mod 512,
	PP_q_m = 2147481344 //	q_m = q/2-1
	// PP_l = 128	//	We use fully-splitting ring, namely l=d, thus we only use d
	PP_k = 4

	PP_k_a    = 10       //	todo:
	PP_l_a    = 10       //	todo:
	PP_eta_a  = 1024 - 1 //	todo:
	PP_beta_a = 2        //	 todo:

	PP_k_c      = 10       //	todo:
	PP_l_c      = 10       //	todo:
	PP_eta_c    = 1024 - 1 //	todo:
	PP_beta_c   = 2        //	 todo:
	PP_eta_c_1  = 1024 - 1 //	todo:
	PP_beta_c_1 = 2        //	 todo:

	PP_m_a   = 1        //	todo:
	PP_eta_f = 1024 - 1 // todo:
)

//TODO_DONE : change the int to intX or uintX
type PublicParameter struct {
	//	paramN defines the value of V by V=2^N - 1
	paramN uint8 // N<256

	/*
		paramI defines the maximum number of consumed coins of a transfer transaction
		As we need to loop for paramI and paramJ, we define them with 'int' type.
	*/
	paramI int

	/*
		paramJ defines the maximum number of generated coins of a transaction
		As we need to loop for paramI and paramJ, we define them with 'int' type.
	*/
	paramJ int

	/*
			d: the degree of the polynomial ring, say R =Z[X] / (X^d + 1)
			d should be a power of two, not too small (otherwise is insecure) and not too large (otherwise inefficient)
			here we define it as 'int', since we need to loop from 0 to d-1 for some matrix, and int is fine for the possible
			values, such as d=128, 256, 512, and even 1024, on any platform/OS, since int maybe int32 or int64.
		require: d >= 128
	*/
	paramD int
	/*
		paramDInv = d^{-1} mod q
	*/
	paramDInv int32

	/*
		q is the module to define R_q[X] = Z_q[X] / (X^d +1)
		q = 1 mod 2d will guarantee that R_q[X] is a fully-splitting ring, say that X^d+1 = (X-\zeta)(X-\zetz^3)...(X-\zeta^{2d-1}),
		where \zeta is a primitive 2d-th root of unity in Z_q^*.
		For efficiency, q is expected to small. Considering the security, q (approx.)= 2^32 is fine.
		For uint32, q lies in [0, 2^32-1], and Z_q = [-(q-1)/2, (q-1)/1], int32 will be fine to denote the values in Z_q.
		q_m = (q-1)/2, as this value will be often used in computation, we define it as a parameter, rather than compute it each time.
	*/
	paramQ uint32

	/*
		q_m = (q-1)/2, as this value will be often used in computation, we define it as a parameter, rather than compute it each time.
	*/
	paramQm uint32

	/*
		k is a power of two such that k|d and q^{-k} is negligible.
		As we will also loop for k, we define it with 'int' type.
	*/
	paramK int

	/*
		paramKInv = k^{-1} mod q
	*/
	paramKInv int32

	/*
		zeta is a primitive 2d-th root of unity in Z_q^*.
		As zeta \in Z_q, we define it with 'int32' type.
	*/
	paramZeta int32

	/*
		As we need to loop k_a, we define it with 'int' type
	*/
	paramKa int

	/*
		As we need to loop k_a, we define it with 'int' type
	*/
	paramLa int

	paramETAa  uint16
	paramBETAa uint8

	/*
		As we need to loop for k_c, we define it with 'int' type
	*/
	paramKc int

	/*
		As we need to loop for l_c, we define it with 'int' type
	*/
	paramLc int

	/*
		As eta_c is used to specify the infNorm of polys in Ring, thus we define it with type 'int32' (as q)
	*/
	paramEtaC int32

	/*
		As beta_c is used to specify the infNorm of polys in Ring, thus we define it with type 'int32' (as q)
	*/
	paramBetaC int32

	paramETAc1  uint16
	paramBETAc1 uint8

	paramMa uint8

	/*
		As paramEtaF may be q/12, we define it with 'int32' type
	*/
	paramEtaF int32

	paramCStr []byte

	/*
		paramMatrixA is expand from paramCStr, with size k_a rows, each row with size l_a
	*/
	paramMatrixA []*PolyNTTVec

	/*
		paramMatrixB is expand from paramCStr, with size k_c rows, each row with size l_c
	*/
	paramMatrixB []*PolyNTTVec

	/*
		paramMatrixC is expand from paramCStr, with size (paramI + paramJ + 7) rows, each row with size l_c
	*/
	paramMatrixC []*PolyNTTVec

	/**
	paramMu defines the const mu, which is determined by the value of N and d
	*/
	paramMu []int32
}

func NewPublicParameter(paramN uint8, paramI int, paramJ int, paramD int, paramQ uint32, paramZeta int32, paramK int, paramKa int, paramLa int, paramETAa uint16, paramBETAa uint8, paramKc int, paramLc int, paramEtaC int32, paramBetaC int32, paramETAc1 uint16, paramBETAc1 uint8, paramMa uint8, paramEtaF int32) *PublicParameter {
	return &PublicParameter{paramN: paramN, paramI: paramI, paramJ: paramJ, paramD: paramD, paramQ: paramQ, paramZeta: paramZeta, paramK: paramK, paramKa: paramKa, paramLa: paramLa, paramETAa: paramETAa, paramBETAa: paramBETAa, paramKc: paramKc, paramLc: paramLc, paramEtaC: paramEtaC, paramBetaC: paramBetaC, paramETAc1: paramETAc1, paramBETAc1: paramBETAc1, paramMa: paramMa, paramEtaF: paramEtaF}
}

/*
func (p *PublicParameter) MasterKeyGen(seed []byte) (*MasterPubKey, *MasterSecretViewKey, *MasterSecretSignKey) {
	panic("implement me")
	//b=reduce(a,q)
	//return masterKeyGen(pp Param,seed)
}

func (p *PublicParameter) CoinbaseTxGen(vin int32, txos []*TxOutputDesc) *CoinbaseTx {
	panic("implement me")
}

func (p *PublicParameter) CoinbaseTxVerify(tx *CoinbaseTx) bool {
	panic("implement me")
}

func (p *PublicParameter) TXOCoinReceive(dpk *DerivedPubKey, commitment []byte, vc []byte, mpk *MasterPubKey, key *MasterSecretViewKey) (bool, int32) {
	panic("implement me")
}

func (p *PublicParameter) TransferTXGen(descs []*TxInputDesc, descs2 []*TxOutputDesc) *TransferTx {
	panic("implement me")
}

func (p *PublicParameter) TransferTXVerify(tx *TransferTx) bool {
	panic("implement me")
}*/

var DefaultPP *PublicParameter = NewPublicParameter(
	51,
	5,
	5,

	128,
	4294962689,
	27080629,
	4,

	10,
	10,
	1024-1,
	2,

	10,
	10,
	1024-1,
	2,

	1024-1,
	2,

	1,
	1024-1,
)

// PQRingCT TODO_DONE: optimize the interface using array?  not
// TODO: efficiency of interface...
type PQRingCT interface {
	MasterKeyGen(seed []byte) (*MasterPubKey, *MasterSecretViewKey, *MasterSecretSignKey)
	CoinbaseTxGen(vin int32, txos []*TxOutputDesc) *CoinbaseTx //(dpk *DerivedPubKey,commit []byte,vc []byte)
	CoinbaseTxVerify(tx *CoinbaseTx) bool
	TXOCoinReceive(dpk *DerivedPubKey, commitment []byte, vc []byte, mpk *MasterPubKey, key *MasterSecretViewKey) (bool, int32)
	TransferTXGen([]*TxInputDesc, []*TxOutputDesc) *TransferTx
	TransferTXVerify(tx *TransferTx) bool
}

type PubParams struct {
	// the length must be paramLa
	A []PolyNTTVec
	// the length must be paramLc
	B []PolyNTTVec
	// the length must be paramI + paramJ + 7
	C []PolyNTTVec //	C[0] = h, C[1]=h_1, ..., C[PP_I+PP_J+6]=h_{PP_I+PP_J+6}
}

// xis is used for ntt and inv-ntt
// TODO_DONE：find a element which order is 256 in d=256
var zetas []uint64 = []uint64{27080629, 4110422914, 2991980804, 3818155385, 4178285626, 3801306276, 1788171609, 719032860, 693020064, 1012065793, 3868474504, 822594634, 3863096576, 1398707051, 1617469426, 3734280983, 4203860295, 268973648, 1264355536, 2457014977, 1862610191, 1845557350, 3524646689, 155760493, 1791293172, 553881927, 1022335433, 2357246872, 1922387663, 3329435763, 2606861621, 2763822798, 2054698751, 3435571946, 1520250555, 2404439723, 159939512, 1935361546, 471402711, 2017533877, 1731369037, 557969974, 2590036638, 136377223, 242328406, 3526651335, 3309073004, 2423454911, 508237158, 2223996169, 630153399, 51037300, 1193962498, 4195730401, 824518067, 3353723723, 3285308318, 3025141231, 2861676009, 2900242289, 2759591014, 2795702206, 158743006, 320463862, 4267882060, 184539775, 1302981885, 476807304, 116677063, 493656413, 2506791080, 3575929829, 3601942625, 3282896896, 426488185, 3472368055, 431866113, 2896255638, 2677493263, 560681706, 91102394, 4025989041, 3030607153, 1837947712, 2432352498, 2449405339, 770316000, 4139202196, 2503669517, 3741080762, 3272627256, 1937715817, 2372575026, 965526926, 1688101068, 1531139891, 2240263938, 859390743, 2774712134, 1890522966, 4135023177, 2359601143, 3823559978, 2277428812, 2563593652, 3736992715, 1704926051, 4158585466, 4052634283, 768311354, 985889685, 1871507778, 3786725531, 2070966520, 3664809290, 4243925389, 3101000191, 99232288, 3470444622, 941238966, 1009654371, 1269821458, 1433286680, 1394720400, 1535371675, 1499260483, 4136219683, 3974498827}

func (pp *PublicParameter) reduce(a int64) int32 {
	qm := int64(pp.paramQm)

	rst := a % int64(pp.paramQ)

	if rst > qm {
		rst = rst - qm
	} else if rst < -qm {
		rst = rst + qm
	}

	return int32(rst)
}
