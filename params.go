package pqringct

import (
	"github.com/cryptosuite/kyber-go/kyber"
	"golang.org/x/crypto/sha3"
	"log"
)

const (
	PP_N = 51 //	N defines the value of V by V=2^N - 1
	PP_I = 5  //	PP_I defines the maximum number of consumed coins of a transfer transaction
	PP_J = 5  //	PP_J defines the maximum number of generated coins of a transaction

	PP_d   = 128
	PP_q   = 4294962689 //	q=11111111111111111110111000000001 is a 32-bit prime such that q = 1 mod 512,
	PP_q_m = 2147481344 //	q_m = q/2-1
	// PP_l = 128	//	We use fully-splitting ring, namely l=d, thus we only use d
	PP_k = 4

	PP_k_a    = 10
	PP_l_a    = 10
	PP_eta_a  = 1024 - 1
	PP_beta_a = 2

	PP_k_c      = 10
	PP_l_c      = 10
	PP_eta_c    = 1024 - 1
	PP_beta_c   = 2
	PP_eta_c_1  = 1024 - 1
	PP_beta_c_1 = 2

	PP_m_a   = 1
	PP_eta_f = 1024 - 1
)

//TODO_DONE : change the int to intX or uintX
type PublicParameter struct {
	/*
		paramN defines the value of V by V=2^N - 1
		N <= d
		As we need to loop for paramN, we define them with 'int' type.
	*/
	paramN int

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
			paramD: the degree of the polynomial ring, say R =Z[X] / (X^d + 1)
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
		paramQ is the module to define R_q[X] = Z_q[X] / (X^d +1)
		q = 1 mod 2d will guarantee that R_q[X] is a fully-splitting ring, say that X^d+1 = (X-\zeta)(X-\zetz^3)...(X-\zeta^{2d-1}),
		where \zeta is a primitive 2d-th root of unity in Z_q^*.
		For efficiency, q is expected to small. Considering the security, q (approx.)= 2^32 is fine.
		For uint32, q lies in [0, 2^32-1], and Z_q = [-(q-1)/2, (q-1)/1], int32 will be fine to denote the values in Z_q.
		q_m = (q-1)/2, as this value will be often used in computation, we define it as a parameter, rather than compute it each time.
	*/
	paramQ uint32

	/*
		paramQm = (q-1)/2, as this value will be often used in computation, we define it as a parameter, rather than compute it each time.
	*/
	paramQm uint32

	/*
		paramK is a power of two such that k|d and q^{-k} is negligible.
		As we will also loop for k, we define it with 'int' type.
	*/
	paramK int

	/*
		paramKInv = k^{-1} mod q
	*/
	paramKInv int32

	/*
		paramSigmaPermutations is determined by (d,k) and the selection of sigma
		paramSigmaPermutations [t] with t=0~(k-1) works for sigma^t
	*/
	paramSigmaPermutations [][]int

	///*
	//	paramSigmaInvPermutations is determined by (d,k) and the selection of sigma
	//	paramSigmaInvPermutations [t] with t=0~(k-1) works for sigma^{-t}
	//*/
	//paramSigmaInvPermutations [][]int

	/*
		paramZeta is a primitive 2d-th root of unity in Z_q^*.
		As zeta \in Z_q, we define it with 'int32' type.
	*/
	paramZeta int32

	/*
		As we need to loop paramKa, we define it with 'int' type
	*/
	paramKa int

	/*
		As we need to loop paramLa, we define it with 'int' type
	*/
	paramLa int

	paramEtaA  int32
	paramBetaA int32

	/*
		As we need to loop for paramKc, we define it with 'int' type
	*/
	paramKc int

	/*
		As we need to loop for paramLc, we define it with 'int' type
	*/
	paramLc int

	/*
		As paramEtaC is used to specify the infNorm of polys in Ring, thus we define it with type 'int32' (as q)
	*/
	paramEtaC int32

	/*
		As paramBetaC is used to specify the infNorm of polys in Ring, thus we define it with type 'int32' (as q)
	*/
	paramBetaC int32

	paramEtaC2  int32
	paramBetaC2 int32

	/*
		paramMa is used to specify the row number of Key Image Matrix
		As we need to loop for m_a, we define it with 'int' type
	*/
	paramMa int

	/*
		As paramEtaF may be q/12, we define it with 'int32' type
	*/
	paramEtaF int32

	/*
		As paramCStr is used to generate the public matrix, such as paramMatrixA, paramMatrixB, paramMatrixC
	*/
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

	/*
		paramMu defines the const mu, which is determined by the value of N and d
	*/
	paramMu []int32

	/*
		paramKem defines the key encapsulate mechanism
	*/
	paramKem *kyber.ParameterSet
	/*
		paramSysBytes defines the length of system parameters
	*/
	paramSysBytes int
}

// NewPublicParameter construct a PublicParameter with some parameters
func NewPublicParameter(paramN int, paramI int, paramJ int, paramD int, paramDInv int32, paramQ uint32, paramZeta int32, paramK int, paramKInv int32, paramSigmaPermutations [][]int, paramKa int, paramLa int, paramEtaA int32, paramBetaA int32, paramKc int, paramLc int, paramEtaC int32, paramBetaC int32, paramEtaC2 int32, paramBetaC2 int32, paramMa int, paramCStr []byte, paramEtaF int32, paramKem *kyber.ParameterSet, paramSysBytes int) (*PublicParameter, error) {
	res := &PublicParameter{paramN: paramN, paramI: paramI, paramJ: paramJ, paramD: paramD, paramDInv: paramDInv, paramQ: paramQ, paramZeta: paramZeta, paramK: paramK, paramKInv: paramKInv, paramSigmaPermutations: paramSigmaPermutations, paramKa: paramKa, paramLa: paramLa, paramEtaA: paramEtaA, paramBetaA: paramBetaA, paramKc: paramKc, paramLc: paramLc, paramEtaC: paramEtaC, paramBetaC: paramBetaC, paramEtaC2: paramEtaC2, paramBetaC2: paramBetaC2, paramMa: paramMa, paramCStr: paramCStr, paramEtaF: paramEtaF, paramKem: paramKem, paramSysBytes: paramSysBytes}
	res.paramQm = res.paramQ >> 1
	seed, err := Hash(res.paramCStr)
	if err != nil {
		return nil, err
	}
	// generate the public matrix paramMatrixA from seed
	tmpa := make([]byte, 32)
	sha3.ShakeSum256(tmpa, append([]byte{'M', 'C'}, seed...))
	res.paramMatrixA, err = res.expandPubMatrixA(tmpa)
	if err != nil {
		return nil, err
	}
	// generate the public matrix paramMatrixB from seed
	tmpb := make([]byte, 32)
	sha3.ShakeSum256(tmpb, append([]byte{'M', 'B'}, seed...))
	res.paramMatrixB, err = res.expandPubMatrixB(tmpb)
	if err != nil {
		return nil, err
	}
	// generate the public matrix paramMatrixC from seed
	tmpc := make([]byte, 32)
	sha3.ShakeSum256(tmpc, append([]byte{'M', 'C'}, seed...))
	res.paramMatrixC, err = res.expandPubMatrixC(tmpc)
	if err != nil {
		return nil, err
	}
	res.paramMu = make([]int32, res.paramD)
	for i := 0; i < res.paramN; i++ {
		res.paramMu[i] = 1
	}
	return res, nil
}

/*
func (p *PublicParameter) MasterKeyGen(seed []byte) (*MasterPublicKey, *MasterSecretViewKey, *MasterSecretSignKey) {
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

func (p *PublicParameter) TXOCoinReceive(dpk *DerivedPubKey, commitment []byte, vc []byte, mpk *MasterPublicKey, key *MasterSecretViewKey) (bool, int32) {
	panic("implement me")
}

func (p *PublicParameter) TransferTXGen(descs []*TxInputDesc, descs2 []*TxOutputDesc) *TransferTx {
	panic("implement me")
}

func (p *PublicParameter) TransferTXVerify(tx *TransferTx) bool {
	panic("implement me")
}*/

// DefaultPP is a public parameter which will be generated by the default parameters
var DefaultPP *PublicParameter

// PQRingCT TODO_DONE: optimize the interface using array?  not
//
//type PQRingCT interface {
//	MasterKeyGen(seed []byte) (*MasterPublicKey, *MasterSecretViewKey, *MasterSecretSignKey)
//	CoinbaseTxGen(vin int32, txos []*TxOutputDesc) *CoinbaseTx //(dpk *DerivedPubKey,commit []byte,vc []byte)
//	CoinbaseTxVerify(tx *CoinbaseTx) bool
//	TXOCoinReceive(dpk *DerivedPubKey, commitment []byte, vc []byte, mpk *MasterPublicKey, key *MasterSecretViewKey) (bool, int32)
//	TransferTXGen([]*TxInputDesc, []*TxOutputDesc) *TransferTx
//	TransferTXVerify(tx *TransferTx) bool
//}

//type PubParams struct {
//	// the length must be paramLa
//	A []PolyNTTVec
//	// the length must be paramLc
//	B []PolyNTTVec
//	// the length must be paramI + paramJ + 7
//	C []PolyNTTVec //	C[0] = h, C[1]=h_1, ..., C[PP_I+PP_J+6]=h_{PP_I+PP_J+6}
//}

// reduce is private function for helping the overall operation is in Zq which is described by paramQ
func (pp *PublicParameter) reduce(a int64) int32 {
	rst := a % int64(pp.paramQ)
	rst = (rst + int64(pp.paramQ)) % int64(pp.paramQ)
	if rst > int64(pp.paramQm) {
		rst = rst - int64(pp.paramQ)
	}
	return int32(rst)
}

func (pp *PublicParameter) reduceInt64(a int64) int64 {
	rst := a % int64(pp.paramQ)
	rst = (rst + int64(pp.paramQ)) % int64(pp.paramQ)
	if rst > int64(pp.paramQm) {
		rst = rst - int64(pp.paramQ)
	}
	return rst
}

// init set the default public parameter for package importer
func init() {
	var err error
	DefaultPP, err = NewPublicParameter(
		51,
		5,
		5,

		128,
		-33554396,
		4294962689,
		27080629,
		4,
		-1073740672,
		[][]int{
			{
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
				16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
				32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
				48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
				64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
				80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
				96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
				112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
			},
			{
				32, 97, 34, 99, 36, 101, 38, 103, 40, 105, 42, 107, 44, 109, 46, 111,
				48, 113, 50, 115, 52, 117, 54, 119, 56, 121, 58, 123, 60, 125, 62, 127,
				64, 1, 66, 3, 68, 5, 70, 7, 72, 9, 74, 11, 76, 13, 78, 15,
				80, 17, 82, 19, 84, 21, 86, 23, 88, 25, 90, 27, 92, 29, 94, 31,
				96, 33, 98, 35, 100, 37, 102, 39, 104, 41, 106, 43, 108, 45, 110, 47,
				112, 49, 114, 51, 116, 53, 118, 55, 120, 57, 122, 59, 124, 61, 126, 63,
				0, 65, 2, 67, 4, 69, 6, 71, 8, 73, 10, 75, 12, 77, 14, 79,
				16, 81, 18, 83, 20, 85, 22, 87, 24, 89, 26, 91, 28, 93, 30, 95,
			},
			{
				64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
				80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
				96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
				112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
				16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
				32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
				48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
			},
			{
				96, 33, 98, 35, 100, 37, 102, 39, 104, 41, 106, 43, 108, 45, 110, 47,
				112, 49, 114, 51, 116, 53, 118, 55, 120, 57, 122, 59, 124, 61, 126, 63,
				0, 65, 2, 67, 4, 69, 6, 71, 8, 73, 10, 75, 12, 77, 14, 79,
				16, 81, 18, 83, 20, 85, 22, 87, 24, 89, 26, 91, 28, 93, 30, 95,
				32, 97, 34, 99, 36, 101, 38, 103, 40, 105, 42, 107, 44, 109, 46, 111,
				48, 113, 50, 115, 52, 117, 54, 119, 56, 121, 58, 123, 60, 125, 62, 127,
				64, 1, 66, 3, 68, 5, 70, 7, 72, 9, 74, 11, 76, 13, 78, 15,
				80, 17, 82, 19, 84, 21, 86, 23, 88, 25, 90, 27, 92, 29, 94, 31,
			},
		},
		10,
		20,
		1<<22-1,
		256,

		10,
		36,
		1<<25-1,
		128,

		1<<23-1,
		256,

		1,
		[]byte("This is experiment const string"),
		1<<28-1,
		kyber.Kyber768,
		32,
	)
	if err != nil {
		log.Fatalln("init error")
	}
}
