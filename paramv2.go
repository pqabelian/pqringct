package pqringct

import (
	"github.com/cryptosuite/kyber-go/kyber"
	"golang.org/x/crypto/sha3"
	"log"
)

func NewPublicParameterV2(
	paramDA int, paramQA int64, paramThetaA int32, paramKA int, paramLA int, paramGammaA int32, paramEtaA int32,
	paramI int, paramJ int, paramN int, paramDC int, paramDCInv int32, paramQC uint32, paramK int, paramKInv int32, paramKC int, paramLC int, paramBetaC int32, paramEtaC int32,
	paramEtaF int32, paramSysBytes int,
	paramZeta int32, paramSigmaPermutations [][]int, paramCStr []byte, paramKem *kyber.ParameterSet) (*PublicParameterv2, error) {
	res := &PublicParameterv2{
		paramDA:       paramDA,
		paramQA:       paramQA,
		paramThetaA:   paramThetaA,
		paramKA:       paramKA,
		paramLambdaA:  paramLA - paramKA - 1,
		paramLA:       paramLA,
		paramGammaA:   paramGammaA,
		paramEtaA:     paramEtaA,
		paramI:        paramI,
		paramJ:        paramJ,
		paramN:        paramN,
		paramDC:       paramDC,
		paramDCInv:    paramDCInv,
		paramQC:       paramQC,
		paramQCm:      paramQC >> 1,
		paramK:        paramK,
		paramKInv:     paramKInv,
		paramKC:       paramKC,
		paramLambdaC:  paramLC - paramKC - paramI - paramJ - 7,
		paramLC:       paramLC,
		paramBetaC:    paramBetaC,
		paramBetaC2:   paramBetaC,
		paramEtaC:     paramEtaC,
		paramEtaC2:    paramEtaC,
		paramEtaF:     paramEtaF,
		paramSysBytes: paramSysBytes,

		paramSigmaPermutations: paramSigmaPermutations,
		paramZeta:              paramZeta,
		paramCStr:              paramCStr,
		paramKem:               paramKem,
	}
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

	// generate the public matrix paramVecA from seed
	tmpamin := make([]byte, 32)
	sha3.ShakeSum256(tmpamin, append([]byte{'M', 'C', 'a'}, seed...))
	res.paramVecA, err = res.expandPubVecAv2(tmpamin)

	// generate the public matrix paramMatrixB from seed
	tmpb := make([]byte, 32)
	sha3.ShakeSum256(tmpb, append([]byte{'M', 'B'}, seed...))
	res.paramMatrixB, err = res.expandPubMatrixB(tmpb)
	if err != nil {
		return nil, err
	}

	// generate the public matrix paramMatrixH from seed
	tmpc := make([]byte, 32)
	sha3.ShakeSum256(tmpc, append([]byte{'M', 'H'}, seed...))
	res.paramMatrixH, err = res.expandPubMatrixH(tmpc)
	if err != nil {
		return nil, err
	}

	res.paramMu = make([]int32, res.paramDC)
	for i := 0; i < res.paramN; i++ {
		res.paramMu[i] = 1
	}

	return res, nil
}

type PublicParameterv2 struct {

	// Paramter for Address
	paramDA int
	paramQA int64
	// For challenge
	paramThetaA int32
	// paramLA = paramKA + 1 + paramLambdaA
	paramKA      int
	paramLambdaA int
	paramLA      int
	// For randomness
	paramGammaA int32
	// For masking
	paramEtaA int32

	// Parameter for Commit
	// paramI defines the maximum number of consumed coins of a transfer transaction
	// As we need to loop for paramI and paramJ, we define them with 'int' type.
	paramI int
	// paramJ defines the maximum number of generated coins of a transaction
	// As we need to loop for paramI and paramJ, we define them with 'int' type.
	paramJ int
	// paramN defines the value of V by V=2^N - 1
	// paramN <= paramDC
	// As we need to loop for paramN, we define them with 'int' type.
	paramN int
	// paramDC: the degree of the polynomial ring, say R =Z[X] / (X^d + 1)
	// d should be a power of two, not too small (otherwise is insecure) and not too large (otherwise inefficient)
	// here we define it as 'int', since we need to loop from 0 to d-1 for some matrix, and int is fine for the possible
	// values, such as d=128, 256, 512, and even 1024, on any platform/OS, since int maybe int32 or int64.
	// require: d >= 128
	paramDC int
	//paramDCInv = d^{-1} mod q
	paramDCInv int32
	// paramQC is the module to define R_q[X] = Z_q[X] / (X^d +1)
	// q = 1 mod 2d will guarantee that R_q[X] is a fully-splitting ring, say that X^d+1 = (X-\zeta)(X-\zetz^3)...(X-\zeta^{2d-1}),
	// where \zeta is a primitive 2d-th root of unity in Z_q^*.
	// For efficiency, q is expected to small. Considering the security, q (approx.)= 2^32 is fine.
	// For uint32, q lies in [0, 2^32-1], and Z_q = [-(q-1)/2, (q-1)/1], int32 will be fine to denote the values in Z_q.
	// q_m = (q-1)/2, as this value will be often used in computation, we define it as a parameter, rather than compute it each time.
	paramQC uint32
	// paramQCm = (q-1)/2, as this value will be often used in computation, we define it as a parameter, rather than compute it each time.
	paramQCm uint32
	// paramK is a power of two such that k|d and q^{-k} is negligible.
	// As we will also loop for k, we define it with 'int' type.
	paramK int
	// paramKInv = k^{-1} mod q
	paramKInv int32
	// paramLC = paramKC + paramI + paramJ + 7 + paramLambdaC
	// As we need to loop for paramKC, we define it with 'int' type
	paramKC      int
	paramLambdaC int
	// As we need to loop for paramLC, we define it with 'int' type
	paramLC int
	// As paramBetaC is used to specify the infNorm of polys in Ring, thus we define it with type 'int32' (as q)
	paramBetaC int32
	// As paramEtaC is used to specify the infNorm of polys in Ring, thus we define it with type 'int32' (as q)
	paramEtaC int32
	// As paramEtaF may be (q_c-1)/16, we define it with 'uint32' type
	paramEtaF int32

	paramSysBytes int

	// Some Helpful parameter
	// paramSigmaPermutations is determined by (d,k) and the selection of sigma
	// paramSigmaPermutations [t] with t=0~(k-1) works for sigma^t
	paramSigmaPermutations [][]int

	///*
	//	paramSigmaInvPermutations is determined by (d,k) and the selection of sigma
	//	paramSigmaInvPermutations [t] with t=0~(k-1) works for sigma^{-t}
	//*/
	//paramSigmaInvPermutations [][]int

	// paramZeta is a primitive 2d-th root of unity in Z_q^*.
	// As zeta \in Z_q, we define it with 'int32' type.
	paramZeta int32

	// As we need to loop paramKA, we define it with 'int' type
	//paramKA int

	// As we need to loop paramLA, we define it with 'int' type
	//paramLA int
	paramBetaA int32

	paramEtaC2  int32
	paramBetaC2 int32

	// paramMa is used to specify the row number of Key Image Matrix
	// As we need to loop for m_a, we define it with 'int' type
	paramMa int

	// As paramCStr is used to generate the public matrix, such as paramMatrixA, paramMatrixB, paramMatrixH
	paramCStr []byte

	// paramMatrixA is expand from paramCStr, with size k_a rows, each row with size l_a
	paramMatrixA []*PolyVecv2

	paramVecA *PolyVecv2

	//paramMatrixB is expand from paramCStr, with size k_c rows, each row with size l_c
	paramMatrixB []*PolyNTTVecv2

	// paramMatrixH is expand from paramCStr, with size (paramI + paramJ + 7) rows, each row with size l_c
	paramMatrixH []*PolyNTTVecv2

	// paramMu defines the const mu, which is determined by the value of N and d
	paramMu []int32

	// paramKem defines the key encapsulate mechanism
	paramKem *kyber.ParameterSet
}

func (pp *PublicParameterv2) expandPubMatrixA(seed []byte) (matrixA []*PolyVecv2, err error) {
	res := make([]*PolyVecv2, pp.paramKA)
	for i := 0; i < pp.paramKA; i++ {
		res[i] = NewPolyVecv2(R_QA, pp.paramDA, pp.paramLA)
		res[i].polys[i].coeffs2[0] = 1
	}
	// generate the remained sub-matrix
	matrix, err := generateMatrix(seed, R_QA, pp.paramDA, pp.paramKA, 1+pp.paramLambdaA)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(matrix); i++ {
		for j := 0; j < len(matrix[i].polys); j++ {
			for k := 0; k < pp.paramDC; k++ {
				res[i].polys[j+pp.paramKA].coeffs2[k] = matrix[i].polys[j].coeffs2[k]
			}
		}
	}
	return res, nil
}

var DefaultPPV2 *PublicParameterv2

func init() {
	var err error
	DefaultPPV2, err = NewPublicParameterV2(
		256,
		34360786961,
		60,
		5,
		10,
		5,
		559557,
		5,
		5,
		51,
		128,
		-33554396,
		4294962689,
		4,
		-1073740672,
		10,
		37,
		128,
		1<<22,
		268435168,
		256/32,
		27080629,
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
		[]byte("This is experiment const string"),
		kyber.Kyber768,
	)
	if err != nil {
		log.Fatalln(err)
	}
}
