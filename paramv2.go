package pqringct

import (
	"github.com/cryptosuite/kyber-go/kyber"
	"golang.org/x/crypto/sha3"
	"log"
	"math/big"
)

func NewPublicParameterV2(
	paramDA int, paramQA int64, paramThetaA int, paramKA int, paramLambdaA int, paramGammaA int, paramEtaA int64, paramBetaA int16,
	paramI int, paramJ int, paramN int,
	paramDC int, paramQC int64, paramK int, paramKC int, paramLambdaC int, paramEtaC int64, paramBetaC int16,
	paramEtaF int64, paramSysBytes int,
	paramDCInv int64, paramKInv int64,
	paramZetaA int64, paramZetaAOrder int,
	paramZetaC int64, paramZetaCOrder int, paramSigmaPermutations [][]int, paramCStr []byte, paramKem *kyber.ParameterSet) (*PublicParameterv2, error) {

	res := &PublicParameterv2{
		paramDA:           paramDA,
		paramQA:           paramQA,
		paramThetaA:       paramThetaA,
		paramKA:           paramKA,
		paramLambdaA:      paramLambdaA,
		paramLA:           paramKA + paramLambdaA + 1,
		paramGammaA:       paramGammaA,
		paramEtaA:         paramEtaA,
		paramBetaA:        paramBetaA,
		paramI:            paramI,
		paramJ:            paramJ,
		paramN:            paramN,
		paramDC:           paramDC,
		paramQC:           paramQC,
		paramK:            paramK,
		paramKC:           paramKC,
		paramLambdaC:      paramLambdaC,
		paramLC:           paramKC + paramI + paramJ + 7 + paramLambdaC,
		paramEtaC:         paramEtaC,
		paramBetaC:        paramBetaC,
		paramEtaF:         paramEtaF,
		paramSeedBytesLen: paramSysBytes,
		//		paramQCm:      	paramQC >> 1,
		paramDCInv:             paramDCInv,
		paramKInv:              paramKInv,
		paramZetaA:        		paramZetaA,
		paramZetaAOrder:   		paramZetaAOrder,
		paramZetaC:             paramZetaC,
		paramZetaCOrder:        paramZetaCOrder,
		paramSigmaPermutations: paramSigmaPermutations,
		paramCStr:              paramCStr,
		paramKem:               paramKem,
	}
	//  parameters for Number Theory Transform
	res.paramZetasC = make([]int64, res.paramZetaCOrder)
	for i := 0; i < res.paramZetaCOrder; i++ {
		res.paramZetasC[i] = powerAndModP(res.paramZetaC, int64(i), res.paramQC)
	}
	res.paramZetasA = make([]int64, res.paramZetaAOrder)
	for i := 0; i < res.paramZetaAOrder; i++ {
		res.paramZetasA[i] = powerAndModP(res.paramZetaA, int64(i), res.paramQA)
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
	res.paramVecA, err = res.expandPubVecA(tmpamin)

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

	res.paramMu = make([]int64, res.paramDC)
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
	paramThetaA int

	paramKA      int
	paramLambdaA int
	// paramLA = paramKA + paramLambdaA + 1
	paramLA int

	// For randomness
	paramGammaA int
	// For masking
	paramEtaA int64
	// For bounding
	paramBetaA int16

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
	// paramQC is the module to define R_q[X] = Z_q[X] / (X^d +1)
	// q = 1 mod 2d will guarantee that R_q[X] is a fully-splitting ring, say that X^d+1 = (X-\zeta)(X-\zetz^3)...(X-\zeta^{2d-1}),
	// where \zeta is a primitive 2d-th root of unity in Z_q^*.
	// For efficiency, q is expected to small. Considering the security, q (approx.)= 2^32 is fine.
	// For uint32, q lies in [0, 2^32-1], and Z_q = [-(q-1)/2, (q-1)/1], int32 will be fine to denote the values in Z_q.
	// q_m = (q-1)/2, as this value will be often used in computation, we define it as a parameter, rather than compute it each time.
	paramQC int64
	// paramK is a power of two such that k|d and q^{-k} is negligible.
	// As we will also loop for k, we define it with 'int' type.
	paramK int
	// paramKInv = k^{-1} mod q

	// As we need to loop for paramKC, we define it with 'int' type
	paramKC      int
	paramLambdaC int
	// paramLC = paramKC + paramI + paramJ + 7 + paramLambdaC
	paramLC int

	// As paramEtaC is used to specify the infNorm of polys in Ring, thus we define it with type 'int32' (as q)
	paramEtaC int64

	// As paramBetaC is used to specify the infNorm of polys in Ring
	paramBetaC int16

	// As paramEtaF may be (q_c-1)/16, we define it with 'int64' type
	paramEtaF int64

	paramSeedBytesLen int

	// Some Helpful parameter
	/*	// paramQCm = (q_c -1)/2, as this value will be often used in computation, we define it as a parameter, rather than compute it each time.
		paramQCm int64*/
	//paramDCInv = d_c^{-1} mod q_c
	paramDCInv int64
	//paramKInv = k^{-1} mod q_c
	paramKInv int64

	paramZetaA int64
	// For splitting
	paramZetasA      []int64
	paramZetaAOrder  int
	paramNTTAFactors []int

	// paramZetaC is a primitive 2d-th root of unity in Z_q^*.
	// As zeta \in Z_q, we define it with 'int32' type.
	paramZetaC int64
	// For splitting
	paramZetasC      []int64
	paramZetaCOrder  int
	paramNTTCFactors []int

	// paramSigmaPermutations is determined by (d,k) and the selection of sigma
	// paramSigmaPermutations [t] with t=0~(k-1) works for sigma^t
	paramSigmaPermutations [][]int

	///*
	//	paramSigmaInvPermutations is determined by (d,k) and the selection of sigma
	//	paramSigmaInvPermutations [t] with t=0~(k-1) works for sigma^{-t}
	//*/
	//paramSigmaInvPermutations [][]int

	// As we need to loop paramKA, we define it with 'int' type
	//paramKA int

	// As paramCStr is used to generate the public matrix, such as paramMatrixA, paramMatrixB, paramMatrixH
	paramCStr []byte

	// paramMatrixA is expand from paramCStr, with size k_a rows, each row with size l_a
	paramMatrixA []*PolyANTTVec

	// paramVecA is expand from paramCStr, with size l_a
	paramVecA *PolyANTTVec

	//paramMatrixB is expand from paramCStr, with size k_c rows, each row with size l_c
	paramMatrixB []*PolyCNTTVec

	// paramMatrixH is expand from paramCStr, with size (paramI + paramJ + 7) rows, each row with size l_c
	paramMatrixH []*PolyCNTTVec

	// paramMu defines the const mu, which is determined by the value of N and d
	paramMu []int64

	// paramKem defines the key encapsulate mechanism
	paramKem *kyber.ParameterSet
}

func (pp *PublicParameterv2) expandPubMatrixA(seed []byte) ([]*PolyANTTVec, error) {
	res := make([]*PolyANTTVec, pp.paramKA)

	unit := pp.NewZeroPolyA()
	unit.coeffs[0] = 1
	unitNTT := pp.NTTPolyA(unit)

	// generate the remained sub-matrix
	matrix, err := pp.generatePolyANTTMatrix(seed, pp.paramKA, 1+pp.paramLambdaA)
	if err != nil {
		return nil, err
	}

	for i := 0; i < pp.paramKA; i++ {
		res[i] = pp.NewZeroPolyANTTVec(pp.paramLA)

		for t := 0; t < pp.paramDA; t++ {
			// repeatedly use unitNTT, set the coeffs rather than the pointer
			res[i].polyANTTs[i].coeffs[t] = unitNTT.coeffs[t]
		}

		for j := 0; j < 1+pp.paramLambdaA; j++ {
			res[i].polyANTTs[pp.paramKA+j] = matrix[i].polyANTTs[j]
		}

	}

	return res, nil
}

func (pp *PublicParameterv2) expandPubVecA(seed []byte) (*PolyANTTVec, error) {
	unit := pp.NewZeroPolyA()
	unit.coeffs[0] = 1
	unitNTT := pp.NTTPolyA(unit)

	// generate the remained sub-matrix
	matrix, err := pp.generatePolyANTTMatrix(seed, 1, pp.paramLambdaA)
	if err != nil {
		return nil, err
	}

	// [0 ... 0(k_a) 1 r ... r(lambda_a)]
	res := pp.NewZeroPolyANTTVec(pp.paramLA) // L_a = K_a+1+lambda_a

	res.polyANTTs[pp.paramKA] = unitNTT

	for j := 0; j < pp.paramLambdaA; j++ {
		res.polyANTTs[pp.paramKA+1+j] = matrix[0].polyANTTs[j]
	}
	return res, nil
}

func (pp *PublicParameterv2) expandPubMatrixB(seed []byte) (matrixB []*PolyCNTTVec, err error) {
	res := make([]*PolyCNTTVec, pp.paramKC)

	unit := pp.NewZeroPolyC()
	unit.coeffs[0] = 1
	unitNTT := pp.NTTPolyC(unit)

	// generate the remained sub-matrix
	matrix, err := pp.generatePolyCNTTMatrix(seed, pp.paramKC, pp.paramI+pp.paramJ+7+pp.paramLambdaC)
	if err != nil {
		return nil, err
	}

	for i := 0; i < pp.paramKC; i++ {
		res[i] = pp.NewZeroPolyCNTTVec(pp.paramLC)

		for t := 0; t < pp.paramDC; t++ {
			res[i].polyCNTTs[i].coeffs[t] = unitNTT.coeffs[t]
		}

		for j := 0; j < pp.paramI+pp.paramJ+7+pp.paramLambdaC; j++ {
			res[i].polyCNTTs[pp.paramKC+j] = matrix[i].polyCNTTs[j]
		}

	}

	return res, nil
}


func (pp *PublicParameterv2) expandPubMatrixH(seed []byte) (matrixH []*PolyCNTTVec, err error) {
	res := make([]*PolyCNTTVec, pp.paramI+pp.paramJ+7)

	unitPoly := pp.NewZeroPolyC()
	unitPoly.coeffs[0] = 1
	unitNTT := pp.NTTPolyC(unitPoly)

	// generate the remained sub-matrix
	matrix, err := pp.generatePolyCNTTMatrix(seed, pp.paramI+pp.paramJ+7, pp.paramLambdaC)
	if err != nil {
		return nil, err
	}

	for i := 0; i < pp.paramI+pp.paramJ+7; i++ {
		res[i] = pp.NewZeroPolyCNTTVec(pp.paramLC) // L_c=K_c+I+J+7+lambda_c

		for t := 0; t < pp.paramDC; t++ {
			res[i].polyCNTTs[pp.paramKC+i].coeffs[t] = unitNTT.coeffs[t]
		}

		for j := 0; j < pp.paramLambdaC; j++ {
			res[i].polyCNTTs[pp.paramKC+pp.paramI+pp.paramJ+7+j] = matrix[i].polyCNTTs[j]
		}
	}

	return res, nil
}


var DefaultPPV2 *PublicParameterv2

func init() {
	var err error

	DefaultPPV2, err = NewPublicParameterV2(
		256,
		137438953937,
		60,
		5,
		4,
		5,
		524287,
		300,
		5,
		5,
		51,
		128,
		9007199254746113,
		4,
		10,
		10,
		16777215,
		128,
		(137438953937-1)>>4,
		256,
		-70368744177704,
		-2251799813686528,
		-12372710086,
		16,
		-396137427805508,
		256,
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
		[]byte("Welcome to Post Quantum World!"), // todo:
		kyber.Kyber768,
	)
	if err != nil {
		log.Fatalln(err)
	}
}

func powerAndModP(base int64, power int64, p int64) int64 {
	a := big.NewInt(base)
	b := big.NewInt(power)
	mod := big.NewInt(p)
	res := big.NewInt(1).Exp(a, b, mod).Int64()
	if res > (p-1)>>1 {
		res -= p
	}
	return res
}
