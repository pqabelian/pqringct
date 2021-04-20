package pqringct

const (
	PP_N = 51	//	N defines the value of V by V=2^N - 1
	PP_I = 5	//	PP_I defines the maximum number of consumed coins of a transfer transaction
	PP_J = 5	//	PP_J defines the maximum number of generated coins of a transaction

	PP_d = 128
	//	PP_q = 4294962689	//	q is a 32-bit prime such that q = 1 mod 512
	// PP_l = 128	//	We use fully-splitting ring, namely l=d, thus we only use d
	PP_k = 4
)

