package pqringct

import (
	"fmt"
	"math/big"
	"testing"
)

func TestReduce(t *testing.T) {
	var a big.Int
	var q int64
	q = 17
	a.SetInt64(-9)
	fmt.Println(reduceBigInt(&a, q))

}
