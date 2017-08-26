package openid

import (
	"testing"
	"math"
)

var srcs = []int64{0, 1, 5, 10, 1000, 3453453, 34345345345, -1, -34234, math.MaxInt64, -math.MaxInt64 - 1, math.MaxInt32}

func TestSource_Encode(t *testing.T) {
	key := make([]byte, 16)
	key[0] = 5
	s := New(key)
	for _, src1 := range srcs {
		str := s.Encode(src1)
		// t.Log(str)
		src2, err := s.Decode(str)
		if err != nil {
			t.Fatal(err)
		}
		if src1 != src2 {
			t.Fatal(src1, src2)
		}
	}
}
