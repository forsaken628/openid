package openid

import (
	"math"
	"testing"
)

var i64s = []int64{
	0, 1, -1, 5, -5,
	10, -10, 1000, -1000,
	1234567,
	12345678901,

	1234567890123,
	123456789012345,
	math.MaxInt64,
	-math.MaxInt64 - 1}

func TestEncode(t *testing.T) {
	key := [32]byte{5}
	s := New(key[:])
	for _, src1 := range i64s {
		str := s.Encode(src1)
		t.Log(str)
		src2, err := s.Decode(str)
		if err != nil {
			t.Fatal(err)
		}
		if src1 != src2 {
			t.Fatal(src1, src2)
		}
	}
}

func TestEncodeRegion(t *testing.T) {
	key := [16]byte{37, 45}
	s := New(key[:])
	_, err := s.DecodeRegion(s.EncodeRegion(12312, "adsf"), "adsf")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.DecodeRegion(s.EncodeRegion(12312, "adsf"), "ads")
	if err != ErrInvalidOpenid {
		t.Fatal(err)
	}
}
