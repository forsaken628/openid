package openid

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
)

var ErrInvalidOpenid = errors.New("invalid openid")

type Source struct {
	key   []byte
	block cipher.Block
}

func New(key []byte) *Source {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return &Source{key: key, block: b}
}

func (s *Source) Encode(src int64) string {
	salt := [5]byte{}
	_, err := rand.Read(salt[:])
	if err != nil {
		panic(err)
	}
	return s.EncodeWithSalt(src, salt)
}

func (s *Source) EncodeRegion(src int64, region string) string {
	salt := [5]byte{}
	_, err := rand.Read(salt[:4])
	if err != nil {
		panic(err)
	}
	sum := md5.Sum([]byte(region))
	salt[4] = sum[0]
	return s.EncodeWithSalt(src, salt)
}

func (s *Source) EncodeWithSalt(src int64, salt [5]byte) string {
	buf := [15]byte{}
	iv := [aes.BlockSize]byte{}
	copy(buf[:5], salt[:])
	copy(iv[:5], salt[:])
	t := salt[0]&0x07 + 1
	for i := byte(0); i < t; i++ {
		s.block.Encrypt(iv[:], iv[:])
	}

	n := binary.PutVarint(buf[5:], src)
	if n < 5 {
		n = 5
	}

	for i := byte(0); i < byte(n); i++ {
		buf[5+i] ^= iv[i]
	}

	return base32.StdEncoding.EncodeToString(buf[:5+n])
}

func (s *Source) Decode(src string) (int64, error) {
	return s.decode(src, nil)
}

func (s *Source) DecodeRegion(src string, region string) (int64, error) {
	sum := md5.Sum([]byte(region))
	return s.decode(src, &sum[0])
}

func (s *Source) decode(src string, regionHash *byte) (int64, error) {
	buf, err := base32.StdEncoding.DecodeString(src)
	if err != nil {
		return 0, err
	}

	if regionHash != nil && *regionHash != buf[4] {
		return 0, ErrInvalidOpenid
	}

	iv := [aes.BlockSize]byte{}
	copy(iv[:], buf[:5])
	t := buf[0]&0x07 + 1
	for i := byte(0); i < t; i++ {
		s.block.Encrypt(iv[:], iv[:])
	}

	n := byte(len(buf))
	for i := byte(5); i < n; i++ {
		buf[i] ^= iv[i-5]
	}

	x, _ := binary.Varint(buf[5:])
	return x, nil
}
