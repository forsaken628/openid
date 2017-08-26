package openid

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/cipher"
	"encoding/binary"
	"encoding/base32"
	"errors"
	"crypto/md5"
)

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
	salt := [2]byte{}
	_, err := rand.Read(salt[:])
	if err != nil {
		panic(err)
	}
	return s.encode(src, salt)
}

func (s *Source) EncodeStatic(src int64, region string) string {
	salt := [2]byte{}
	sum := md5.Sum([]byte(region))
	copy(salt[:], sum[:2])
	return s.encode(src, salt)
}

func (s *Source) EncodeWithSalt(src int64, salt [2]byte) string {
	return s.encode(src, salt)
}

func (s *Source) encode(src int64, salt [2]byte) string {
	buf1 := [10]byte{}
	buf2 := [8]byte{}
	copy(buf1[8:10], salt[:])

	binary.LittleEndian.PutUint64(buf2[:], uint64(src))

	iv := [aes.BlockSize]byte{buf1[8], buf1[9]}
	t := buf1[9]&0x07 + 1
	for i := byte(0); i < t; i++ {
		s.block.Encrypt(iv[:], iv[:])
	}

	offset := iv[9] & 0x70 >> 4
	for i := byte(0); i < 8; i++ {
		if i+offset < 8 {
			buf1[i] = iv[i] ^ buf2[i+offset]
		} else {
			buf1[i] = iv[i] ^ buf2[i+offset-8]
		}
	}

	return base32.StdEncoding.EncodeToString(buf1[:])
}

func (s *Source) Decode(src string) (int64, error) {
	buf1, err := base32.StdEncoding.DecodeString(src)
	buf2 := [8]byte{}
	if err != nil {
		return 0, err
	}

	if len(buf1) != 10 {
		return 0, errors.New("invalid src")
	}

	iv := [aes.BlockSize]byte{buf1[8], buf1[9]}
	t := buf1[9]&0x07 + 1
	for i := byte(0); i < t; i++ {
		s.block.Encrypt(iv[:], iv[:])
	}

	offset := iv[9] & 0x70 >> 4
	for i := byte(0); i < 8; i++ {
		if i+offset < 8 {
			buf2[i+offset] = iv[i] ^ buf1[i]
		} else {
			buf2[i+offset-8] = iv[i] ^ buf1[i]
		}
	}

	return int64(binary.LittleEndian.Uint64(buf2[:])), nil
}
