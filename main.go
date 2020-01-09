package main

import (
	"encoding/binary"
	"io/ioutil"
	"math/bits"
)

const BlockSize = 64

const (
	chunk = 64
	init0 = 0x67452301
	init1 = 0xEFCDAB89
	init2 = 0x98BADCFE
	init3 = 0x10325476
	init4 = 0xC3D2E1F0
)
const (
	_K0 = 0x5A827999
	_K1 = 0x6ED9EBA1
	_K2 = 0x8F1BBCDC
	_K3 = 0xCA62C1D6
)

type digest struct {
	h   [5]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

func main() {
	Text, e := ioutil.ReadFile("Text")
	if e != nil {
		println("file err")
	}
	sha := NewHash()
	blockGeneric(sha, GenOriginData(Text))
	hashcode := make([]byte, 0)
	for i := 0; i < 5; i++ {
		code := make([]byte, 4)
		binary.BigEndian.PutUint32(code, sha.h[i])
		hashcode = append(hashcode, code...)
	}
	e = ioutil.WriteFile("hash", hashcode, 0644)
}

func NewHash() *digest {
	d := new(digest)
	d.Reset()
	return d
}
func (d *digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.nx = 0
	d.len = 0
}
func blockGeneric(dig *digest, p []byte) {
	var w [16]uint32

	h0, h1, h2, h3, h4 := dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4]
	for len(p) >= chunk {
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}

		a, b, c, d, e := h0, h1, h2, h3, h4

		i := 0
		for ; i < 16; i++ {
			f := b&c | (^b)&d
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K0
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}
		for ; i < 20; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)

			f := b&c | (^b)&d
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K0
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}
		for ; i < 40; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := b ^ c ^ d
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K1
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}
		for ; i < 60; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := ((b | c) & d) | (b & c)
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K2
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}
		for ; i < 80; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := b ^ c ^ d
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K3
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e

		p = p[chunk:]
	}

	dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4] = h0, h1, h2, h3, h4
}

func GenOriginData(Text []byte) []byte {
	OriginWords := make([]byte, 0)
	length := len(Text)
	LengthWords := make([]byte, 8)
	binary.BigEndian.PutUint64(LengthWords, uint64(length))
	ZeroWords := make([]byte, BlockSize-((length+8)%BlockSize))
	OriginWords = append(OriginWords, Text...)
	OriginWords = append(OriginWords, ZeroWords...)
	OriginWords = append(OriginWords, LengthWords...)
	return OriginWords
}
