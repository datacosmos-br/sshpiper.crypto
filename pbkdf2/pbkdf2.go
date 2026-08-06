// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pbkdf2 implements the key derivation function PBKDF2 as defined in
// RFC 8018 (PKCS #5 v2.1).
//
// This package is a wrapper for the PBKDF2 implementation in the
// [crypto/pbkdf2] package. It is [frozen] and is not accepting new features.
//
// [frozen]: https://go.dev/wiki/Frozen
package pbkdf2

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
)

// Key derives a key from the password, salt and iteration count, returning a
// []byte of length keylen that can be used as cryptographic key. The key is
// derived based on the method described as PBKDF2 with the HMAC variant using
// the supplied hash function.
func Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	if iter <= 0 || keyLen < 0 {
		panic("pbkdf2: invalid parameters")
	}
	blockLen := h().Size()
	if keyLen > (1<<32-1)*blockLen {
		panic("pbkdf2: derived key too long")
	}
	out := make([]byte, keyLen)
	remaining := out
	var count [4]byte
	for block := uint32(1); len(remaining) > 0; block++ {
		binary.BigEndian.PutUint32(count[:], block)
		x := hmac.New(h, password)
		x.Write(salt)
		x.Write(count[:])
		u := x.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			x = hmac.New(h, password)
			x.Write(u)
			u = x.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		n := len(remaining)
		if n > len(t) {
			n = len(t)
		}
		copy(out[len(out)-len(remaining):], t[:n])
		remaining = remaining[n:]
	}
	return out
}
