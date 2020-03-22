package cipher

import (
	"crypto/cipher"

	"github.com/Dreamacro/go-shadowsocks2/shadowstream"
	"gitlab.com/yawning/chacha20.git"
)

type chacha20Key []byte

func (k chacha20Key) IVSize() int {
	return 8
}

func (k chacha20Key) Encrypter(iv []byte) cipher.Stream {
	cipher, err := chacha20.New(k, iv)
	if err != nil {
		panic(err)
	}
	return cipher
}

func (k chacha20Key) Decrypter(iv []byte) cipher.Stream {
	return k.Encrypter(iv)
}

func Chacha20(key []byte) (shadowstream.Cipher, error) {
	if len(key) != chacha20.KeySize {
		return nil, shadowstream.KeySizeError(chacha20.KeySize)
	}
	return chacha20Key(key), nil
}
