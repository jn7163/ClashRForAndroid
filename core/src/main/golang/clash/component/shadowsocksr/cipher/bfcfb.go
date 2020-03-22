package cipher

import (
	"github.com/Dreamacro/go-shadowsocks2/shadowstream"
	"golang.org/x/crypto/blowfish"
)

func BFCFB(key []byte) (shadowstream.Cipher, error) {
	blk, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &CFBStream{blk}, nil
}
