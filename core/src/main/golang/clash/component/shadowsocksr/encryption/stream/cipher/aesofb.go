package cipher

import (
	"crypto/aes"

	"github.com/Dreamacro/clash/component/shadowsocksr/encryption/stream/mode"
	"github.com/Dreamacro/go-shadowsocks2/shadowstream"
)

func AESOFB(key []byte) (shadowstream.Cipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &mode.OFBStream{blk}, nil
}
