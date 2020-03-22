package cipher

import (
	"crypto/des"

	"github.com/Dreamacro/clash/component/shadowsocksr/encryption/stream/mode"
	"github.com/Dreamacro/go-shadowsocks2/shadowstream"
)

func DESCFB(key []byte) (shadowstream.Cipher, error) {
	blk, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &mode.CFBStream{blk}, nil
}
