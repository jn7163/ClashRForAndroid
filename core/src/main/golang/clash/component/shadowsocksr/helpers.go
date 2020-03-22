package shadowsocksr

import (
	"encoding/hex"
	"net"

	"github.com/Dreamacro/clash/log"
)

func GetPacketTCPHeaderSize(b []byte, defaultLength int) int {
	if b == nil || len(b) < 2 {
		return defaultLength
	}

	switch b[0] & 0x07 {
	case 1:
		// IPv4 1+4+2
		return 7
	case 4:
		// IPv6 1+16+2
		return 19
	case 3:
		// domain name, variant length
		return 4 + int(b[1])
	}

	return defaultLength
}

func NewConnLogger(c net.Conn, name string) net.Conn {
	return &ConnLogger{Conn: c, name: name}
}

type ConnLogger struct {
	net.Conn
	name string
}

func (c *ConnLogger) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err == nil {
		log.Debugln("[%s] successfully read %d bytes: %s", c.name, n, hex.EncodeToString(b[:n]))
	} else {
		log.Debugln("[%s] failed to read because: %w", c.name, err)
	}
	return n, err
}

func (c *ConnLogger) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err == nil {
		log.Debugln("[%s] successfully write %d bytes: %s", c.name, n, hex.EncodeToString(b[:n]))
	} else {
		log.Debugln("[%s] failed to write because: %w", c.name, err)
	}
	return n, err
}
