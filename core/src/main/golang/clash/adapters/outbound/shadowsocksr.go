package outbound

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/shadowsocksr/encryption"
	C "github.com/Dreamacro/clash/constant"
)

type ShadowSocksR struct {
	*Base
	server string
	cipher encryption.Cipher

	host string
	port uint16

	protocol      string
	protocolParam string
	protocolData  interface{}
	obfs          string
	obfsParam     string
	obfsData      interface{}
}

type ShadowSocksROption struct {
	Name          string `proxy:"name"`
	Server        string `proxy:"server"`
	Port          int    `proxy:"port"`
	Password      string `proxy:"password"`
	Cipher        string `proxy:"cipher"`
	Protocol      string `proxy:"protocol"`
	ProtocolParam string `proxy:"protocol-param"`
	Obfs          string `proxy:"obfs"`
	ObfsParam     string `proxy:"obfs-param"`

	// TODO: Add UDP support
	// UDP bool `proxy:"udp,omitempty"`
}

func (ssr *ShadowSocksR) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := dialer.DialContext(ctx, "tcp", ssr.server)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", ssr.server, err)
	}
	tcpKeepAlive(c)

	// c = shadowsocksr.NewConnLogger(c, "before_sending")

	if c, err = ssr.cipher.StreamConn(c); err != nil {
		return nil, fmt.Errorf("%s connect error: %w", ssr.server, err)
	}

	// ssconn := SSRUtils.NewSSTCPConn(c, cipher)
	// if ssconn.Conn == nil || ssconn.RemoteAddr() == nil {
	// 	return nil, fmt.Errorf("%s connect error: cannot establish connection", ssr.server)
	// }

	// ssconn.IObfs = SSRObfs.NewObfs(ssr.obfs)
	// obfsServerInfo := &SSRServer.ServerInfoForObfs{
	// 	Host:   ssr.host,
	// 	Port:   ssr.port,
	// 	TcpMss: 1460,
	// 	Param:  ssr.obfsParam,
	// }
	// ssconn.IObfs.SetServerInfo(obfsServerInfo)
	// ssconn.IObfs.SetData(ssconn.IObfs.GetData())

	// ssconn.IProtocol = SSRProtocol.NewProtocol(ssr.protocol)
	// protocolServerInfo := &SSRServer.ServerInfoForObfs{
	// 	Host:   ssr.host,
	// 	Port:   ssr.port,
	// 	TcpMss: 1460,
	// 	Param:  ssr.protocolParam,
	// }
	// ssconn.IProtocol.SetServerInfo(protocolServerInfo)
	// ssconn.IProtocol.SetData(ssconn.IProtocol.GetData())

	// c = shadowsocksr.NewConnLogger(c, "before_encryption")

	addr := serializesSocksAddr(metadata)
	if _, err := c.Write(addr); err != nil {
		return nil, fmt.Errorf("%s connect error: %w", ssr.server, err)
	}

	return newConn(c, ssr), nil
}

func (ssr *ShadowSocksR) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type": ssr.Type().String(),
	})
}

func NewShadowSocksR(option ShadowSocksROption) (*ShadowSocksR, error) {
	server := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	ciph, err := encryption.PickCipher(option.Cipher, nil, option.Password)
	if err != nil {
		return nil, fmt.Errorf("ssr %s initialize error: %w", server, err)
	}

	return &ShadowSocksR{
		Base: &Base{
			name: option.Name,
			tp:   C.ShadowsocksR,
			udp:  false,
		},

		server: server,
		cipher: ciph,

		host: option.Server,
		port: uint16(option.Port),

		obfs:          option.Obfs,
		obfsParam:     option.ObfsParam,
		protocol:      option.Protocol,
		protocolParam: option.ProtocolParam,
	}, nil
}
