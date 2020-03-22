package obfs

import (
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/component/shadowsocksr"
)

type ShadowSocksRHTTPSimpleObfs struct {
	net.Conn
	headerSent      bool
	tcpHeaderLength int
	ivLen           int

	Method       string
	RequestURI   []string
	Host         string
	Port         int
	UserAgent    string
	CustomHeader string
}

var (
	RequestURIs = [][]string{
		[]string{"/", ""},
		[]string{"/login.php?redir=", ""},
		[]string{"/register.php?code=", ""},
		[]string{"/s?ie=utf-8&f=8&rsv_bp=1&rsv_idx=1&ch=&bar=&wd=", "&rn="},
		[]string{"/post.php?id=", "&goto=view.php"},
	}
	UserAgents = []string{
		"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/44.0",
		"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/27.0.1453.93 Chrome/27.0.1453.93 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0",
		"Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)",
		"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
		"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)",
		"Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Linux; Android 4.4; Nexus 5 Build/BuildID) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
	}
)

func NewShadowSocksRHTTPSimpleObfs(c net.Conn, param string) net.Conn {
	host := "bing.com"
	port := 80
	customHeader := ""

	if len(param) > 0 {
		paramParts := strings.Split(param, "#")
		domains := strings.Split(paramParts[0], ",")
		domain := domains[rand.Intn(len(domains))]

		domainParts := strings.Split(domain, ":")
		host = strings.TrimSpace(domainParts[0])
		if len(domainParts) > 1 {
			port, _ = strconv.Atoi(domainParts[1])
		}

		if len(paramParts) > 1 {
			customHeader = strings.Replace(paramParts[1], "\\n", "\r\n", -1)
		}
	}

	return &ShadowSocksRHTTPSimpleObfs{
		Conn:       c,
		headerSent: false,

		Method:       "GET",
		RequestURI:   RequestURIs[rand.Intn(len(RequestURIs))],
		Host:         host,
		Port:         port,
		UserAgent:    UserAgents[rand.Intn(len(UserAgents))],
		CustomHeader: customHeader,
	}
}

func (c *ShadowSocksRHTTPSimpleObfs) SetTCPHeaderLength(b []byte, defaultLength int) {
	c.tcpHeaderLength = shadowsocksr.GetPacketTCPHeaderSize(b, defaultLength)
}

func (c *ShadowSocksRHTTPSimpleObfs) randomBoundary() string {
	b := make([]byte, 32)
	set := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	for i := 0; i < 32; i++ {
		b[i] = set[rand.Intn(len(set))]
	}
	return string(b)
}

func (c *ShadowSocksRHTTPSimpleObfs) Write(b []byte) (int, error) {
	if c.headerSent {
		return c.Conn.Write(b)
	}

	dataLength := len(b)
	var dataInHeader []byte
	if headSize := c.ivLen + c.tcpHeaderLength; dataLength-headSize > 64 {
		dataInHeader = make([]byte, headSize+rand.Intn(64))
	} else {
		dataInHeader = make([]byte, dataLength)
	}
	copy(dataInHeader, b[0:len(dataInHeader)])

	httpBuf := fmt.Sprintf("%s %s%s%s HTTP/1.1\r\nHost: %s:%d\r\n",
		c.Method,
		c.RequestURI[0],
		url.QueryEscape(string(dataInHeader)),
		c.RequestURI[1],
		c.Host,
		c.Port)

	if len(c.CustomHeader) > 0 {
		httpBuf = httpBuf + c.CustomHeader + "\r\n\r\n"
	} else {
		var contentType string
		if c.Method == "GET" {
			contentType = "Content-Type: multipart/form-data; boundary=" + c.randomBoundary() + "\r\n"
		}
		httpBuf = httpBuf +
			"User-Agent: " + c.UserAgent + "\r\n" +
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
			"Accept-Language: en-US,en;q=0.8\r\n" +
			"Accept-Encoding: gzip, deflate\r\n" +
			contentType +
			"DNT: 1\r\n" +
			"Connection: keep-alive\r\n" +
			"\r\n"
	}

	var dataToWrite []byte
	if len(dataInHeader) < dataLength {
		dataToWrite = make([]byte, len(httpBuf)+(dataLength-len(dataInHeader)))
		copy(dataToWrite, []byte(httpBuf))
		copy(dataToWrite[len(httpBuf):], b[len(dataInHeader):])
	} else {
		dataToWrite = []byte(httpBuf)
	}

	c.headerSent = true
	return c.Conn.Write(dataToWrite)
}
