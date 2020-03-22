package protocol

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"hash/adler32"
	"hash/crc32"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/Dreamacro/clash/component/shadowsocksr"
)

type AuthSHA1v4 struct {
	net.Conn
	authenticated bool
	clientInfo    *ClientInfo

	iv  []byte
	key []byte
}

type ClientInfo struct {
	ClientID []byte
	ConnID   uint32
	Mux      sync.Mutex
}

func NewAuthSHA1v4Protocol(c net.Conn, param string) (net.Conn, error) {
	return &AuthSHA1v4{
		Conn:          c,
		authenticated: false,
	}, nil
}

func (c *AuthSHA1v4) Read(b []byte) (int, error) {
	return 0, nil
}

func (c *AuthSHA1v4) Write(b []byte) (int, error) {
	dataLength := len(b)
	offset := 0

	var outData []byte

	if !c.authenticated && dataLength > 0 {
		authLength := dataLength
		if headSize := shadowsocksr.GetPacketTCPHeaderSize(b, 30); headSize <= dataLength {
			authLength = headSize
		}

		packedData := c.packWithAuth(b[:authLength])
		c.authenticated = true
		outData = append(outData, packedData...)
		dataLength -= authLength
		offset += authLength
	}

	const blockSize = 4096
	for dataLength > blockSize {
		packedData := c.pack(b[offset : offset+blockSize])
		outData = append(outData, packedData...)
		dataLength -= blockSize
		offset += blockSize
	}

	if dataLength > 0 {
		packedData := c.pack(b[offset:])
		outData = append(outData, packedData...)
	}

	return c.Conn.Write(outData)
}

func (c *AuthSHA1v4) packWithAuth(b []byte) []byte {
	dataLength := len(b)
	randLength := c.getRandomDataLength(b)
	ObfsHMACSHA1Len := 10

	dataOffset := randLength + 4 + 2
	outLength := dataOffset + dataLength + 12 + ObfsHMACSHA1Len
	outData := make([]byte, outLength)

	c.clientInfo.Mux.Lock()
	c.clientInfo.ConnID++
	if c.clientInfo.ConnID > 0xFF000000 {
		c.clientInfo.ClientID = nil
	}
	if len(c.clientInfo.ClientID) == 0 {
		c.clientInfo.ClientID = make([]byte, 8)
		rand.Read(c.clientInfo.ClientID)
		c.clientInfo.ConnID = rand.Uint32() & 0xFFFFF
	}
	var clientID []byte
	copy(clientID, c.clientInfo.ClientID)
	connID := c.clientInfo.ConnID
	c.clientInfo.Mux.Unlock()

	// 0-1, out length
	binary.BigEndian.PutUint16(outData[0:], uint16(outLength&0xFFFF))

	// 2~6, crc of out length+salt+key
	salt := []byte("auth_sha1_v4")
	crcData := make([]byte, len(salt)+len(c.key)+2)
	copy(crcData[0:2], outData[0:2])
	copy(crcData[2:], salt)
	copy(crcData[2+len(salt):], c.key)
	crc32 := crc32.ChecksumIEEE(crcData)
	binary.LittleEndian.PutUint32(outData[2:], crc32)

	// 6~rand length+6, rand numbers
	rand.Read(outData[6:dataOffset])

	// 6, rand length
	if randLength < 128 {
		outData[6] = byte(randLength & 0xFF)
	} else {
		// 6, magic number 0xFF
		outData[6] = 0xFF
		// 7-8, rand length
		binary.BigEndian.PutUint16(outData[7:], uint16(randLength&0xFFFF))
	}

	// rand length+6~rand length+10, time stamp
	now := time.Now().Unix()
	binary.LittleEndian.PutUint32(outData[dataOffset:dataOffset+4], uint32(now))

	// rand length+10~rand length+14, client ID
	copy(outData[dataOffset+4:dataOffset+8], clientID[0:4])

	// rand length+14~rand length+18, connection ID
	binary.LittleEndian.PutUint32(outData[dataOffset+8:dataOffset+12], connID)

	// rand length+18~rand length+18+data length, data
	copy(outData[dataOffset+12:], b)

	key := make([]byte, len(c.iv)+len(c.key))
	copy(key, c.iv)
	copy(key[len(c.iv):], c.key)
	hmacSHA1 := hmac.New(sha1.New, key)
	hmacSHA1.Write(outData[:outLength-ObfsHMACSHA1Len])
	h := hmacSHA1.Sum(nil)[:10]

	// out length-10~out length/rand length+18+data length~end, hmac
	copy(outData[outLength-ObfsHMACSHA1Len:], h[0:ObfsHMACSHA1Len])

	return outData
}

func (c *AuthSHA1v4) pack(b []byte) []byte {
	dataLength := len(b)
	randLength := c.getRandomDataLength(b)

	outLength := randLength + dataLength + 8
	outData := make([]byte, outLength)

	// 0~1, out length
	binary.BigEndian.PutUint16(outData[0:2], uint16(outLength&0xFFFF))

	// 2~3, crc of out length
	crc32 := crc32.ChecksumIEEE(b)
	binary.LittleEndian.PutUint16(outData[2:4], uint16(crc32&0xFFFF))

	// 4~rand length+4, rand number
	rand.Read(outData[4 : 4+randLength])

	// 4, rand length
	if randLength < 128 {
		outData[4] = byte(randLength & 0xFF)
	} else {
		// 4, magic number 0xFF
		outData[4] = 0xFF
		// 5~6, rand length
		binary.BigEndian.PutUint16(outData[5:], uint16(randLength&0xFFFF))
	}

	// rand length+4~out length-4, data
	if dataLength > 0 {
		copy(outData[randLength+4:], b)
	}

	// out length-4~end, adler32 of full data
	adler := adler32.Checksum(outData[:outLength-4])
	binary.LittleEndian.PutUint32(outData[outLength-4:], adler)

	return outData
}

func (c *AuthSHA1v4) getRandomDataLength(b []byte) int {
	if len(b) <= 400 {
		return rand.Intn(1024) + 1
	} else if len(b) <= 1300 {
		return rand.Intn(128) + 1
	} else {
		return 1
	}
}
