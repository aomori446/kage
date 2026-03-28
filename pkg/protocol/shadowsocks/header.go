package shadowsocks

import (
	crand "crypto/rand"
	"encoding/binary"
	"kage/pkg/core"
	"math/rand/v2"
	"time"
)

func PackRequestHeader(targetAddr *core.Address, initialPayload []byte) ([]byte, []byte, error) {
	addr := targetAddr.Bytes()
	
	n := rand.IntN(899) + 1
	padding := make([]byte, n)
	_, err := crand.Read(padding)
	if err != nil {
		return nil, nil, err
	}
	paddingLen := make([]byte, 2)
	binary.BigEndian.PutUint16(paddingLen, uint16(len(padding)))
	
	vlHeader := make([]byte, 0, len(addr)+len(paddingLen)+len(padding)+len(initialPayload))
	vlHeader = append(vlHeader, addr...)
	vlHeader = append(vlHeader, paddingLen...)
	vlHeader = append(vlHeader, padding...)
	vlHeader = append(vlHeader, initialPayload...)
	
	flHeader := make([]byte, 0, 11)
	flHeader = append(flHeader, 0)
	flHeader = binary.BigEndian.AppendUint64(flHeader, uint64(time.Now().Unix()))
	flHeader = binary.BigEndian.AppendUint16(flHeader, uint16(len(vlHeader)))
	
	return flHeader, vlHeader, nil
}
