package shadowsocks

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
)

// Padding generate random padding with size between (min,max) and max <= 65535 -2
func Padding(min, max uint16) ([]byte, error) {
	if max > 0xFFFF-2 {
		max = 0xFFFF - 2
	}
	
	if min > max {
		return nil, fmt.Errorf("min greater than max, min = %d, max = %d", min, max)
	}
	
	n := rand.UintN(uint(max))
	nn := uint16(n)
	
	if nn < min {
		nn = min
	}
	
	buf := make([]byte, 2+nn)
	binary.BigEndian.PutUint16(buf, nn)
	
	_, err := crand.Read(buf[2:])
	if err != nil {
		return nil, err
	}
	return buf, nil
}
