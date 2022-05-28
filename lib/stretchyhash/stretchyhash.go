package stretchyhash

import (
	"crypto"
	"errors"
	"fmt"
	"hash"
)

const (
	stretchLimit int = 4
)

var (
	ErrTooMuchStretch error = errors.New("unsupported stretch length")
)

type stretchyHash struct {
	// h is the underlying cryptographic hash algorithm
	h hash.Hash
	// stretch is the stretch-factor for the hash
	stretch int
}

// New returns a new StretchyHash based on the given cryptographic hash.
// The resulting hash's output length will be 2^(2^stretch - stretch) bigger,
// with a proportionately increasing bias toward 0 bits.
func New(h crypto.Hash, stretch int) (hash.Hash, error) {
	if stretch < 1 {
		return nil, fmt.Errorf("%w: %d (min: 1)", ErrTooMuchStretch, stretch)
	}
	if stretch > stretchLimit {
		return nil, fmt.Errorf("%w: %d (max: %d)", ErrTooMuchStretch, stretch, stretchLimit)
	}
	return &stretchyHash{
		h:       h.New(),
		stretch: stretch,
	}, nil
}

func (sh *stretchyHash) Write(b []byte) (n int, err error) {
	return sh.h.Write(b)
}

// stretch turns every 2^stretch bits into 2^2^stretch bits with only a single 1
func stretch(data []byte, stretch int) []byte {
	// For simplicity, convert to and from bit arrays.
	// TODO: Optimize this.
	bits := toBits(data)
	chunkWidth := 1 << stretch
	resultBits := make([]bool, len(bits)*(1<<(chunkWidth-stretch)))
	for i := 0; i < len(resultBits); i += chunkWidth {
		var chunk int
		for j := 0; j < chunkWidth; j++ {
			if bits[8*i+j] {
				chunk += (1 << j)
			}
		}
		resultBits[i*chunkWidth+chunk] = true
	}
	return fromBits(resultBits)
}

func toBits(bytes []byte) []bool {
	result := make([]bool, len(bytes)*8)
	for i, b := range bytes {
		for j := 0; j < 8; j++ {
			result[8*i+j] = (b & (1 << j)) != 0
		}
	}
	return result
}

func fromBits(bits []bool) []byte {
	result := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b {
			result[i/8] += (1 << (i % 8))
		}
	}
	return result
}

func (sh *stretchyHash) Sum(b []byte) []byte {
	unstretched := sh.h.Sum(nil)
	return append(b, stretch(unstretched, sh.stretch)...)
}

func (sh *stretchyHash) Reset() {
	sh.h.Reset()
}

func (sh *stretchyHash) Size() int {
	return sh.h.Size() * (1 << ((1 << sh.stretch) - sh.stretch))
}

func (sh *stretchyHash) BlockSize() int {
	return sh.h.BlockSize()
}
