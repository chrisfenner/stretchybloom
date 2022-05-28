package stretchyhash

import (
	"crypto"
	_ "crypto/sha256"
	"fmt"
	"testing"
)

func TestStretchyHashLengths(t *testing.T) {
	cases := []struct {
		stretch int
		hash    crypto.Hash
		len     int
	}{
		{
			stretch: 1,
			hash:    crypto.SHA256,
			len:     64,
		},
		{
			stretch: 2,
			hash:    crypto.SHA256,
			len:     128,
		},
		{
			stretch: 3,
			hash:    crypto.SHA256,
			len:     1024,
		},
		{
			stretch: 4,
			hash:    crypto.SHA256,
			len:     131072,
		},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%v-%v", c.stretch, c.hash), func(t *testing.T) {
			h, err := New(c.hash, c.stretch)
			if err != nil {
				t.Fatalf("could not construct hash: %v", err.Error())
			}
			if s := h.Size(); s != c.len {
				t.Errorf("incorrect size: got %v want %v", s, c.len)
			}
		})
	}
}
