package z

import (
	"encoding/json"
	"log"
)

type Bloom2 struct {
	bitset []byte
}

func NewBloomFilter2(params ...float64) *Bloom2 {
	keys := make([][]byte, 0)
	filter := []byte(NewFilter(nil, keys, 10))

	return &Bloom2{
		bitset: filter,
	}
}

func (bl *Bloom2) Add(hashes ...uint32) {
	// func appendFilter(buf []byte, keys [][]byte, bitsPerKey int) []byte {
	bitsPerKey := 10
	buf := bl.bitset

	if bitsPerKey < 0 {
		bitsPerKey = 0
	}
	// 0.69 is approximately ln(2).
	k := uint32(float64(bitsPerKey) * 0.69)
	if k < 1 {
		k = 1
	}
	if k > 30 {
		k = 30
	}

	nBits := len(hashes) * int(bitsPerKey)
	// For small len(keys), we can see a very high false positive rate. Fix it
	// by enforcing a minimum bloom filter length.
	if nBits < 64 {
		nBits = 64
	}
	nBytes := (nBits + 7) / 8
	nBits = nBytes * 8
	buf, filter := extend(buf, nBytes+1)

	for _, h := range hashes {
		delta := h>>17 | h<<15
		for j := uint32(0); j < k; j++ {
			bitPos := h % uint32(nBits)
			filter[bitPos/8] |= 1 << (bitPos % 8)
			h += delta
		}
	}
	filter[nBytes] = uint8(k)

	bl.bitset = buf
}

func (bl *Bloom2) AddIfNotHas(hash uint32) bool {
	if bl.Has(hash) {
		return false
	}
	bl.Add(hash)
	return true
}

// Clear resets the Bloom filter.
func (bl *Bloom2) Clear() {
	bl = NewBloomFilter2()
}

func (bl Bloom2) Has(h uint32) bool {
	f := bl.bitset

	if len(f) < 2 {
		return false
	}
	k := f[len(f)-1]
	if k > 30 {
		// This is reserved for potentially new encodings for short Bloom filters.
		// Consider it a match.
		return true
	}
	nBits := uint32(8 * (len(f) - 1))
	delta := h>>17 | h<<15
	for j := uint8(0); j < k; j++ {
		bitPos := h % nBits
		if f[bitPos/8]&(1<<(bitPos%8)) == 0 {
			return false
		}
		h += delta
	}
	return true
}

func (bl Bloom2) JSONMarshal() []byte {
	data, err := json.Marshal(bl.bitset)
	if err != nil {
		log.Fatal("json.Marshal failed: ", err)
	}
	return data
}

// returns bloom32 / bloom64 object.
func JSONUnmarshal2(dbData []byte) (*Bloom2, error) {
	var bl Bloom2
	err := json.Unmarshal(dbData, &bl.bitset)
	return &bl, err
}
