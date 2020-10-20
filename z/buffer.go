/*
 * Copyright 2020 Dgraph Labs, Inc. and Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package z

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"sort"

	"github.com/pkg/errors"
)

// Buffer is equivalent of bytes.Buffer without the ability to read. It is NOT thread-safe.
//
// In UseCalloc mode, z.Calloc is used to allocate memory, which depending upon how the code is
// compiled could use jemalloc for allocations.
//
// In UseMmap mode, Buffer  uses file mmap to allocate memory. This allows us to store big data
// structures without using physical memory.
//
// MaxSize can be set to limit the memory usage.
type Buffer struct {
	buf           []byte
	offset        int64
	curSz         int64
	maxSz         int64
	fd            *os.File
	bufType       BufferType
	autoMmapAfter int64
}

type BufferType int

func (t BufferType) String() string {
	switch t {
	case UseCalloc:
		return "UseCalloc"
	case UseMmap:
		return "UseMmap"
	}
	return "invalid"
}

const (
	UseCalloc BufferType = iota
	UseMmap
	UseInvalid
)

// smallBufferSize is an initial allocation minimal capacity.
const smallBufferSize = 64

// Newbuffer is a helper utility, which creates a virtually unlimited Buffer in UseCalloc mode.
func NewBuffer(sz int64) *Buffer {
	buf, err := NewBufferWith(sz, 256<<30, UseCalloc)
	if err != nil {
		log.Fatalf("while creating buffer: %v", err)
	}
	return buf
}

func (b *Buffer) doMmap() error {
	curBuf := b.buf
	fd, err := ioutil.TempFile("", "buffer")
	if err != nil {
		return err
	}
	if err := fd.Truncate(int64(b.curSz)); err != nil {
		return errors.Wrapf(err, "while truncating %s to size: %d", fd.Name(), b.curSz)
	}

	buf, err := Mmap(fd, true, b.maxSz) // Mmap up to max size.
	if err != nil {
		return errors.Wrapf(err, "while mmapping %s with size: %d", fd.Name(), b.maxSz)
	}
	if len(curBuf) > 0 {
		assert(b.offset == int64(copy(buf, curBuf[:b.offset])))
		Free(curBuf)
	}
	b.buf = buf
	b.bufType = UseMmap
	b.fd = fd
	return nil
}

// NewBufferWith would allocate a buffer of size sz upfront, with the total size of the buffer not
// exceeding maxSz. Both sz and maxSz can be set to zero, in which case reasonable defaults would be
// used. Buffer can't be used without initialization via NewBuffer.
func NewBufferWith(sz, maxSz int64, bufType BufferType) (*Buffer, error) {
	if sz == 0 {
		sz = smallBufferSize
	}
	if maxSz == 0 {
		maxSz = math.MaxInt32
	}

	b := &Buffer{
		offset:  1,
		curSz:   sz,
		maxSz:   maxSz,
		bufType: UseCalloc, // by default.
	}

	switch bufType {
	case UseCalloc:
		b.buf = Calloc(sz)
	case UseMmap:
		if err := b.doMmap(); err != nil {
			return nil, err
		}
	default:
		log.Fatalf("Invalid bufType: %q\n", bufType)
	}

	b.buf[0] = 0x00
	return b, nil
}

func (b *Buffer) IsEmpty() bool {
	return b.offset == 1
}

// Len would return the number of bytes written to the buffer so far.
func (b *Buffer) Len() int64 {
	return b.offset
}

// Bytes would return all the written bytes as a slice.
func (b *Buffer) Bytes() []byte {
	return b.buf[1:b.offset]
}

func (b *Buffer) AutoMmapAfter(size int64) {
	b.autoMmapAfter = size
}

// Grow would grow the buffer to have at least n more bytes. In case the buffer is at capacity, it
// would reallocate twice the size of current capacity + n, to ensure n bytes can be written to the
// buffer without further allocation. In UseMmap mode, this might result in underlying file
// expansion.
func (b *Buffer) Grow(n int64) {
	// In this case, len and cap are the same.
	if b.buf == nil {
		panic("z.Buffer needs to be initialized before using")
	}
	if b.maxSz-b.offset < n {
		panic(fmt.Sprintf("Buffer max size exceeded: %d."+
			" Offset: %d. Grow: %d", b.maxSz, b.offset, n))
	}
	if b.curSz-b.offset > n {
		return
	}

	growBy := b.curSz + n
	if growBy > 1<<30 {
		growBy = 1 << 30
	}
	if n > growBy {
		// Always at least allocate n, even if it exceeds the 1GB limit above.
		growBy = n
	}
	b.curSz += growBy

	switch b.bufType {
	case UseCalloc:
		if b.autoMmapAfter > 0 && b.curSz > b.autoMmapAfter {
			// This would do copy as well.
			check(b.doMmap())

		} else {
			newBuf := Calloc(b.curSz)
			copy(newBuf, b.buf[:b.offset])
			Free(b.buf)
			b.buf = newBuf
		}
	case UseMmap:
		if err := b.fd.Truncate(b.curSz); err != nil {
			log.Fatalf("While trying to truncate file %s to size: %d error: %v\n",
				b.fd.Name(), b.curSz, err)
		}
	}
}

// Allocate is a way to get a slice of size n back from the buffer. This slice can be directly
// written to. Warning: Allocate is not thread-safe. The byte slice returned MUST be used before
// further calls to Buffer.
func (b *Buffer) Allocate(n int64) []byte {
	b.Grow(n)
	off := b.offset
	b.offset += n
	return b.buf[off:b.offset]
}

// AllocateOffset works the same way as allocate, but instead of returning a byte slice, it returns
// the offset of the allocation.
func (b *Buffer) AllocateOffset(n int64) int64 {
	b.Grow(n)
	b.offset += n
	return b.offset - n
}

func (b *Buffer) writeLen(sz int64) {
	buf := b.Allocate(4)
	binary.BigEndian.PutUint32(buf, uint32(sz))
}

// SliceAllocate would encode the size provided into the buffer, followed by a call to Allocate,
// hence returning the slice of size sz. This can be used to allocate a lot of small buffers into
// this big buffer.
// Note that SliceAllocate should NOT be mixed with normal calls to Write.
func (b *Buffer) SliceAllocate(sz int64) []byte {
	b.Grow(4 + sz)
	b.writeLen(sz)
	return b.Allocate(sz)
}

func (b *Buffer) WriteSlice(slice []byte) {
	dst := b.SliceAllocate(int64(len(slice)))
	copy(dst, slice)
}

func (b *Buffer) SliceIterate(f func(slice []byte) error) error {
	slice, next := []byte{}, int64(1)
	for next != 0 {
		slice, next = b.Slice(next)
		if err := f(slice); err != nil {
			return err
		}
	}
	return nil
}

type LessFunc func(a, b []byte) bool
type sortHelper struct {
	offsets []int64
	b       *Buffer
	tmp     *Buffer
	less    LessFunc
	small   []int64
}

func (s *sortHelper) sortSmall(start, end int64) {
	s.tmp.Reset()
	s.small = s.small[:0]
	next := start
	for next != 0 && next < end {
		s.small = append(s.small, next)
		_, next = s.b.Slice(next)
	}

	// We are sorting the slices pointed to by s.small offsets, but only moving the offsets around.
	sort.Slice(s.small, func(i, j int) bool {
		left, _ := s.b.Slice(s.small[i])
		right, _ := s.b.Slice(s.small[j])
		return s.less(left, right)
	})
	// Now we iterate over the s.small offsets and copy over the slices. The result is now in order.
	for _, off := range s.small {
		s.tmp.Write(rawSlice(s.b.buf[off:]))
	}
	assert(end-start == int64(copy(s.b.buf[start:end], s.tmp.Bytes())))
}

func assert(b bool) {
	if !b {
		log.Fatalf("%+v", errors.Errorf("Assertion failure"))
	}
}
func check(err error) {
	if err != nil {
		log.Fatalf("%+v", err)
	}
}
func check2(_ interface{}, err error) {
	check(err)
}

func (s *sortHelper) merge(left, right []byte, start, end int64) {
	if len(left) == 0 || len(right) == 0 {
		return
	}
	s.tmp.Reset()
	check2(s.tmp.Write(left))
	left = s.tmp.Bytes()

	var ls, rs []byte

	copyLeft := func() {
		assert(len(ls) == copy(s.b.buf[start:], ls))
		left = left[len(ls):]
		start += int64(len(ls))
	}
	copyRight := func() {
		assert(len(rs) == copy(s.b.buf[start:], rs))
		right = right[len(rs):]
		start += int64(len(rs))
	}

	for start < end {
		if len(left) == 0 {
			assert(len(right) == copy(s.b.buf[start:end], right))
			return
		}
		if len(right) == 0 {
			assert(len(left) == copy(s.b.buf[start:end], left))
			return
		}
		ls = rawSlice(left)
		rs = rawSlice(right)

		// We skip the first 4 bytes in the rawSlice, because that stores the length.
		if s.less(ls[4:], rs[4:]) {
			copyLeft()
		} else {
			copyRight()
		}
	}
}

func (s *sortHelper) sort(lo, hi int) []byte {
	assert(lo <= hi)

	mid := lo + (hi-lo)/2
	loff, hoff := s.offsets[lo], s.offsets[hi]
	if lo == mid {
		// No need to sort, just return the buffer.
		return s.b.buf[loff:hoff]
	}

	// lo, mid would sort from [offset[lo], offset[mid]) .
	left := s.sort(lo, mid)
	// Typically we'd use mid+1, but here mid represents an offset in the buffer. Each offset
	// contains a thousand entries. So, if we do mid+1, we'd skip over those entries.
	right := s.sort(mid, hi)

	s.merge(left, right, loff, hoff)
	return s.b.buf[loff:hoff]
}

// SortSlice is like SortSliceBetween but sorting over the entire buffer.
func (b *Buffer) SortSlice(less func(left, right []byte) bool) {
	b.SortSliceBetween(1, b.offset, less)
}
func (b *Buffer) SortSliceBetween(start, end int64, less LessFunc) {
	if start >= end {
		return
	}
	if start == 0 {
		panic("start can never be zero")
	}

	var offsets []int64
	next, count := start, 0
	for next != 0 && next < end {
		if count%1024 == 0 {
			offsets = append(offsets, next)
		}
		_, next = b.Slice(next)
		count++
	}
	assert(len(offsets) > 0)
	if offsets[len(offsets)-1] != end {
		offsets = append(offsets, end)
	}

	szTmp := int64(float64((end-start)/2) * 1.1)
	s := &sortHelper{
		offsets: offsets,
		b:       b,
		less:    less,
		small:   make([]int64, 0, 1024),
		tmp:     NewBuffer(szTmp),
	}
	defer s.tmp.Release()

	left := offsets[0]
	for _, off := range offsets[1:] {
		s.sortSmall(left, off)
		left = off
	}
	s.sort(0, len(offsets)-1)
}

func rawSlice(buf []byte) []byte {
	sz := binary.BigEndian.Uint32(buf)
	return buf[:4+int(sz)]
}

// Slice would return the slice written at offset.
func (b *Buffer) Slice(offset int64) ([]byte, int64) {
	if offset >= b.offset {
		return nil, 0
	}

	sz := binary.BigEndian.Uint32(b.buf[offset:])
	start := offset + 4
	next := start + int64(sz)
	res := b.buf[start:next]
	if next >= b.offset {
		next = 0
	}
	return res, next
}

// SliceOffsets is an expensive function. Use sparingly.
func (b *Buffer) SliceOffsets() []int64 {
	next := int64(1)
	var offsets []int64
	for next != 0 {
		offsets = append(offsets, next)
		_, next = b.Slice(next)
	}
	return offsets
}

func (b *Buffer) Data(offset int64) []byte {
	if offset > b.curSz {
		panic("offset beyond current size")
	}
	return b.buf[offset:b.curSz]
}

// Write would write p bytes to the buffer.
func (b *Buffer) Write(p []byte) (n int64, err error) {
	b.Grow(int64(len(p)))
	n = int64(copy(b.buf[b.offset:], p))
	b.offset += n
	return n, nil
}

// Reset would reset the buffer to be reused.
func (b *Buffer) Reset() {
	b.offset = 1
}

// Release would free up the memory allocated by the buffer. Once the usage of buffer is done, it is
// important to call Release, otherwise a memory leak can happen.
func (b *Buffer) Release() error {
	switch b.bufType {
	case UseCalloc:
		Free(b.buf)

	case UseMmap:
		fname := b.fd.Name()
		if err := Munmap(b.buf); err != nil {
			return errors.Wrapf(err, "while munmap file %s", fname)
		}
		if err := b.fd.Truncate(0); err != nil {
			return errors.Wrapf(err, "while truncating file %s", fname)
		}
		if err := b.fd.Close(); err != nil {
			return errors.Wrapf(err, "while closing file %s", fname)
		}
		if err := os.Remove(b.fd.Name()); err != nil {
			return errors.Wrapf(err, "while deleting file %s", fname)
		}
	}
	return nil
}
