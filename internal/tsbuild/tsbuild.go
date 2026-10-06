// Package tsbuild constructs small MPEG-TS fragments for tests and smoke
// checks. It is deliberately minimal and not intended for production use.
package tsbuild

import (
	"encoding/binary"
)

const (
	PacketSize = 188
	PIDNull    = 0x1FFF
)

// Options fixes the signalling that PAT/PMT carry.
type Options struct {
	ProgramNumber int
	PMTPID        int
	PCRPID        int
	Media         []MediaStream
	Version       byte
}

// MediaStream is one PMT elementary stream entry.
type MediaStream struct {
	StreamType byte
	PID        int
}

// Builder accumulates packets while maintaining per-PID continuity counters.
type Builder struct {
	Opt Options
	out []byte
	cc  map[int]int
}

// New returns a builder with conventional single-program signalling.
func New() *Builder {
	return &Builder{
		Opt: Options{
			ProgramNumber: 1,
			PMTPID:        0x1000,
			PCRPID:        0x0100,
			Media: []MediaStream{
				{StreamType: 0x1B, PID: 0x0101},
				{StreamType: 0x0F, PID: 0x0102},
			},
			Version: 0,
		},
		cc: map[int]int{},
	}
}

// PacketMutator alters a packet before it is emitted (error injection).
type PacketMutator func(buf []byte)

// crc32MPEG mirrors the checker-side implementation.
func crc32MPEG(b []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, v := range b {
		crc ^= uint32(v) << 24
		for j := 0; j < 8; j++ {
			if crc&0x80000000 != 0 {
				crc = crc<<1 ^ 0x04C11DB7
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func finishSection(body []byte) []byte {
	crc := crc32MPEG(body)
	return append(body, byte(crc>>24), byte(crc>>16), byte(crc>>8), byte(crc))
}

// PATSection builds the current PAT section (table_id 0x00).
func (b *Builder) PATSection() []byte {
	body := []byte{
		0x00, 0, 0, // table_id + section_length placeholder
		0x00, 0x01, // transport_stream_id
		0xC0 | (b.Opt.Version << 1) | 0x01, 0x00, 0x00,
		byte(b.Opt.ProgramNumber >> 8), byte(b.Opt.ProgramNumber),
		0xE0 | byte(b.Opt.PMTPID>>8), byte(b.Opt.PMTPID),
	}
	binary.BigEndian.PutUint16(body[1:], 0xB000|uint16(len(body)+4-3))
	return finishSection(body)
}

// MultiPATSection builds a PAT advertising several programs.
func (b *Builder) MultiPATSection(pmtPIDs map[int]int) []byte {
	body := []byte{
		0x00, 0, 0,
		0x00, 0x01,
		0xC0 | (b.Opt.Version << 1) | 0x01, 0x00, 0x00,
	}
	for prog, pid := range pmtPIDs {
		body = append(body, byte(prog>>8), byte(prog), 0xE0|byte(pid>>8), byte(pid))
	}
	binary.BigEndian.PutUint16(body[1:], 0xB000|uint16(len(body)+4-3))
	return finishSection(body)
}

// PMTSection builds the current PMT section (table_id 0x02).
func (b *Builder) PMTSection() []byte {
	body := []byte{
		0x02, 0, 0,
		byte(b.Opt.ProgramNumber >> 8), byte(b.Opt.ProgramNumber),
		0xC0 | (b.Opt.Version << 1) | 0x01, 0x00, 0x00,
		0xE0 | byte(b.Opt.PCRPID>>8), byte(b.Opt.PCRPID),
		0xF0, 0x00, // program_info_length 0
	}
	for _, m := range b.Opt.Media {
		body = append(body, m.StreamType, 0xE0|byte(m.PID>>8), byte(m.PID), 0xF0, 0x00)
	}
	binary.BigEndian.PutUint16(body[1:], 0xB000|uint16(len(body)+4-3))
	return finishSection(body)
}

// nextCC returns the CC for a payload-bearing packet: last emitted + 1 mod 16.
func (b *Builder) nextCC(pid int) int {
	c, ok := b.cc[pid]
	if !ok {
		c = -1
	}
	c = (c + 1) & 0x0F
	b.cc[pid] = c
	return c
}

// lastCC returns the CC carried by the pid's most recent packet (0 initially).
func (b *Builder) lastCC(pid int) int { return b.cc[pid] }

func (b *Builder) header(pid int, pusi bool, afc byte, cc int) []byte {
	h := []byte{0x47, 0x00, 0, byte(afc) | byte(cc)}
	if pusi {
		h[1] |= 0x40
	}
	h[1] |= byte((pid >> 8) & 0x1F)
	h[2] = byte(pid)
	return h
}

// AddPAT/AddPMT emit a single-packet complete section.
func (b *Builder) AddPAT() *Builder { return b.AddPATWith(b.PATSection()) }

func (b *Builder) AddPATWith(section []byte) *Builder {
	pkt := make([]byte, PacketSize)
	h := b.header(0x0000, true, 0x10, b.nextCC(0x0000))
	copy(pkt, h)
	pkt[4] = 0x00 // pointer_field
	copy(pkt[5:], section)
	for i := 5 + len(section); i < PacketSize; i++ {
		pkt[i] = 0xFF
	}
	b.out = append(b.out, pkt...)
	return b
}

func (b *Builder) AddPMT() *Builder { return b.AddPMTWith(b.PMTSection()) }

func (b *Builder) AddPMTWith(section []byte) *Builder {
	pkt := make([]byte, PacketSize)
	h := b.header(b.Opt.PMTPID, true, 0x10, b.nextCC(b.Opt.PMTPID))
	copy(pkt, h)
	pkt[4] = 0x00
	copy(pkt[5:], section)
	for i := 5 + len(section); i < PacketSize; i++ {
		pkt[i] = 0xFF
	}
	b.out = append(b.out, pkt...)
	return b
}

// AddPayload emits a payload-only packet filled with a deterministic pattern.
func (b *Builder) AddPayload(pid int) *Builder {
	pkt := make([]byte, PacketSize)
	h := b.header(pid, false, 0x10, b.nextCC(pid))
	copy(pkt, h)
	for i := 4; i < PacketSize; i++ {
		pkt[i] = byte(i*31 + pid)
	}
	b.out = append(b.out, pkt...)
	return b
}

// AddPCR emits a packet carrying adaptation (PCR) plus payload.
// pcr27 is in 27 MHz units; flags other than PCR are left clear.
func (b *Builder) AddPCR(pid int, pcr27 int64) *Builder {
	pkt := make([]byte, PacketSize)
	h := b.header(pid, false, 0x30, b.nextCC(pid))
	copy(pkt, h)
	pkt[4] = 7 // adaptation_field_length
	pkt[5] = 0x10
	base := pcr27 / 300
	ext := pcr27 % 300
	pkt[6] = byte(base >> 25)
	pkt[7] = byte(base >> 17)
	pkt[8] = byte(base >> 9)
	pkt[9] = byte(base >> 1)
	pkt[10] = byte(base<<7) | 0x7E | byte(ext>>8&0x01)
	pkt[11] = byte(ext)
	for i := 12; i < PacketSize; i++ {
		pkt[i] = byte(i*17 + pid)
	}
	b.out = append(b.out, pkt...)
	return b
}

// AddAdaptationOnly emits an adaptation-only packet whose CC must stay equal
// to the previous CC for the PID.
func (b *Builder) AddAdaptationOnly(pid int) *Builder {
	pkt := make([]byte, PacketSize)
	cc := b.lastCC(pid) // adaptation-only repeats the previous CC
	h := b.header(pid, false, 0x20, cc)
	copy(pkt, h)
	pkt[4] = 1
	pkt[5] = 0x00
	for i := 6; i < PacketSize; i++ {
		pkt[i] = 0xFF
	}
	b.out = append(b.out, pkt...)
	return b
}

// AddRaw emits a fully custom packet without touching continuity state.
func (b *Builder) AddRaw(pkt []byte) *Builder {
	if len(pkt) != PacketSize {
		panic("raw packet must be 188 bytes")
	}
	b.out = append(b.out, pkt...)
	return b
}

// AddNull emits a null-stuffing packet (PID 0x1FFF).
func (b *Builder) AddNull() *Builder {
	pkt := make([]byte, PacketSize)
	for i := range pkt {
		pkt[i] = 0xFF
	}
	pkt[0] = 0x47
	pkt[1] = 0x1F
	pkt[2] = 0xFF
	pkt[3] = 0x10 // payload-only; continuity counter irrelevant for null PID
	b.out = append(b.out, pkt...)
	return b
}

// MutateLast applies fn to the most recently emitted packet.
func (b *Builder) MutateLast(fn PacketMutator) *Builder {
	fn(b.out[len(b.out)-PacketSize:])
	return b
}

// Bytes returns the assembled fragment.
func (b *Builder) Bytes() []byte {
	out := make([]byte, len(b.out))
	copy(out, b.out)
	return out
}
