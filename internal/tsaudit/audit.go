package tsaudit

import "sort"

// MaxBodyBytes is the largest accepted fragment: 8 MiB.
const MaxBodyBytes = 8 << 20

// pcrCycle is the 33-bit PCR base wraparound expressed in 27 MHz units
// (base ticks * 300 extension ticks).
const pcrCycle = int64(1) << 33 * 300

// PCRRef locates one PCR value in the fragment.
type PCRRef struct {
	Packet     int   `json:"packet"`
	Base       int64 `json:"base"`
	Extension  int   `json:"extension"`
	Value27MHz int64 `json:"value27mhz"`
}

// MediaPIDStats carries per-PID payload accounting.
type MediaPIDStats struct {
	PID          int   `json:"pid"`
	PacketCount  int   `json:"packetCount"`
	PayloadBytes int64 `json:"payloadBytes"`
}

// Report is the all-or-nothing success result.
type Report struct {
	ProgramNumber int             `json:"programNumber"`
	PMTPID        int             `json:"pmtPID"`
	PCRPID        int             `json:"pcrPID"`
	MediaPIDs     []int           `json:"mediaPIDs"`
	PacketCount   int             `json:"packetCount"`
	FirstPCR      *PCRRef         `json:"firstPCR"`
	LastPCR       *PCRRef         `json:"lastPCR"`
	Duration27MHz int64           `json:"duration27mhz"`
	DurationMs    float64         `json:"durationMs"`
	PayloadBytes  int64           `json:"payloadBytes"`
	Media         []MediaPIDStats `json:"media"`
}

type ccState struct {
	started bool
	cc      int
}

// Audit validates a raw MPEG-TS fragment. On success it returns a Report; on
// the first violated rule it returns an AuditError and no partial results.
func Audit(data []byte, maxPcrGapMs int) (*Report, *AuditError) {
	if maxPcrGapMs < 1 || maxPcrGapMs > 10000 {
		return nil, auditError(ErrInvalidMaxPcrGap, "maxPcrGapMs must be between 1 and 10000", -1, -1)
	}
	if len(data) == 0 {
		return nil, auditError(ErrEmptyBody, "request body is empty", -1, -1)
	}
	if len(data)%packetSize != 0 {
		return nil, auditError(ErrNotPacketAligned, "body length is not a multiple of 188 bytes", len(data)/packetSize, -1)
	}
	n := len(data) / packetSize
	pkts := make([]*Packet, n)

	// ---- Pass A: per-packet header rules + PAT collection ----------------
	var pats []*tableSection
	for i := 0; i < n; i++ {
		off := i * packetSize
		raw := data[off : off+packetSize : off+packetSize]
		p, err := parsePacket(raw, i)
		if err != nil {
			return nil, err
		}
		pkts[i] = p

		if p.HasAdaptation && len(p.Adaptation) > 0 && p.Adaptation[0]&afFlagDiscontinuity != 0 {
			return nil, auditError(ErrDiscontinuity, "adaptation field discontinuity indicator set", i, p.PID)
		}

		if p.PID == pidPAT {
			if !p.PUSI {
				return nil, auditError(ErrPATSectionSpansPacket, "PAT continuation packet: section is not contained in one packet", i, p.PID)
			}
			sec, err := parseTablePacket(raw, p, i, 0x00, ErrPATTableID, ErrPATSectionSpansPacket, ErrSectionTruncated)
			if err != nil {
				return nil, err
			}
			pats = append(pats, sec)
		}
	}

	if len(pats) == 0 {
		return nil, auditError(ErrPATNotFound, "no PAT found on PID 0x0000", 0, pidPAT)
	}
	pat := pats[0]
	for _, s := range pats[1:] {
		if s.version != pat.version || !bytesEqual(s.raw, pat.raw) {
			return nil, auditError(ErrPATVersionMismatch, "PAT sections must share one version and identical content", s.packet, pidPAT)
		}
	}
	if len(pat.programs) == 0 {
		return nil, auditError(ErrNoProgram, "PAT declares no program", pat.packet, pidPAT)
	}
	if len(pat.programs) > 1 {
		return nil, auditError(ErrMultiProgram, "PAT declares more than one program", pat.packet, pidPAT)
	}
	prog := pat.programs[0]
	if prog.pid == pidPAT || prog.pid == 0x1FFF {
		return nil, auditError(ErrSectionSyntax, "PAT uses reserved PMT PID", pat.packet, pidPAT)
	}

	// ---- Pass B: PMT collection on the PAT-signalled PID -----------------
	var pmts []*tableSection
	for i, p := range pkts {
		if p.PID != prog.pid {
			continue
		}
		if !p.PUSI {
			return nil, auditError(ErrPMTSectionSpansPacket, "PMT continuation packet: section is not contained in one packet", i, p.PID)
		}
		raw := data[i*packetSize : i*packetSize+packetSize]
		sec, err := parseTablePacket(raw, p, i, 0x02, ErrPMTTableID, ErrPMTSectionSpansPacket, ErrSectionTruncated)
		if err != nil {
			return nil, err
		}
		pmts = append(pmts, sec)
	}
	if len(pmts) == 0 {
		return nil, auditError(ErrPMTNotFound, "no PMT found on the PAT-signalled PID", 0, prog.pid)
	}
	pmt := pmts[0]
	for _, s := range pmts[1:] {
		if s.version != pmt.version || !bytesEqual(s.raw, pmt.raw) {
			return nil, auditError(ErrPMTVersionMismatch, "PMT sections must share one version and identical content", s.packet, prog.pid)
		}
	}
	if pmtProgramNumber(pmt) != prog.number {
		return nil, auditError(ErrSectionSyntax, "PMT program_number does not match PAT", pmt.packet, prog.pid)
	}
	if pmt.pcrPID == 0x1FFF {
		return nil, auditError(ErrNoPCR, "PMT declares no PCR PID (0x1FFF)", pmt.packet, prog.pid)
	}

	mediaSet := map[int]bool{}
	var mediaPIDs []int
	for _, pid := range pmt.mediaPIDs {
		if !mediaSet[pid] {
			mediaSet[pid] = true
			mediaPIDs = append(mediaPIDs, pid)
		}
	}
	sort.Ints(mediaPIDs)

	declared := map[int]bool{prog.pid: true, pmt.pcrPID: true}
	for _, pid := range mediaPIDs {
		declared[pid] = true
	}
	tracked := map[int]bool{pidPAT: true}
	for pid := range declared {
		tracked[pid] = true
	}

	// ---- Pass C: PID membership, continuity counters and PCR timeline ----
	cc := map[int]*ccState{}
	stats := map[int]*MediaPIDStats{}
	for _, pid := range mediaPIDs {
		stats[pid] = &MediaPIDStats{PID: pid}
	}

	var firstPCR, lastPCR *PCRRef
	var prevPCR, unwrappedPCR int64
	var pcrCount int
	var payloadTotal int64

	for i, p := range pkts {
		if p.PID == 0x1FFF { // null packets are stuffing and carry no semantics
			continue
		}
		if p.PID != pidPAT && !declared[p.PID] {
			return nil, auditError(ErrUnknownPID, "packet on PID not declared by PAT/PMT", i, p.PID)
		}

		if v, hasFlag, ok := p.pcr(); hasFlag {
			if !ok {
				return nil, auditError(ErrPCRNoBase, "PCR flag set but PCR field is truncated", i, p.PID)
			}
			if p.PID != pmt.pcrPID {
				return nil, auditError(ErrPCROnWrongPID, "PCR may only appear on the PMT-declared PCR PID", i, p.PID)
			}
			ref := &PCRRef{Packet: i, Base: v / 300, Extension: int(v % 300), Value27MHz: v}
			if pcrCount == 0 {
				firstPCR, lastPCR = ref, ref
				unwrappedPCR = v
			} else {
				d := v - prevPCR
				if d < -pcrCycle/2 { // genuine 33-bit base wraparound
					d += pcrCycle
				}
				if d < 0 {
					return nil, auditError(ErrPCRReversed, "PCR moved backwards after 33-bit unwrap", i, p.PID)
				}
				if d > int64(maxPcrGapMs)*27000 {
					return nil, auditError(ErrPCRGapExceeded, "PCR interval exceeds maxPcrGapMs", i, p.PID)
				}
				unwrappedPCR += d
				ref.Value27MHz = unwrappedPCR
				ref.Base = unwrappedPCR / 300
				ref.Extension = int(unwrappedPCR % 300)
				lastPCR = ref
			}
			prevPCR = v
			pcrCount++
		}

		if tracked[p.PID] {
			st := cc[p.PID]
			if st == nil {
				st = &ccState{}
				cc[p.PID] = st
			}
			if st.started {
				if p.HasPayload {
					if p.CC == st.cc {
						return nil, auditError(ErrCCDuplicatePayload, "continuity counter repeated on a payload-bearing packet", i, p.PID)
					}
					if want := (st.cc + 1) & 0x0F; p.CC != want {
						return nil, auditError(ErrCCGap, "continuity counter did not increment modulo 16", i, p.PID)
					}
				} else if p.CC != st.cc {
					return nil, auditError(ErrCCGap, "adaptation-only packet must keep the continuity counter unchanged", i, p.PID)
				}
			}
			st.started = true
			st.cc = p.CC
		}

		if st := stats[p.PID]; st != nil && p.HasPayload {
			st.PacketCount++
			b := int64(packetSize - p.PayloadStart)
			st.PayloadBytes += b
			payloadTotal += b
		}
	}

	if pcrCount == 0 {
		return nil, auditError(ErrNoPCR, "no PCR found on the PMT-declared PCR PID", 0, pmt.pcrPID)
	}

	duration := int64(0)
	if pcrCount > 1 {
		duration = lastPCR.Value27MHz - firstPCR.Value27MHz
	}
	media := make([]MediaPIDStats, 0, len(mediaPIDs))
	for _, pid := range mediaPIDs {
		media = append(media, *stats[pid])
	}

	return &Report{
		ProgramNumber: prog.number,
		PMTPID:        prog.pid,
		PCRPID:        pmt.pcrPID,
		MediaPIDs:     mediaPIDs,
		PacketCount:   n,
		FirstPCR:      firstPCR,
		LastPCR:       lastPCR,
		Duration27MHz: duration,
		DurationMs:    float64(duration) / 27000,
		PayloadBytes:  payloadTotal,
		Media:         media,
	}, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func pmtProgramNumber(s *tableSection) int {
	return int(s.raw[3])<<8 | int(s.raw[4])
}
