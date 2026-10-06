import {
  PACKET_SIZE,
  SYNC_BYTE,
  NULL_PID,
  PID_PAT,
  TABLE_ID_PAT,
  TABLE_ID_PMT,
  PCR_BASE_WRAP,
  PCR_TICKS_PER_MS,
  ERROR_CODES,
} from './constants.mjs';
import { crc32Mpeg2 } from './crc.mjs';

const PCR_EXT_WRAP = 300;
const PCR_WRAP_27MHZ = PCR_BASE_WRAP * PCR_EXT_WRAP; // 2^33 * 300
const HEADER_SIZE = 4;

export class AuditError extends Error {
  constructor(code, packetIndex, pid, message) {
    super(message || code);
    this.name = 'AuditError';
    this.code = code;
    this.packetIndex = packetIndex === undefined ? null : packetIndex;
    this.pid = pid === undefined || pid === null ? null : pid;
  }
}

export function pidToHex(pid) {
  return `0x${pid.toString(16).padStart(4, '0')}`;
}

function readU16(b, o) {
  return (b[o] << 8) | b[o + 1];
}

function readU32(b, o) {
  return (b[o] * 0x1000000) + ((b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]);
}

// Parse a PSI section claimed to live entirely inside one TS packet payload.
// Returns { start, end, version, body: Buffer } or throws AuditError.
function parseSinglePacketSection(payload, expectedTableId, packetIndex, pid) {
  // A PSI packet carrying section data must set the payload-unit-start flag,
  // hence must begin with the pointer_field.
  let pointer = payload[0];
  if (pointer > payload.length - 1) {
    throw new AuditError(ERROR_CODES.SECTION_INVALID, packetIndex, pid,
      'pointer_field exceeds packet payload');
  }
  const start = 1 + pointer;
  const minSectionSize = 8; // table_id .. last_section_number (shortest legal CRC-protected section)
  if (payload.length - start < minSectionSize) {
    throw new AuditError(ERROR_CODES.SECTION_NOT_SINGLE_PACKET, packetIndex, pid,
      'section does not fit in a single transport packet');
  }
  const tableId = payload[start];
  if (tableId !== expectedTableId) {
    throw new AuditError(ERROR_CODES.SECTION_INVALID, packetIndex, pid,
      `unexpected table_id 0x${tableId.toString(16)}`);
  }
  if ((payload[start + 1] & 0x80) === 0) {
    throw new AuditError(ERROR_CODES.SECTION_INVALID, packetIndex, pid,
      'section_syntax_indicator not set');
  }
  const sectionLength = ((payload[start + 1] & 0x0f) << 8) | payload[start + 2];
  const end = start + 3 + sectionLength;
  // The whole section, including its CRC, must terminate inside this packet.
  if (sectionLength < 5 + 4 || end > payload.length) {
    throw new AuditError(ERROR_CODES.SECTION_NOT_SINGLE_PACKET, packetIndex, pid,
      'section is not fully contained in a single transport packet');
  }
  const sectionNumber = payload[start + 6];
  const lastSectionNumber = payload[start + 7];
  if (sectionNumber !== 0 || lastSectionNumber !== 0) {
    throw new AuditError(ERROR_CODES.SECTION_INVALID, packetIndex, pid,
      'multi-section PAT/PMT is not permitted for a single-program audit');
  }
  const expectedCrc = readU32(payload, end - 4);
  const actualCrc = crc32Mpeg2(payload, start, end - 4);
  if (actualCrc !== expectedCrc) {
    throw new AuditError(ERROR_CODES.SECTION_CRC_FAILED, packetIndex, pid,
      'section CRC-32 mismatch');
  }
  const version = (payload[start + 5] >> 1) & 0x1f;
  const currentNext = payload[start + 5] & 0x01;
  if (currentNext !== 1) {
    throw new AuditError(ERROR_CODES.SECTION_INVALID, packetIndex, pid,
      'section is not currently applicable (current_next_indicator=0)');
  }
  return { start, end, version };
}

function parsePat(payload, packetIndex, pid) {
  const { start, end, version } = parseSinglePacketSection(
    payload, TABLE_ID_PAT, packetIndex, pid);
  const transportStreamId = readU16(payload, start + 3);
  const programs = [];
  let o = start + 8;
  while (o < end - 4) {
    if (o + 4 > end - 4) {
      throw new AuditError(ERROR_CODES.SECTION_INVALID, packetIndex, pid,
        'PAT program loop is truncated');
    }
    const programNumber = readU16(payload, o);
    const pidValue = readU16(payload, o + 2) & 0x1fff;
    if (programNumber !== 0) programs.push({ programNumber, pmtPid: pidValue });
    o += 4;
  }
  return {
    version,
    transportStreamId,
    programs,
    sectionBytes: Buffer.from(payload.subarray(start, end)),
  };
}

function parsePmt(payload, expectedProgramNumber, packetIndex, pid) {
  const { start, end, version } = parseSinglePacketSection(
    payload, TABLE_ID_PMT, packetIndex, pid);
  const programNumber = readU16(payload, start + 3);
  if (programNumber !== expectedProgramNumber) {
    throw new AuditError(ERROR_CODES.PMT_PROGRAM_MISMATCH, packetIndex, pid,
      `PMT program_number ${programNumber} does not match PAT program ${expectedProgramNumber}`);
  }
  const pcrPid = readU16(payload, start + 8) & 0x1fff;
  const programInfoLength = readU16(payload, start + 10) & 0x0fff;
  let o = start + 12 + programInfoLength;
  if (o > end - 4) {
    throw new AuditError(ERROR_CODES.SECTION_INVALID, packetIndex, pid,
      'PMT program_info_length exceeds section');
  }
  const streams = [];
  while (o < end - 4) {
    if (o + 5 > end - 4) {
      throw new AuditError(ERROR_CODES.SECTION_INVALID, packetIndex, pid,
        'PMT elementary stream loop is truncated');
    }
    const streamType = payload[o];
    const elementaryPid = readU16(payload, o + 1) & 0x1fff;
    const esInfoLength = readU16(payload, o + 3) & 0x0fff;
    o += 5;
    if (o + esInfoLength > end - 4) {
      throw new AuditError(ERROR_CODES.SECTION_INVALID, packetIndex, pid,
        'PMT ES descriptor length exceeds section');
    }
    o += esInfoLength;
    streams.push({ streamType, elementaryPid });
  }
  return {
    version,
    programNumber,
    pcrPid,
    streams,
    sectionBytes: Buffer.from(payload.subarray(start, end)),
  };
}

// Strict audit of a complete single-program MPEG-TS buffer.
// Throws AuditError on any rule violation; returns the audit summary otherwise.
export function auditTs(buffer, maxPcrGapMs) {
  if (!Buffer.isBuffer(buffer) && !(buffer instanceof Uint8Array)) {
    throw new AuditError(ERROR_CODES.EMPTY_STREAM, null, null, 'empty request body');
  }
  const totalLength = buffer.length;
  if (totalLength === 0) {
    throw new AuditError(ERROR_CODES.EMPTY_STREAM, null, null, 'empty request body');
  }
  if (totalLength % PACKET_SIZE !== 0) {
    throw new AuditError(ERROR_CODES.PACKET_LENGTH,
      Math.floor(totalLength / PACKET_SIZE), null,
      `stream length ${totalLength} is not a multiple of ${PACKET_SIZE} bytes`);
  }
  const packetCount = totalLength / PACKET_SIZE;

  // Programme table state.
  let programNumber = null;
  let pmtPid = null;
  let pcrPid = null;
  const mediaPidSet = new Set();
  const patByVersion = new Map();   // version -> section bytes
  const pmtByVersion = new Map();
  let patCount = 0;
  let pmtCount = 0;

  // Continuity state: registered PIDs are checked live; packets observed on a
  // PID before it becomes known (e.g. media before the PMT) are replayed later.
  const ccRegistered = new Set();
  const ccLast = new Map();      // pid -> last continuity_counter
  const ccPending = new Map();   // pid -> [{ index, hasPayload, cc }]
  ccRegistered.add(PID_PAT);

  function registerPid(pid) {
    if (pid === NULL_PID || ccRegistered.has(pid)) return;
    ccRegistered.add(pid);
    const events = ccPending.get(pid);
    if (events) {
      for (const ev of events) checkContinuity(pid, ev);
      ccPending.delete(pid);
    }
  }

  function checkContinuity(pid, ev) {
    const { index, hasPayload, cc } = ev;
    if (ccLast.has(pid)) {
      const expected = (ccLast.get(pid) + 1) & 0x0f;
      if (hasPayload) {
        if (cc !== expected) {
          throw new AuditError(ERROR_CODES.CONTINUITY_ERROR, index, pid,
            `continuity_counter ${cc} does not continue from ${ccLast.get(pid)}`);
        }
      } else {
        // Adaptation-only packet: counter must be held, not incremented.
        if (cc !== ccLast.get(pid)) {
          throw new AuditError(ERROR_CODES.CONTINUITY_ERROR, index, pid,
            `adaptation-only packet changed continuity_counter from ${ccLast.get(pid)} to ${cc}`);
        }
      }
    }
    ccLast.set(pid, cc);
  }

  function observeContinuity(pid, index, hasPayload, cc) {
    if (pid === NULL_PID) return;
    const ev = { index, hasPayload, cc };
    if (ccRegistered.has(pid)) checkContinuity(pid, ev);
    else {
      if (!ccPending.has(pid)) ccPending.set(pid, []);
      ccPending.get(pid).push(ev);
    }
  }

  // Every packet carrying a PCR flag, in stream order.
  const pcrEvents = [];
  // Payload byte totals per PID (filtered to declared media PIDs at the end).
  const payloadBytesByPid = new Map();

  for (let index = 0; index < packetCount; index++) {
    const off = index * PACKET_SIZE;
    const b0 = buffer[off];
    if (b0 !== SYNC_BYTE) {
      throw new AuditError(ERROR_CODES.INVALID_SYNC_BYTE, index, null,
        `expected sync byte 0x47, got 0x${b0.toString(16).padStart(2, '0')}`);
    }
    const b1 = buffer[off + 1];
    const b2 = buffer[off + 2];
    const b3 = buffer[off + 3];

    if (b1 & 0x80) {
      const pidValue = ((b1 & 0x1f) << 8) | b2;
      throw new AuditError(ERROR_CODES.TRANSPORT_ERROR_INDICATOR, index, pidValue,
        'transport_error_indicator is set');
    }
    const scramblingControl = (b3 >> 6) & 0x03;
    if (scramblingControl !== 0) {
      const pidValue = ((b1 & 0x1f) << 8) | b2;
      throw new AuditError(ERROR_CODES.SCRAMBLED, index, pidValue,
        'transport_scrambling_control is non-zero');
    }

    const pid = ((b1 & 0x1f) << 8) | b2;
    const payloadUnitStart = (b1 & 0x40) !== 0;
    const adaptationControl = (b3 >> 4) & 0x03;
    const cc = b3 & 0x0f;

    if (adaptationControl === 0x00) {
      throw new AuditError(ERROR_CODES.ADAPTATION_FIELD_INVALID, index, pid,
        'reserved adaptation_field_control value 00');
    }
    const hasAdaptation = adaptationControl === 0x02 || adaptationControl === 0x03;
    const hasPayload = adaptationControl === 0x01 || adaptationControl === 0x03;

    let payloadOffset = HEADER_SIZE;
    let pcrBase = null;
    let pcrExt = null;

    if (hasAdaptation) {
      const adaptationLength = buffer[off + HEADER_SIZE];
      // afc=10 (adaptation only) must carry at least the flags byte on a
      // non-null packet; afc=11 with length 0 is a legal single stuffing byte.
      if (pid !== NULL_PID && adaptationLength === 0 && !hasPayload) {
        throw new AuditError(ERROR_CODES.ADAPTATION_FIELD_INVALID, index, pid,
          'adaptation_field_length is 0 on an adaptation-only non-null packet');
      }
      if (HEADER_SIZE + 1 + adaptationLength > PACKET_SIZE) {
        throw new AuditError(ERROR_CODES.ADAPTATION_FIELD_INVALID, index, pid,
          'adaptation_field_length exceeds packet bounds');
      }
      if (hasPayload && HEADER_SIZE + 1 + adaptationLength >= PACKET_SIZE) {
        throw new AuditError(ERROR_CODES.ADAPTATION_FIELD_INVALID, index, pid,
          'adaptation field leaves no room for declared payload');
      }
      if (adaptationLength > 0) {
        const flagsOffset = off + HEADER_SIZE + 1;
        const flags = buffer[flagsOffset];
        if (flags & 0x80) {
          throw new AuditError(ERROR_CODES.DISCONTINUITY_FLAG, index, pid,
            'adaptation_field discontinuity_indicator is set');
        }
        if (flags & 0x10) {
          if (adaptationLength < 7) {
            throw new AuditError(ERROR_CODES.PCR_INVALID, index, pid,
              'PCR flag set but adaptation field too short for a 6-byte PCR');
          }
          const p = flagsOffset + 1;
          pcrBase = (buffer[p] * 2 ** 25)
            + (buffer[p + 1] * 2 ** 17)
            + (buffer[p + 2] * 2 ** 9)
            + (buffer[p + 3] * 2)
            + (buffer[p + 4] >> 7);
          pcrExt = ((buffer[p + 4] & 0x01) << 8) | buffer[p + 5];
          if (pcrBase >= PCR_BASE_WRAP || pcrExt >= PCR_EXT_WRAP) {
            throw new AuditError(ERROR_CODES.PCR_INVALID, index, pid,
              'PCR field contains out-of-range values');
          }
        }
      }
      payloadOffset = HEADER_SIZE + 1 + adaptationLength;
    }

    const payloadLength = hasPayload ? PACKET_SIZE - payloadOffset : 0;
    if (hasPayload && payloadLength <= 0) {
      throw new AuditError(ERROR_CODES.ADAPTATION_FIELD_INVALID, index, pid,
        'adaptation field control declares payload but none remains');
    }

    // Continuity counters are validated for PAT, PMT, PCR PID and declared media.
    if (pid !== NULL_PID) {
      observeContinuity(pid, index, hasPayload, cc);
    }

    if (hasPayload && pid !== NULL_PID) {
      payloadBytesByPid.set(pid, (payloadBytesByPid.get(pid) || 0) + payloadLength);
    }

    if (pcrBase !== null) {
      pcrEvents.push({ index, pid, base: pcrBase, ext: pcrExt });
    }

    const payloadView = hasPayload
      ? buffer.subarray(off + payloadOffset, off + PACKET_SIZE)
      : null;

    // PAT
    if (pid === PID_PAT) {
      if (hasPayload) {
        if (!payloadUnitStart) {
          throw new AuditError(ERROR_CODES.SECTION_NOT_SINGLE_PACKET, index, pid,
            'PAT fragment without payload_unit_start_indicator');
        }
        const pat = parsePat(payloadView, index, pid);
        patCount += 1;

        if (pat.programs.length === 0) {
          throw new AuditError(ERROR_CODES.NO_PMT, index, pid,
            'PAT declares no program');
        }
        if (pat.programs.length > 1) {
          throw new AuditError(ERROR_CODES.MULTIPLE_PROGRAMS, index, pid,
            `PAT declares ${pat.programs.length} programs; exactly one required`);
        }
        const entry = pat.programs[0];
        const previous = patByVersion.get(pat.version);
        if (previous && !previous.equals(pat.sectionBytes)) {
          throw new AuditError(ERROR_CODES.TABLE_VERSION_CONTENT_MISMATCH, index, pid,
            `PAT version ${pat.version} reappears with different content`);
        }
        if (!previous) patByVersion.set(pat.version, pat.sectionBytes);
        programNumber = entry.programNumber;
        pmtPid = entry.pmtPid;
        registerPid(pmtPid);
      }
    } else if (pmtPid !== null && pid === pmtPid) {
      // PMT
      if (hasPayload) {
        if (!payloadUnitStart) {
          throw new AuditError(ERROR_CODES.SECTION_NOT_SINGLE_PACKET, index, pid,
            'PMT fragment without payload_unit_start_indicator');
        }
        const pmt = parsePmt(payloadView, programNumber, index, pid);
        pmtCount += 1;

        const previous = pmtByVersion.get(pmt.version);
        if (previous && !previous.equals(pmt.sectionBytes)) {
          throw new AuditError(ERROR_CODES.TABLE_VERSION_CONTENT_MISMATCH, index, pid,
            `PMT version ${pmt.version} reappears with different content`);
        }
        if (!previous) pmtByVersion.set(pmt.version, pmt.sectionBytes);

        pcrPid = pmt.pcrPid;
        for (const s of pmt.streams) {
          mediaPidSet.add(s.elementaryPid);
          registerPid(s.elementaryPid);
        }
        if (pcrPid !== NULL_PID) registerPid(pcrPid);
      }
    }
  }

  if (patCount === 0) {
    throw new AuditError(ERROR_CODES.NO_PAT, null, null, 'stream contains no PAT');
  }
  if (pmtCount === 0) {
    throw new AuditError(ERROR_CODES.NO_PMT, null, pmtPid,
      `stream contains no PMT on PID ${pidToHex(pmtPid)}`);
  }

  // PCR may only appear on the PID declared by the PMT.
  const wrongPcr = pcrEvents.find((e) => e.pid !== pcrPid);
  if (wrongPcr) {
    throw new AuditError(ERROR_CODES.PCR_WRONG_PID, wrongPcr.index, wrongPcr.pid,
      `PCR found on PID ${pidToHex(wrongPcr.pid)}, declared PCR PID is ${pidToHex(pcrPid)}`);
  }
  if (pcrPid === NULL_PID || pcrEvents.length === 0) {
    throw new AuditError(ERROR_CODES.PCR_MISSING, null, pcrPid,
      'no PCR found on the declared PCR PID');
  }

  // Expand the 33-bit/27-MHz PCR timeline across wraps; enforce monotonicity
  // and the configured maximum gap.
  const maxGapTicks = maxPcrGapMs * PCR_TICKS_PER_MS;
  let high = 0;
  let prevUnwrapped = null;
  let firstEvent = null;
  let lastEvent = null;

  for (const ev of pcrEvents) {
    const raw = ev.base * PCR_EXT_WRAP + ev.ext;
    if (prevUnwrapped !== null) {
      const prevRaw = prevUnwrapped - high;
      const withinWrapDelta = raw - prevRaw;
      let candidate;
      let delta;
      if (withinWrapDelta >= 0) {
        candidate = high + raw;
        delta = withinWrapDelta;
      } else {
        // A legal 33-bit wrap adds exactly one full period; a backwards PCR
        // would leave a near-full-period delta, which the gap bound rejects.
        const wrappedDelta = withinWrapDelta + PCR_WRAP_27MHZ;
        if (wrappedDelta > maxGapTicks) {
          throw new AuditError(ERROR_CODES.PCR_BACKWARD, ev.index, ev.pid,
            'PCR value moves backwards (wrap would exceed max gap)');
        }
        high += PCR_WRAP_27MHZ;
        candidate = high + raw;
        delta = wrappedDelta;
      }
      if (delta < 0) {
        throw new AuditError(ERROR_CODES.PCR_BACKWARD, ev.index, ev.pid,
          'unwrapped PCR moves backwards');
      }
      if (delta > maxGapTicks) {
        throw new AuditError(ERROR_CODES.PCR_GAP_EXCEEDED, ev.index, ev.pid,
          `PCR gap ${(delta / PCR_TICKS_PER_MS).toFixed(3)} ms exceeds maxPcrGapMs=${maxPcrGapMs}`);
      }
      prevUnwrapped = candidate;
    } else {
      prevUnwrapped = raw;
      firstEvent = ev;
    }
    lastEvent = ev;
  }

  const durationTicks = prevUnwrapped - (firstEvent.base * PCR_EXT_WRAP + firstEvent.ext);
  const durationMs = Math.round((durationTicks / PCR_TICKS_PER_MS) * 1000) / 1000;

  const mediaPids = [...mediaPidSet].sort((a, b) => a - b);
  const payloadByPid = {};
  let payloadBytesTotal = 0;
  for (const pid of mediaPids) {
    const bytes = payloadBytesByPid.get(pid) || 0;
    payloadByPid[pidToHex(pid)] = bytes;
    payloadBytesTotal += bytes;
  }
  // PCR PID carrying payload but not itself declared as an elementary stream.
  if (pcrPid !== NULL_PID && !mediaPidSet.has(pcrPid)) {
    const bytes = payloadBytesByPid.get(pcrPid) || 0;
    if (bytes > 0) {
      payloadByPid[pidToHex(pcrPid)] = bytes;
      payloadBytesTotal += bytes;
    }
  }

  return {
    programNumber,
    pmtPid: pidToHex(pmtPid),
    pcrPid: pidToHex(pcrPid),
    mediaPids: mediaPids.map(pidToHex),
    packetCount,
    firstPcr: { base: firstEvent.base, extension: firstEvent.ext },
    lastPcr: { base: lastEvent.base, extension: lastEvent.ext },
    durationMs,
    durationTicks27mhz: durationTicks,
    payloadBytes: {
      total: payloadBytesTotal,
      byPid: payloadByPid,
    },
  };
}
