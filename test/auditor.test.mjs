import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditTs } from '../src/auditor.mjs';
import { PACKET_SIZE, PCR_BASE_WRAP, ERROR_CODES } from '../src/constants.mjs';
import {
  validStream,
  patSection,
  pmtSection,
  psiPacket,
  tsPacket,
  pesPayload,
} from './helpers.mjs';

const PMT_PID = 0x1000;
const PCR_PID = 0x0100;

function expectError(buffer, maxGap, code, packetIndex = undefined, pid = undefined) {
  try {
    auditTs(buffer, maxGap);
    assert.fail(`expected AuditError ${code}`);
  } catch (err) {
    assert.equal(err.code, code, `got ${err.code}: ${err.message}`);
    if (packetIndex !== undefined) assert.equal(err.packetIndex, packetIndex);
    if (pid !== undefined) assert.equal(err.pid, pid);
  }
}

test('accepts a well-formed single-program stream and reports summary', () => {
  const stream = validStream({ count: 8 });
  const r = auditTs(stream, 100);
  assert.equal(r.programNumber, 1);
  assert.equal(r.pmtPid, '0x1000');
  assert.equal(r.pcrPid, '0x0100');
  assert.deepEqual(r.mediaPids, ['0x0100']);
  assert.equal(r.packetCount, 10);
  assert.equal(r.firstPcr.base, 1_000_000);
  assert.equal(r.lastPcr.base, 1_000_630);
  assert.equal(r.durationMs, 7);
  assert.ok(r.payloadBytes.byPid['0x0100'] > 0);
  assert.equal(r.payloadBytes.total, r.payloadBytes.byPid['0x0100']);
});

test('empty body is rejected', () => {
  expectError(Buffer.alloc(0), 100, ERROR_CODES.EMPTY_STREAM);
});

test('length not a multiple of 188 is rejected', () => {
  expectError(Buffer.alloc(PACKET_SIZE + 1, 0xff), 100, ERROR_CODES.PACKET_LENGTH);
});

test('invalid sync byte is rejected with packet index', () => {
  const stream = validStream();
  stream[2 * PACKET_SIZE] = 0x00;
  expectError(stream, 100, ERROR_CODES.INVALID_SYNC_BYTE, 2, null);
});

test('transport error indicator is rejected', () => {
  const stream = validStream();
  stream[3 * PACKET_SIZE + 1] |= 0x80;
  expectError(stream, 100, ERROR_CODES.TRANSPORT_ERROR_INDICATOR, 3, PCR_PID);
});

test('scrambling is rejected', () => {
  const stream = validStream();
  // scrambling_control=10 in the high bits of byte 4
  stream[4 * PACKET_SIZE + 3] |= 0x80;
  expectError(stream, 100, ERROR_CODES.SCRAMBLED, 4, PCR_PID);
});

test('discontinuity indicator is rejected', () => {
  const packets = [
    psiPacket(0, patSection({ pmtPid: PMT_PID })),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID })),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 1000 }, payload: pesPayload() }),
    tsPacket({ pid: PCR_PID, cc: 1, discontinuity: true, pcr: { base: 1090 }, payload: pesPayload(0x01) }),
  ];
  expectError(Buffer.concat(packets), 100, ERROR_CODES.DISCONTINUITY_FLAG, 3, PCR_PID);
});

test('reserved adaptation_field_control 00 is rejected', () => {
  const stream = validStream();
  stream[5 * PACKET_SIZE + 3] &= 0xcf; // clear adaptation control bits (5:4)
  expectError(stream, 100, ERROR_CODES.ADAPTATION_FIELD_INVALID, 5, PCR_PID);
});

test('payload-bearing packets must increment CC mod 16', () => {
  const packets = [
    psiPacket(0, patSection({ pmtPid: PMT_PID })),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID })),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 1000 }, payload: pesPayload() }),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 1090 }, payload: pesPayload(0x01) }),
  ];
  expectError(Buffer.concat(packets), 100, ERROR_CODES.CONTINUITY_ERROR, 3, PCR_PID);
});

test('CC wraps 15 -> 0 for payload packets', () => {
  const packets = [
    psiPacket(0, patSection({ pmtPid: PMT_PID })),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID })),
  ];
  for (let i = 0; i < 17; i++) {
    packets.push(tsPacket({
      pid: PCR_PID,
      cc: i & 0x0f,
      pcr: { base: 1000 + i * 90 },
      payload: pesPayload(i & 0x0f),
    }));
  }
  const r = auditTs(Buffer.concat(packets), 100);
  assert.equal(r.packetCount, 19);
});

test('adaptation-only packets hold the CC; following payload increments', () => {
  const packets = [
    psiPacket(0, patSection({ pmtPid: PMT_PID })),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID })),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 1000 }, payload: pesPayload() }),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 1045 }, adaptationOnly: true }),
    tsPacket({ pid: PCR_PID, cc: 1, pcr: { base: 1090 }, payload: pesPayload(0x02) }),
  ];
  auditTs(Buffer.concat(packets), 100);
});

test('adaptation-only packet that bumps CC is rejected', () => {
  const packets = [
    psiPacket(0, patSection({ pmtPid: PMT_PID })),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID })),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 1000 }, payload: pesPayload() }),
    tsPacket({ pid: PCR_PID, cc: 1, pcr: { base: 1045 }, adaptationOnly: true }),
  ];
  expectError(Buffer.concat(packets), 100, ERROR_CODES.CONTINUITY_ERROR, 3, PCR_PID);
});

test('afc=11 with adaptation_field_length 0 (single stuffing byte) is legal', () => {
  const packets = [
    psiPacket(0, patSection({ pmtPid: PMT_PID })),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID })),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 1000 }, payload: pesPayload() }),
  ];
  // Hand-craft afc=11 with adaptation_field_length 0, then payload.
  const p = Buffer.alloc(188, 0xff);
  p[0] = 0x47;
  p[1] = PCR_PID >>> 8;
  p[2] = PCR_PID & 0xff;
  p[3] = 0x31; // afc=11, cc=1
  p[4] = 0x00; // adaptation_field_length = 0
  packets.push(p);
  auditTs(Buffer.concat(packets), 100);
});

test('PAT and PMT CC are validated too', () => {
  const packets = [
    psiPacket(0, patSection({ pmtPid: PMT_PID }), { cc: 0 }),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID }), { cc: 0 }),
    psiPacket(0, patSection({ pmtPid: PMT_PID }), { cc: 0 }), // duplicate, no PUSI section replay
  ];
  expectError(Buffer.concat(packets), 100, ERROR_CODES.CONTINUITY_ERROR, 2, 0);
});

test('CC replay covers media packets seen before the PMT', () => {
  const packets = [
    psiPacket(0, patSection({ pmtPid: PMT_PID })),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 1000 }, payload: pesPayload() }),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID })),
    tsPacket({ pid: PCR_PID, cc: 1, pcr: { base: 1090 }, payload: pesPayload(0x02) }),
  ];
  auditTs(Buffer.concat(packets), 100);

  const bad = [
    psiPacket(0, patSection({ pmtPid: PMT_PID })),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 1000 }, payload: pesPayload() }),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 1090 }, payload: pesPayload(0x02) }),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID })),
  ];
  expectError(Buffer.concat(bad), 100, ERROR_CODES.CONTINUITY_ERROR, 2, PCR_PID);
});

test('stream without PAT is rejected', () => {
  const packets = [
    tsPacket({ pid: 0x0100, cc: 0, pcr: { base: 1000 }, payload: pesPayload() }),
  ];
  expectError(Buffer.concat(packets), 100, ERROR_CODES.NO_PAT);
});

test('stream without PMT is rejected', () => {
  const packets = [
    psiPacket(0, patSection({ pmtPid: PMT_PID })),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 1000 }, payload: pesPayload() }),
  ];
  expectError(Buffer.concat(packets), 100, ERROR_CODES.NO_PMT);
});

test('multiple programs are rejected', () => {
  const multi = patSection({
    programs: [
      { programNumber: 1, pmtPid: 0x1000 },
      { programNumber: 2, pmtPid: 0x1001 },
    ],
  });
  const packets = [psiPacket(0, multi)];
  expectError(Buffer.concat(packets), 100, ERROR_CODES.MULTIPLE_PROGRAMS, 0, 0);
});

test('corrupt section CRC is rejected', () => {
  const stream = validStream();
  stream[PACKET_SIZE + 10] ^= 0xff; // damage PMT section byte
  expectError(stream, 100, ERROR_CODES.SECTION_CRC_FAILED, 1, PMT_PID);
});

test('same version with changed content is rejected; identical repeats pass', () => {
  const repeat = [
    psiPacket(0, patSection({ pmtPid: PMT_PID, tsId: 1 })),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID })),
    psiPacket(0, patSection({ pmtPid: PMT_PID, tsId: 1 }), { cc: 1 }),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 1000 }, payload: pesPayload() }),
    tsPacket({ pid: PCR_PID, cc: 1, pcr: { base: 1090 }, payload: pesPayload(0x01) }),
  ];
  auditTs(Buffer.concat(repeat), 100);

  const changed = [
    psiPacket(0, patSection({ pmtPid: PMT_PID, tsId: 1 })),
    psiPacket(0, patSection({ pmtPid: PMT_PID, tsId: 99 }), { cc: 1 }),
  ];
  expectError(Buffer.concat(changed), 100, ERROR_CODES.TABLE_VERSION_CONTENT_MISMATCH, 1, 0);
});

test('PMT program_number not matching PAT is rejected', () => {
  const packets = [
    psiPacket(0, patSection({ programNumber: 1, pmtPid: PMT_PID })),
    psiPacket(PMT_PID, pmtSection({ programNumber: 7, pcrPid: PCR_PID })),
  ];
  expectError(Buffer.concat(packets), 100, ERROR_CODES.PMT_PROGRAM_MISMATCH, 1, PMT_PID);
});

test('PCR on a PID other than the declared PCR PID is rejected', () => {
  const stream = validStream({ pcrPid: 0x0100, mediaPid: 0x0200 });
  // validStream already puts PCR on mediaPid; set a PCR also on PAT-less other pid
  const packets = [
    stream.subarray(0, PACKET_SIZE * 2),
    tsPacket({ pid: 0x0300, cc: 0, pcr: { base: 1 }, payload: pesPayload(0x09) }),
    stream.subarray(PACKET_SIZE * 2),
  ];
  expectError(Buffer.concat(packets), 100, ERROR_CODES.PCR_WRONG_PID, 2, 0x0300);
});

test('missing PCR is rejected', () => {
  const packets = [
    psiPacket(0, patSection({ pmtPid: PMT_PID })),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID })),
    tsPacket({ pid: PCR_PID, cc: 0, payload: pesPayload() }),
  ];
  expectError(Buffer.concat(packets), 100, ERROR_CODES.PCR_MISSING);
});

test('PCR going backwards is rejected', () => {
  const packets = [
    psiPacket(0, patSection({ pmtPid: PMT_PID })),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID })),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 1_000_000 }, payload: pesPayload() }),
    tsPacket({ pid: PCR_PID, cc: 1, pcr: { base: 999_999 }, payload: pesPayload(0x01) }),
  ];
  expectError(Buffer.concat(packets), 100, ERROR_CODES.PCR_BACKWARD, 3, PCR_PID);
});

test('PCR gap at the limit passes; over the limit fails', () => {
  const atLimit = [
    psiPacket(0, patSection({ pmtPid: PMT_PID })),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID })),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 0 }, payload: pesPayload() }),
    tsPacket({ pid: PCR_PID, cc: 1, pcr: { base: 100 * 90 }, payload: pesPayload(0x01) }),
  ];
  auditTs(Buffer.concat(atLimit), 100);

  const over = [
    psiPacket(0, patSection({ pmtPid: PMT_PID })),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID })),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: 0 }, payload: pesPayload() }),
    tsPacket({ pid: PCR_PID, cc: 1, pcr: { base: 101 * 90 }, payload: pesPayload(0x01) }),
  ];
  expectError(Buffer.concat(over), 100, ERROR_CODES.PCR_GAP_EXCEEDED, 3, PCR_PID);
});

test('PCR is unwrapped across the 33-bit base wrap without a gap violation', () => {
  const nearWrap = PCR_BASE_WRAP - 45; // half ms before wrap
  const packets = [
    psiPacket(0, patSection({ pmtPid: PMT_PID })),
    psiPacket(PMT_PID, pmtSection({ pcrPid: PCR_PID })),
    tsPacket({ pid: PCR_PID, cc: 0, pcr: { base: nearWrap, ext: 0 }, payload: pesPayload() }),
    tsPacket({ pid: PCR_PID, cc: 1, pcr: { base: 45, ext: 0 }, payload: pesPayload(0x01) }),
  ];
  const r = auditTs(Buffer.concat(packets), 100);
  assert.equal(r.firstPcr.base, nearWrap);
  assert.equal(r.lastPcr.base, 45);
  assert.equal(r.durationMs, 1);
});
