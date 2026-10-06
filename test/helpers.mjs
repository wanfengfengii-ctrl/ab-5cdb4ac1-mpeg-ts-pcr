// Helpers that synthesise MPEG-TS packets/sections for tests and smoke checks.
import { crc32Mpeg2 } from '../src/crc.mjs';
import { PACKET_SIZE, SYNC_BYTE } from '../src/constants.mjs';

export { PACKET_SIZE };

// Build a CRC-protected section. `fields` are the section bytes following the
// section_length field (table_id_extension ... end of data loops).
export function buildSection(tableId, fields) {
  const length = fields.length + 4; // fields + CRC32
  const out = Buffer.alloc(3 + fields.length + 4);
  out[0] = tableId;
  out[1] = 0xb0 | ((length >> 8) & 0x0f);
  out[2] = length & 0xff;
  out.set(fields, 3);
  const crc = crc32Mpeg2(out, 0, out.length - 4);
  out.writeUInt32BE(crc >>> 0, out.length - 4);
  return out;
}

export function patSection({ programNumber = 1, pmtPid = 0x1000, version = 1, tsId = 1, programs } = {}) {
  const progs = programs || [{ programNumber, pmtPid }];
  const fields = Buffer.alloc(5 + progs.length * 4);
  fields.writeUInt16BE(tsId, 0);
  fields[2] = 0xc1 | ((version & 0x1f) << 1); // current_next = 1
  fields[3] = 0; // section_number
  fields[4] = 0; // last_section_number
  progs.forEach((p, i) => {
    fields.writeUInt16BE(p.programNumber, 5 + i * 4);
    fields.writeUInt16BE(0xe000 | (p.pmtPid & 0x1fff), 7 + i * 4);
  });
  return buildSection(0x00, fields);
}

export function pmtSection({
  programNumber = 1,
  pcrPid = 0x100,
  version = 1,
  streams = [{ streamType: 0x1b, elementaryPid: 0x100 }],
} = {}) {
  const fields = Buffer.alloc(9 + streams.length * 5);
  fields.writeUInt16BE(programNumber, 0);
  fields[2] = 0xc1 | ((version & 0x1f) << 1);
  fields[3] = 0;
  fields[4] = 0;
  fields.writeUInt16BE(0xe000 | (pcrPid & 0x1fff), 5);
  fields.writeUInt16BE(0xf000, 7); // program_info_length = 0
  streams.forEach((s, i) => {
    const o = 9 + i * 5;
    fields[o] = s.streamType;
    fields.writeUInt16BE(0xe000 | (s.elementaryPid & 0x1fff), o + 1);
    fields.writeUInt16BE(0xf000, o + 3); // ES_info_length = 0
  });
  return buildSection(0x02, fields);
}

export function encodePcr(base, ext = 0) {
  // base can reach 2^33-1, beyond JS 32-bit bitwise range: use division.
  const out = Buffer.alloc(6);
  out[0] = Math.floor(base / 2 ** 25) & 0xff;
  out[1] = Math.floor(base / 2 ** 17) & 0xff;
  out[2] = Math.floor(base / 2 ** 9) & 0xff;
  out[3] = Math.floor(base / 2) & 0xff;
  out[4] = ((base & 1) << 7) | 0x7e | ((ext >>> 8) & 1);
  out[5] = ext & 0xff;
  return out;
}

// Build one 188-byte transport packet.
export function tsPacket(opts = {}) {
  const p = Buffer.alloc(PACKET_SIZE, 0xff);
  const pid = opts.pid ?? 0x1fff;
  let flags = 0;
  if (opts.tei) flags |= 0x80;
  if (opts.pusi) flags |= 0x40;
  if (opts.priority) flags |= 0x20;
  p[0] = SYNC_BYTE;
  p[1] = flags | ((pid >>> 8) & 0x1f);
  p[2] = pid & 0xff;

  let afc = opts.afc;
  if (afc === undefined) {
    const hasPayload = !!opts.payload;
    const hasAdapt = opts.adaptationOnly || opts.pcr || opts.discontinuity || opts.randomAccess;
    afc = hasPayload ? (hasAdapt ? 3 : 1) : 2;
  }
  const scrambling = opts.scrambling ?? 0;
  p[3] = ((scrambling & 3) << 6) | ((afc & 3) << 4) | ((opts.cc ?? 0) & 0xf);

  let off = 4;
  if (afc === 2 || afc === 3) {
    const body = [];
    let flags = 0;
    if (opts.discontinuity) flags |= 0x80;
    if (opts.randomAccess) flags |= 0x40;
    if (opts.esPriority) flags |= 0x20;
    if (opts.pcr) flags |= 0x10;
    if (opts.opcr) flags |= 0x08;
    body.push(flags);
    if (opts.pcr) {
      for (const byte of encodePcr(opts.pcr.base, opts.pcr.ext ?? 0)) body.push(byte);
    }
    p[off++] = body.length;
    for (const byte of body) p[off++] = byte;
  }
  if ((afc === 1 || afc === 3) && opts.payload) {
    opts.payload.copy(p, off);
  }
  return p;
}

// PSI packet: pointer_field 0x00 followed by the section, rest stuffed 0xFF.
export function psiPacket(pid, section, opts = {}) {
  const payload = Buffer.alloc(184, 0xff);
  payload[0] = 0x00;
  section.copy(payload, 1);
  return tsPacket({ pid, pusi: true, cc: opts.cc ?? 0, payload, ...opts });
}

export function nullPacket(cc = 0) {
  return tsPacket({ pid: 0x1fff, cc, adaptationOnly: true });
}

// Pes-style payload filler.
export function pesPayload(byte = 0xaa, size = 184) {
  const p = Buffer.alloc(size, byte);
  p[0] = 0x00; p[1] = 0x00; p[2] = 0x01; p[3] = 0xe0;
  return p;
}

// A known-good program: PAT + PMT + media packets carrying monotonic PCR.
export function validStream(opts = {}) {
  const programNumber = opts.programNumber ?? 1;
  const pmtPid = opts.pmtPid ?? 0x1000;
  const pcrPid = opts.pcrPid ?? 0x100;
  const mediaPid = opts.mediaPid ?? 0x100;
  const version = opts.version ?? 1;
  const count = opts.count ?? 8;
  const startBase = opts.startBase ?? 1_000_000;
  const stepBase = opts.stepBase ?? 90; // 1 ms of PCR_base (90 kHz)
  const streamType = opts.streamType ?? 0x1b;

  const packets = [
    psiPacket(0x0000, patSection({ programNumber, pmtPid, version }), { cc: 0 }),
    psiPacket(pmtPid, pmtSection({ programNumber, pcrPid, version, streams: [{ streamType, elementaryPid: mediaPid }] }), { cc: 0 }),
  ];
  for (let i = 0; i < count; i++) {
    packets.push(tsPacket({
      pid: mediaPid,
      cc: i & 0x0f,
      pusi: i === 0,
      pcr: { base: startBase + i * stepBase, ext: 0 },
      payload: pesPayload(0xa0 + (i & 0x0f)),
    }));
  }
  return Buffer.concat(packets);
}
