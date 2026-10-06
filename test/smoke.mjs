// Black-box smoke test against a running server over HTTP.
// Used by the one-shot `verify` compose service; exits non-zero on any failure.
import {
  validStream,
  patSection,
  pmtSection,
  psiPacket,
  tsPacket,
  pesPayload,
} from './helpers.mjs';

const BASE = process.env.SMOKE_BASE_URL || 'http://app:8080';
const URL = `${BASE}/api/mpegts/audit?maxPcrGapMs=100`;

let failures = 0;
function check(name, cond, detail = '') {
  if (cond) {
    console.log(`  ok   ${name}`);
  } else {
    failures += 1;
    console.error(`  FAIL ${name}${detail ? ` -- ${detail}` : ''}`);
  }
}

async function waitForHealth(timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return true;
    } catch { /* server not up yet */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

async function audit(body, init = {}) {
  return fetch(URL, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', ...(init.headers || {}) },
    body,
  });
}

console.log(`smoke target: ${BASE}`);
check('server became healthy', await waitForHealth());

// 1. Legal stream.
{
  const res = await audit(validStream({ count: 6 }));
  const body = await res.json();
  check('valid stream -> 200', res.status === 200, `status ${res.status} ${JSON.stringify(body)}`);
  check('  program number reported', body.programNumber === 1);
  check('  media PID reported', JSON.stringify(body.mediaPids) === JSON.stringify(['0x0100']));
  check('  packet count reported', body.packetCount === 8, `got ${body.packetCount}`);
  check('  first/last PCR reported', body.firstPcr && body.lastPcr);
  check('  unwrapped duration reported', typeof body.durationMs === 'number' && body.durationMs === 5);
  check('  payload byte stats reported', body.payloadBytes && body.payloadBytes.total > 0);
}

// 2. PCR wrap stream stays legal.
{
  const wrap = 2 ** 33 - 45;
  const stream = Buffer.concat([
    psiPacket(0, patSection({ pmtPid: 0x1000 })),
    psiPacket(0x1000, pmtSection({ pcrPid: 0x100 })),
    tsPacket({ pid: 0x100, cc: 0, pcr: { base: wrap }, payload: pesPayload() }),
    tsPacket({ pid: 0x100, cc: 1, pcr: { base: 45 }, payload: pesPayload(0x02) }),
  ]);
  const res = await audit(stream);
  const body = await res.json();
  check('PCR wrap stream -> 200', res.status === 200, JSON.stringify(body));
  check('  wrap duration is 1ms', body.durationMs === 1, `got ${body.durationMs}`);
}

// 3. Abnormal streams must be refused with stable codes.
async function expect422(name, stream, code) {
  const res = await audit(stream);
  const body = await res.json().catch(() => ({}));
  const ok = res.status === 422
    && body.ok === false
    && body.error?.code === code
    && (body.error.packetIndex === null || typeof body.error.packetIndex === 'number')
    && (body.error.pid === null || typeof body.error.pid === 'string');
  check(`${name} -> 422 ${code}`, ok, `status=${res.status} body=${JSON.stringify(body)}`);
}

{
  const badSync = validStream();
  badSync[2 * 188] = 0x00;
  await expect422('bad sync byte', badSync, 'INVALID_SYNC_BYTE');

  const tei = validStream();
  tei[3 * 188 + 1] |= 0x80;
  await expect422('transport error indicator', tei, 'TRANSPORT_ERROR_INDICATOR');

  const scrambled = validStream();
  scrambled[4 * 188 + 3] |= 0x80;
  await expect422('scrambled packet', scrambled, 'SCRAMBLED');

  const discontinuity = Buffer.concat([
    psiPacket(0, patSection({ pmtPid: 0x1000 })),
    psiPacket(0x1000, pmtSection({ pcrPid: 0x100 })),
    tsPacket({ pid: 0x100, cc: 0, pcr: { base: 1000 }, payload: pesPayload() }),
    tsPacket({ pid: 0x100, cc: 1, discontinuity: true, pcr: { base: 1090 }, payload: pesPayload(2) }),
  ]);
  await expect422('discontinuity flag', discontinuity, 'DISCONTINUITY_FLAG');

  const multiPat = Buffer.concat([
    psiPacket(0, patSection({
      programs: [{ programNumber: 1, pmtPid: 0x1000 }, { programNumber: 2, pmtPid: 0x1001 }],
    })),
  ]);
  await expect422('multiple programs', multiPat, 'MULTIPLE_PROGRAMS');

  const badCrc = validStream();
  // Flip a PMT stream-loop byte (past the structural header) to break the CRC.
  badCrc[188 + 17] ^= 0xff;
  await expect422('corrupt PMT CRC', badCrc, 'SECTION_CRC_FAILED');

  const ccBreak = Buffer.concat([
    psiPacket(0, patSection({ pmtPid: 0x1000 })),
    psiPacket(0x1000, pmtSection({ pcrPid: 0x100 })),
    tsPacket({ pid: 0x100, cc: 0, pcr: { base: 0 }, payload: pesPayload() }),
    tsPacket({ pid: 0x100, cc: 5, pcr: { base: 90 }, payload: pesPayload(2) }),
  ]);
  await expect422('continuity counter break', ccBreak, 'CONTINUITY_ERROR');

  const pcrBack = Buffer.concat([
    psiPacket(0, patSection({ pmtPid: 0x1000 })),
    psiPacket(0x1000, pmtSection({ pcrPid: 0x100 })),
    tsPacket({ pid: 0x100, cc: 0, pcr: { base: 1_000_000 }, payload: pesPayload() }),
    tsPacket({ pid: 0x100, cc: 1, pcr: { base: 1_000 }, payload: pesPayload(2) }),
  ]);
  await expect422('PCR backwards', pcrBack, 'PCR_BACKWARD');

  const pcrGap = Buffer.concat([
    psiPacket(0, patSection({ pmtPid: 0x1000 })),
    psiPacket(0x1000, pmtSection({ pcrPid: 0x100 })),
    tsPacket({ pid: 0x100, cc: 0, pcr: { base: 0 }, payload: pesPayload() }),
    tsPacket({ pid: 0x100, cc: 1, pcr: { base: 101 * 90 }, payload: pesPayload(2) }),
  ]);
  await expect422('PCR gap exceeded', pcrGap, 'PCR_GAP_EXCEEDED');

  const wrongPcrPid = Buffer.concat([
    psiPacket(0, patSection({ pmtPid: 0x1000 })),
    psiPacket(0x1000, pmtSection({ pcrPid: 0x100, streams: [{ streamType: 0x1b, elementaryPid: 0x200 }] })),
    tsPacket({ pid: 0x200, cc: 0, payload: pesPayload() }),
    tsPacket({ pid: 0x300, cc: 0, pcr: { base: 0 }, payload: pesPayload(3) }),
  ]);
  await expect422('PCR on undeclared PID', wrongPcrPid, 'PCR_WRONG_PID');
}

// 4. HTTP-level rule enforcement.
{
  const noGap = await fetch(`${BASE}/api/mpegts/audit`, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body: validStream(),
  });
  check('missing maxPcrGapMs -> 400', noGap.status === 400, `status ${noGap.status}`);

  const badGap = await fetch(`${BASE}/api/mpegts/audit?maxPcrGapMs=0`, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body: validStream(),
  });
  check('maxPcrGapMs=0 -> 400', badGap.status === 400, `status ${badGap.status}`);

  const wrongType = await fetch(URL, {
    method: 'POST',
    headers: { 'content-type': 'text/plain' },
    body: validStream(),
  });
  check('wrong content type -> 415', wrongType.status === 415, `status ${wrongType.status}`);

  const oversize = await audit(Buffer.alloc(8 * 1024 * 1024 + 188, 0x47));
  check('oversize body -> 413', oversize.status === 413, `status ${oversize.status}`);
}

if (failures > 0) {
  console.error(`\nsmoke result: ${failures} check(s) failed`);
  process.exit(1);
}
console.log('\nsmoke result: all checks passed');
