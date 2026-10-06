import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from '../src/server.mjs';
import { validStream } from './helpers.mjs';

let server;
let base;

before(async () => {
  server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  base = `http://127.0.0.1:${port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

async function postAudit(body, { gap = 100, contentType = 'application/octet-stream' } = {}) {
  return fetch(`${base}/api/mpegts/audit?maxPcrGapMs=${gap}`, {
    method: 'POST',
    headers: { 'content-type': contentType },
    body,
  });
}

test('health endpoint reports ok', async () => {
  const res = await fetch(`${base}/health`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { status: 'ok' });
});

test('valid stream returns the audit summary', async () => {
  const res = await postAudit(validStream({ count: 5 }));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.equal(body.programNumber, 1);
  assert.equal(body.packetCount, 7);
  assert.equal(body.durationMs, 4);
  assert.deepEqual(body.mediaPids, ['0x0100']);
  assert.ok(body.payloadBytes.total > 0);
});

test('missing maxPcrGapMs is a 400 with stable code', async () => {
  const res = await fetch(`${base}/api/mpegts/audit`, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body: validStream(),
  });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error.code, 'INVALID_MAX_PCR_GAP');
});

test('out-of-range maxPcrGapMs is a 400', async () => {
  const res = await postAudit(validStream(), { gap: 10001 });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error.code, 'INVALID_MAX_PCR_GAP');
});

test('wrong content type is a 415', async () => {
  const res = await postAudit(validStream(), { contentType: 'text/plain' });
  assert.equal(res.status, 415);
});

test('an invalid stream is a 422 carrying packet index, pid and stable code', async () => {
  const stream = validStream({ count: 4 });
  stream[3 * 188 + 1] |= 0x80; // TEI on packet 3
  const res = await postAudit(stream);
  assert.equal(res.status, 422);
  const body = await res.json();
  assert.equal(body.ok, false);
  assert.equal(body.error.code, 'TRANSPORT_ERROR_INDICATOR');
  assert.equal(body.error.packetIndex, 3);
  assert.equal(body.error.pid, '0x0100');
});

test('oversize body is a 413', async () => {
  const res = await postAudit(Buffer.alloc(8 * 1024 * 1024 + 1, 0xff));
  assert.equal(res.status, 413);
  assert.equal((await res.json()).error.code, 'BODY_TOO_LARGE');
});

test('unknown route is 404', async () => {
  const res = await fetch(`${base}/nope`);
  assert.equal(res.status, 404);
});
