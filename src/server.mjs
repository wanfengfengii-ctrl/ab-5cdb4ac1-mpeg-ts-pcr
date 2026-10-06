import http from 'node:http';
import { URL } from 'node:url';
import { MAX_STREAM_SIZE, ERROR_CODES } from './constants.mjs';
import { auditTs, AuditError } from './auditor.mjs';

export function createRequestHandler() {
  return function handler(req, res) {
    const send = (status, body) => {
      const json = JSON.stringify(body);
      res.writeHead(status, {
        'content-type': 'application/json; charset=utf-8',
        'content-length': Buffer.byteLength(json),
      });
      res.end(json);
    };

    let pathname;
    let query;
    try {
      const url = new URL(req.url, 'http://localhost');
      pathname = url.pathname;
      query = url.searchParams;
    } catch {
      return send(400, { ok: false, error: { code: 'BAD_REQUEST', message: 'malformed URL' } });
    }

    if (req.method === 'GET' && pathname === '/health') {
      return send(200, { status: 'ok' });
    }

    if (req.method !== 'POST' || pathname !== '/api/mpegts/audit') {
      return send(404, { ok: false, error: { code: 'NOT_FOUND', message: 'use POST /api/mpegts/audit' } });
    }

    if ((req.headers['content-type'] || '').toLowerCase() !== 'application/octet-stream') {
      return send(415, {
        ok: false,
        error: { code: 'UNSUPPORTED_MEDIA_TYPE', message: 'Content-Type must be application/octet-stream' },
      });
    }

    // maxPcrGapMs is required and must be an integer in [1, 10000].
    const rawGap = query.get('maxPcrGapMs');
    if (rawGap === null || !/^\d+$/.test(rawGap)) {
      return send(400, {
        ok: false,
        error: { code: 'INVALID_MAX_PCR_GAP', message: 'query parameter maxPcrGapMs is required and must be an integer' },
      });
    }
    const maxPcrGapMs = Number(rawGap);
    if (!Number.isSafeInteger(maxPcrGapMs) || maxPcrGapMs < 1 || maxPcrGapMs > 10000) {
      return send(400, {
        ok: false,
        error: { code: 'INVALID_MAX_PCR_GAP', message: 'maxPcrGapMs must be between 1 and 10000' },
      });
    }

    const chunks = [];
    let received = 0;
    let tooLarge = false;

    req.on('data', (chunk) => {
      if (tooLarge) return;
      received += chunk.length;
      if (received > MAX_STREAM_SIZE) {
        tooLarge = true;
        send(413, {
          ok: false,
          error: { code: ERROR_CODES.BODY_TOO_LARGE, message: `stream exceeds ${MAX_STREAM_SIZE} bytes (8 MiB)` },
        });
        // Let the 413 flush, then tear down the oversized upload.
        res.on('finish', () => req.destroy());
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (tooLarge) return;
      const body = Buffer.concat(chunks);
      try {
        const result = auditTs(body, maxPcrGapMs);
        return send(200, { ok: true, ...result });
      } catch (err) {
        if (err instanceof AuditError) {
          return send(422, {
            ok: false,
            error: {
              code: err.code,
              message: err.message,
              packetIndex: err.packetIndex,
              pid: err.pid === null || err.pid === undefined ? null : `0x${err.pid.toString(16).padStart(4, '0')}`,
            },
          });
        }
        return send(500, { ok: false, error: { code: 'INTERNAL_ERROR', message: String(err && err.message || err) } });
      }
    });

    req.on('error', () => {
      // Socket errors (including our own destroy on oversize) end here.
      if (!res.writableEnded) {
        res.socket?.destroy();
      }
    });
  };
}

export function createServer() {
  return http.createServer(createRequestHandler());
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const port = Number(process.env.PORT || 8080);
  const host = process.env.HOST || '0.0.0.0';
  const server = createServer();
  server.listen(port, host, () => {
    console.log(`mpegts-audit listening on http://${host}:${port}`);
  });
}
