# mpegts-audit

广播归档前的单节目 MPEG-TS 严格核验服务。零第三方依赖（Node.js 内置 `http` / `node:test` / `fetch`）。

## API

### `POST /api/mpegts/audit?maxPcrGapMs=<1..10000>`

- `Content-Type: application/octet-stream`，Body 为原始 TS 流，上限 8 MiB。
- 必填查询参数 `maxPcrGapMs`：整数，取值 1–10000（毫秒）。
- 流必须由 188 字节包组成。

**成功 `200`**（示例）：

```json
{
  "ok": true,
  "programNumber": 1,
  "pmtPid": "0x1000",
  "pcrPid": "0x0100",
  "mediaPids": ["0x0100"],
  "packetCount": 10,
  "firstPcr": { "base": 1000000, "extension": 0 },
  "lastPcr": { "base": 1000630, "extension": 0 },
  "durationMs": 7,
  "durationTicks27mhz": 189000,
  "payloadBytes": { "total": 1656, "byPid": { "0x0100": 1656 } }
}
```

**失败 `422`**（任何规则失败即整体拒绝，绝不返回部分结果）：

```json
{
  "ok": false,
  "error": {
    "code": "PCR_GAP_EXCEEDED",
    "message": "PCR gap 101.000 ms exceeds maxPcrGapMs=100",
    "packetIndex": 3,
    "pid": "0x0100"
  }
}
```

`packetIndex` 为 0 基包序号（无具体包时为 `null`），`pid` 为相关 PID。
传输/参数类错误使用 `400/413/415`，流规则错误使用 `422`。

### `GET /health`

健康检查端点，返回 `{"status":"ok"}`。

## 核验规则

- 同步字节必须为 `0x47`；总长度必须是 188 的整数倍。
- 拒绝 `transport_error_indicator`、非零 `transport_scrambling_control`、适配字段 `discontinuity_indicator`。
- PAT/PMT 段必须在单个 TS 包内完整承载、CRC-32（MPEG-2）正确；同一表版本重复出现时内容必须逐字节一致；拒绝多节目 PAT 与非当前段。
- PMT 的 `program_number` 必须与 PAT 一致。
- PAT、PMT、PCR PID 及 PMT 声明的所有媒体 PID：含载荷包的 `continuity_counter` 必须模 16 递增；仅适配字段包必须保持计数不变。声明前出现的包同样纳入回放校验，空包（0x1fff）不校验。
- PCR 只能出现在 PMT 声明的 PCR PID 上；PCR 按 27 MHz 展开 33 位回绕后不得倒退，相邻 PCR 间隔不得超过 `maxPcrGapMs`（回绕点按一个完整周期正确展开）。

稳定错误码见 `src/constants.mjs` 的 `ERROR_CODES`（`INVALID_SYNC_BYTE`、`TRANSPORT_ERROR_INDICATOR`、`SCRAMBLED`、`DISCONTINUITY_FLAG`、`SECTION_CRC_FAILED`、`SECTION_NOT_SINGLE_PACKET`、`TABLE_VERSION_CONTENT_MISMATCH`、`MULTIPLE_PROGRAMS`、`CONTINUITY_ERROR`、`PCR_WRONG_PID`、`PCR_BACKWARD`、`PCR_GAP_EXCEEDED` 等）。

## 本地运行

```bash
npm test          # 单元 + HTTP 集成测试
npm run build     # 语法检查并产出 dist/
PORT=8080 npm start
```

## Docker / Docker Compose

```bash
# 构建并用 verify 一次性服务完成全量验证（测试 -> 构建 -> 合法/异常流冒烟）
docker compose up --build --exit-code-from verify verify
```

- `app`：长期服务，宿主机端口可通过环境变量配置：`APP_PORT=9090 docker compose up -d app`；内置健康检查。
- `verify`：一次性服务，等待 `app` 健康后依次运行代码测试、应用构建、合法流与异常流 HTTP 冒烟，以自身退出码报告结果并退出（`restart: "no"`），可在清洁环境反复重跑。
- 仅启动服务：`APP_PORT=8080 docker compose up app`。
