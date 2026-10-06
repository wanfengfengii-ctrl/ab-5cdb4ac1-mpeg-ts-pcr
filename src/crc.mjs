// CRC-32/MPEG-2: polynomial 0x04C11DB7, init 0xFFFFFFFF, MSB first,
// no input/output reflection, final XOR 0. Used to verify PSI sections.
const TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let crc = n << 24;
    for (let k = 0; k < 8; k++) {
      crc = crc & 0x80000000 ? ((crc << 1) ^ 0x04c11db7) >>> 0 : (crc << 1) >>> 0;
    }
    table[n] = crc >>> 0;
  }
  return table;
})();

export function crc32Mpeg2(data, start = 0, end = data.length) {
  let crc = 0xffffffff;
  for (let i = start; i < end; i++) {
    crc = (((crc << 8) >>> 0) ^ TABLE[((crc >>> 24) ^ data[i]) & 0xff]) >>> 0;
  }
  return crc >>> 0;
}
