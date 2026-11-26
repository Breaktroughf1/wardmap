// Fetches the Wardmap release archive for this platform from GitHub, checks
// it against the SHA-256 recorded in release.json (taken from the release's
// Sigstore-verified checksums.txt when this package was built), extracts only
// the wardmap binary into a per-user cache, and re-hashes the cached binary
// on every run. No install scripts, no dependencies.
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { version, checksums } = require('./release.json');

const REPO = 'Breaktroughf1/wardmap';

function target(platform = process.platform, arch = process.arch) {
  const plat = { darwin: 'darwin', linux: 'linux', win32: 'windows' }[platform];
  const cpu = { x64: 'amd64', arm64: 'arm64' }[arch];
  if (!plat || !cpu) throw new Error(`unsupported platform ${platform}/${arch}`);
  const ext = plat === 'windows' ? 'zip' : 'tar.gz';
  return { archive: `wardmap_${version}_${plat}_${cpu}.${ext}`, exe: plat === 'windows' ? 'wardmap.exe' : 'wardmap', ext };
}

function cacheDir() {
  if (process.env.WARDMAP_NPM_CACHE) return process.env.WARDMAP_NPM_CACHE;
  if (process.platform === 'win32') return path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'wardmap', 'npm');
  if (process.platform === 'darwin') return path.join(os.homedir(), 'Library', 'Caches', 'wardmap', 'npm');
  return path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache'), 'wardmap', 'npm');
}

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

// untar returns the contents of the regular file `name` in a tar stream.
function untar(tar, name) {
  for (let off = 0; off + 512 <= tar.length;) {
    const header = tar.subarray(off, off + 512);
    if (header.every((b) => b === 0)) break;
    const str = (a, b) => header.subarray(a, b).toString('utf8').replace(/\0.*$/s, '');
    const prefix = str(345, 500);
    const entry = (prefix ? `${prefix}/` : '') + str(0, 100);
    const size = parseInt(str(124, 136).trim() || '0', 8);
    const type = str(156, 157) || '0';
    const start = off + 512;
    if ((type === '0' || type === '') && (entry === name || entry === `./${name}`)) {
      return Buffer.from(tar.subarray(start, start + size));
    }
    off = start + Math.ceil(size / 512) * 512;
  }
  throw new Error(`${name} not found in the release archive`);
}

// unzip returns the contents of `name` from a zip archive (stored or deflated).
function unzip(zip, name) {
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 65557); i--) {
    if (zip.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('release archive is not a zip file');
  const count = zip.readUInt16LE(eocd + 10);
  let p = zip.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (zip.readUInt32LE(p) !== 0x02014b50) throw new Error('corrupt zip central directory');
    const method = zip.readUInt16LE(p + 10);
    const csize = zip.readUInt32LE(p + 20);
    const nlen = zip.readUInt16LE(p + 28);
    const elen = zip.readUInt16LE(p + 30);
    const clen = zip.readUInt16LE(p + 32);
    const local = zip.readUInt32LE(p + 42);
    const entry = zip.subarray(p + 46, p + 46 + nlen).toString('utf8');
    if (entry === name) {
      if (zip.readUInt32LE(local) !== 0x04034b50) throw new Error('corrupt zip entry');
      const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
      const data = zip.subarray(start, start + csize);
      if (method === 0) return Buffer.from(data);
      if (method === 8) return zlib.inflateRawSync(data);
      throw new Error(`unsupported zip compression method ${method}`);
    }
    p += 46 + nlen + elen + clen;
  }
  throw new Error(`${name} not found in the release archive`);
}

async function ensureBinary() {
  const t = target();
  const want = checksums[t.archive];
  if (!/^[0-9a-f]{64}$/.test(want || '')) throw new Error(`no checksum recorded for ${t.archive}`);
  const dir = path.join(cacheDir(), version);
  const bin = path.join(dir, t.exe);
  const marker = `${bin}.sha256`;
  if (fs.existsSync(bin) && fs.existsSync(marker) && sha256(fs.readFileSync(bin)) === fs.readFileSync(marker, 'utf8').trim()) {
    return bin;
  }
  const url = `https://github.com/${REPO}/releases/download/v${version}/${t.archive}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download ${url}: HTTP ${res.status}`);
  const archive = Buffer.from(await res.arrayBuffer());
  const got = sha256(archive);
  if (got !== want) throw new Error(`checksum mismatch for ${t.archive}: expected ${want}, got ${got}; refusing to run it`);
  const data = t.ext === 'zip' ? unzip(archive, t.exe) : untar(zlib.gunzipSync(archive), t.exe);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = `${bin}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, data, { mode: 0o755 });
  fs.renameSync(tmp, bin);
  fs.writeFileSync(marker, `${sha256(data)}\n`);
  return bin;
}

module.exports = { ensureBinary, target, untar, unzip };
