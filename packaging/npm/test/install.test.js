// Tests for the npm launcher against GoReleaser snapshot archives.
// Run: WARDMAP_DIST=dist node --test packaging/npm/test/install.test.js
// Needs lib/release.json; the test writes its own into a temporary copy.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const cp = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');

const dist = process.env.WARDMAP_DIST || path.join(__dirname, '..', '..', '..', 'dist');
const files = fs.readdirSync(dist);
const hostPlat = { darwin: 'darwin', linux: 'linux', win32: 'windows' }[process.platform];
const hostCpu = { x64: 'amd64', arm64: 'arm64' }[process.arch];
const hostArchive = files.find((f) => f.endsWith(`_${hostPlat}_${hostCpu}.${hostPlat === 'windows' ? 'zip' : 'tar.gz'}`));
const version = hostArchive.replace(/^wardmap_/, '').replace(/_[a-z]+_[a-z0-9]+\.(tar\.gz|zip)$/, '');
const archive = fs.readFileSync(path.join(dist, hostArchive));
const good = crypto.createHash('sha256').update(archive).digest('hex');

// load returns a fresh copy of the launcher with the given pinned checksum.
function load(pin) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wardmap-npm-'));
  fs.cpSync(path.join(__dirname, '..', 'lib'), path.join(dir, 'lib'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'lib', 'release.json'), JSON.stringify({ version, checksums: { [hostArchive]: pin } }));
  process.env.WARDMAP_NPM_CACHE = fs.mkdtempSync(path.join(os.tmpdir(), 'wardmap-cache-'));
  return require(path.join(dir, 'lib', 'install.js'));
}

function serve(buf) {
  global.fetch = async () => ({ ok: true, status: 200, arrayBuffer: async () => buf });
}

test('extracts the binary from tar.gz and zip archives', () => {
  const m = load(good);
  const tgz = files.find((f) => f.endsWith('_linux_arm64.tar.gz'));
  const elf = m.untar(zlib.gunzipSync(fs.readFileSync(path.join(dist, tgz))), 'wardmap');
  assert.deepStrictEqual([...elf.subarray(0, 4)], [0x7f, 0x45, 0x4c, 0x46]);
  const zip = files.find((f) => f.endsWith('_windows_amd64.zip'));
  assert.strictEqual(m.unzip(fs.readFileSync(path.join(dist, zip)), 'wardmap.exe').subarray(0, 2).toString(), 'MZ');
  assert.throws(() => m.target('freebsd', 'x64'), /unsupported platform/);
});

test('runs a genuine download and caches it', async () => {
  const m = load(good);
  serve(archive);
  const bin = await m.ensureBinary();
  assert.ok(cp.execFileSync(bin, ['version']).toString().includes(version.split('-')[0]));
  global.fetch = async () => { throw new Error('should use the cache'); };
  assert.strictEqual(await m.ensureBinary(), bin);
});

test('refuses a tampered download', async () => {
  const m = load(good);
  serve(Buffer.concat([archive, Buffer.from('x')]));
  await assert.rejects(m.ensureBinary(), /checksum mismatch/);
});

test('refuses when the pinned checksum is wrong or missing', async () => {
  serve(archive);
  await assert.rejects(load('0'.repeat(64)).ensureBinary(), /checksum mismatch/);
  await assert.rejects(load('not-a-hash').ensureBinary(), /no checksum recorded/);
});

test('re-fetches a tampered cached binary instead of running it', async () => {
  const m = load(good);
  serve(archive);
  const bin = await m.ensureBinary();
  fs.appendFileSync(bin, 'tamper');
  let fetched = false;
  global.fetch = async () => { fetched = true; return { ok: true, status: 200, arrayBuffer: async () => archive }; };
  await m.ensureBinary();
  assert.ok(fetched, 'a cached binary whose hash changed must be replaced');
});
