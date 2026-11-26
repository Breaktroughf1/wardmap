#!/usr/bin/env node
// Runs the Wardmap binary for this platform, fetching and verifying it on
// first use (see lib/install.js). Exit codes are Wardmap's own (2 also covers launcher errors).
'use strict';
const { spawnSync } = require('node:child_process');
const { ensureBinary } = require('../lib/install.js');

(async () => {
  let bin;
  try {
    bin = await ensureBinary();
  } catch (err) {
    process.stderr.write(`wardmap (npm): ${err.message}\n`);
    process.exit(2);
  }
  const r = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' });
  if (r.error) {
    process.stderr.write(`wardmap (npm): ${r.error.message}\n`);
    process.exit(2);
  }
  process.exit(r.status === null ? 2 : r.status);
})();
