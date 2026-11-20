'use strict';
// Reads user-chosen files (open dialog, Finder "Open With", dock drop, clipboard file URLs,
// dev argv) with a size check and decodes them. Paths never leave the main process; only
// the base name is reported to the renderer.

const fs = require('node:fs');
const path = require('node:path');
const decoder = require('./decoder');

const MAX_FILES = 100;

async function readFileCapped(p) {
  let fh;
  try {
    fh = await fs.promises.open(p, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
    const st = await fh.stat();
    if (st.isDirectory()) return { error: ['unsupported_format', 'Folders cannot be scanned.'] };
    if (!st.isFile()) return { error: ['unsupported_format', 'Not a regular file.'] };
    if (st.size === 0) return { error: ['empty_input', 'The file is empty.'] };
    if (st.size > decoder.MAX_INPUT_BYTES) {
      return { error: ['too_large', `The file is larger than ${decoder.MAX_INPUT_BYTES / 1024 / 1024} MiB.`] };
    }
    const buf = Buffer.alloc(st.size);
    const { bytesRead } = await fh.read(buf, 0, st.size, 0);
    return { bytes: new Uint8Array(buf.buffer, buf.byteOffset, bytesRead) };
  } catch (e) {
    return { error: ['read_error', e.code === 'EACCES' || e.code === 'EPERM' ? 'Permission denied.' : 'The file could not be read.'] };
  } finally {
    await fh?.close().catch(() => {});
  }
}

/** Decodes files in order. Resolves ScanResult[] (one per path, at most MAX_FILES + 1). */
async function scanPaths(paths, kind) {
  const list = [...new Set(paths.filter((p) => typeof p === 'string' && path.isAbsolute(p)))];
  const take = list.slice(0, MAX_FILES);
  const results = new Array(take.length);
  let next = 0;
  // Two workers: bounds memory (each holds at most one file's bytes) and matches the
  // decoder's concurrency limit.
  const worker = async () => {
    while (next < take.length) {
      const i = next++;
      const source = { kind, name: path.basename(take[i]).slice(0, 255) };
      const r = await readFileCapped(take[i]);
      results[i] = r.error ? decoder.errorResult(source, r.error[0], r.error[1]) : await decoder.decode(r.bytes, source);
    }
  };
  await Promise.all([worker(), worker()]);
  if (list.length > take.length) {
    results.push(decoder.errorResult({ kind }, 'too_many_files',
      `Only the first ${MAX_FILES} files were scanned (${list.length - MAX_FILES} skipped).`));
  }
  return results;
}

module.exports = { scanPaths, MAX_FILES };
