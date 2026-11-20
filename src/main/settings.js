'use strict';
// Settings only (never content): a tiny JSON file in userData.

const fs = require('node:fs');
const path = require('node:path');
const { app } = require('electron');

const DEFAULTS = Object.freeze({ autoScanClipboard: true });
const VALIDATORS = { autoScanClipboard: (v) => typeof v === 'boolean' };

let current = { ...DEFAULTS };
const listeners = new Set();

const file = () => path.join(app.getPath('userData'), 'settings.json');

function load() {
  try {
    const raw = fs.readFileSync(file(), 'utf8');
    if (raw.length > 4096) return;
    const j = JSON.parse(raw);
    for (const k of Object.keys(DEFAULTS)) {
      if (j && Object.hasOwn(j, k) && VALIDATORS[k](j[k])) current[k] = j[k];
    }
  } catch { /* missing or invalid → defaults */ }
}

function save() {
  try {
    fs.mkdirSync(path.dirname(file()), { recursive: true, mode: 0o700 });
    const tmp = `${file()}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(current), { mode: 0o600 });
    fs.renameSync(tmp, file());
  } catch { /* settings are best-effort */ }
}

const isKey = (k) => typeof k === 'string' && Object.hasOwn(DEFAULTS, k);
const get = () => ({ ...current });

function set(key, value) {
  if (!isKey(key) || !VALIDATORS[key](value)) throw new Error('invalid setting');
  if (current[key] === value) return get();
  current = { ...current, [key]: value };
  save();
  for (const l of listeners) l(get());
  return get();
}

const onChange = (fn) => { listeners.add(fn); return () => listeners.delete(fn); };

module.exports = { load, get, set, isKey, onChange };
