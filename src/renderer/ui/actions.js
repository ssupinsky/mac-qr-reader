// User actions that cross the IPC boundary. Main validates everything again; links only
// open after main's native confirmation dialog. Nothing here ever opens automatically.
import { toast } from './toast.js';

const qr = window.qr;

export async function copy(text, { sensitive = false, what = '' } = {}) {
  try {
    await qr.copyText(String(text), { sensitive: !!sensitive });
    toast(sensitive ? `${what ? `${what} copied` : 'Copied'} — clipboard clears in 60 s` : (what ? `${what} copied` : 'Copied'),
      { icon: sensitive ? 'lock' : 'check', ms: sensitive ? 2600 : 1600 });
  } catch (e) {
    toast(`Couldn’t copy: ${e?.message || e}`, { icon: 'warning', tone: 'warn' });
  }
}

export async function openLink(url) {
  try {
    const r = await qr.openExternal(String(url));
    if (r && r.opened === false && r.reason) toast(r.reason, { icon: 'info', tone: 'muted' });
  } catch (e) {
    toast(`Couldn’t open: ${e?.message || e}`, { icon: 'warning', tone: 'warn' });
  }
}

/** @param {{suggestedName: string, kind: 'vcf'|'ics'|'txt'|'bin'}} saveAs @param {string} value text, or base64 for kind 'bin' */
export async function save(saveAs, value) {
  try {
    const opts = { suggestedName: saveAs.suggestedName, kind: saveAs.kind };
    if (saveAs.kind === 'bin') opts.bytesBase64 = value; else opts.text = value;
    const r = await qr.saveText(opts);
    if (r?.saved) toast('Saved', { icon: 'save' });
  } catch (e) {
    toast(`Couldn’t save: ${e?.message || e}`, { icon: 'warning', tone: 'warn' });
  }
}

/** Runs an Analysis action ({kind, label, value, sensitive, saveAs}). */
export function runAction(a) {
  if (a.kind === 'copy') return copy(a.value, { sensitive: a.sensitive, what: copyNoun(a.label, a.sensitive) });
  if (a.kind === 'open') return openLink(a.value);
  if (a.kind === 'save' && a.saveAs) return save(a.saveAs, a.value);
  return undefined;
}

/** "Copy password" → "Password". */
export function copyNoun(label, sensitive) {
  const m = /^Copy\s+(.+)$/i.exec(String(label || ''));
  if (!m) return sensitive ? 'Copied' : '';
  const n = m[1].replace(/\s*\(.*\)$/, '');
  return n.charAt(0).toUpperCase() + n.slice(1);
}
