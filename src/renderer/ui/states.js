// Empty, error and "no code found" states — friendly and specific, with next steps.
import { el } from './dom.js';
import { icon } from './icons.js';
import { displayText } from './text.js';

export const ERRORS = {
  unsupported_format: {
    icon: 'doc', title: 'This file type isn’t supported',
    body: 'QR Reader scans PNG, JPEG, HEIC, GIF, TIFF, WebP, BMP, AVIF, ICO and PDF files.',
    tips: ['Screenshot the code with ⌃⇧⌘4 (copies it), then press ⌘V here', 'Or export the image as PNG or JPEG first'],
  },
  empty_input: { icon: 'doc', title: 'This file is empty', body: 'There are no bytes to scan.', tips: ['Check that the file finished downloading or saving'] },
  too_large: {
    icon: 'photo', title: 'This image is too large',
    body: 'Files up to 64 MB and 300 megapixels can be scanned.',
    tips: ['Screenshot just the code with ⌃⇧⌘4, then press ⌘V', 'Or export a smaller version of the image'],
  },
  decode_error: {
    icon: 'warning', title: 'This file couldn’t be read',
    body: 'It may be damaged, incomplete, or a password-protected PDF.',
    tips: ['Open it in Preview to check it', 'Or screenshot the code with ⌃⇧⌘4 and press ⌘V'],
  },
  decoder_unavailable: {
    icon: 'shield', title: 'The scanner is switched off',
    body: 'The sandboxed decoder didn’t pass its safety self-test, so QR Reader won’t decode images.',
    tips: ['Rebuild the app with ./start.sh', 'Pasted text (⌘V) still works'],
  },
  timeout: { icon: 'clock', title: 'Scanning took too long', body: 'The image may be very large or complex.', tips: ['Crop the image closer to the code', 'Or screenshot just the code with ⌃⇧⌘4 and press ⌘V'] },
  read_error: { icon: 'folder', title: 'Couldn’t read the file', body: 'It may have moved, or QR Reader isn’t allowed to read it.', tips: ['Check the file still exists, then open it again (⌘O)'] },
  too_many_files: { icon: 'folder', title: 'Too many files', body: 'Up to 100 files are scanned at once; the rest were skipped.', tips: ['Open the remaining files in a second batch'] },
  clipboard_empty: {
    icon: 'clipboard', title: 'Nothing to scan on the clipboard',
    body: 'The clipboard has no image, file or text.',
    tips: ['Copy an image or a file in Finder, then press ⌘V', 'Screenshots: ⌃⇧⌘4 copies a selection straight to the clipboard'],
  },
};

function errorInfo(err) {
  return ERRORS[err?.code] || { icon: 'warning', title: 'Something went wrong', body: err?.message || 'The scan failed.', tips: ['Try again, or try a screenshot of the code'] };
}

function tipsList(tips) {
  return el('ul', { class: 'tips' }, tips.map((t) => el('li', {}, icon('chevronRight', { size: 11 }), el('span', { text: t }))));
}

/** Big centered message used for errors and "no code" (when there's no preview). */
export function messageState({ icon: ic, title, body, tips = [], name, tone = 'neutral', actions = [] }) {
  return el('div', { class: `message-state tone-${tone}`, role: 'status', 'data-testid': tone === 'error' ? 'error' : 'message' },
    el('div', { class: 'ms-icon' }, icon(ic, { size: 30 })),
    name ? el('div', { class: 'ms-name' }, displayText(name)) : null,
    el('h2', { class: 'ms-title', text: title }),
    body ? el('p', { class: 'ms-body', text: body }) : null,
    tips.length ? tipsList(tips) : null,
    actions.length ? el('div', { class: 'ms-actions' }, actions) : null);
}

export function errorState(result, actions = []) {
  const info = errorInfo(result.error);
  return messageState({ ...info, name: result.source?.name && result.source.name !== 'Clipboard image' ? result.source.name : null, tone: 'error', actions });
}

export function noCodeState(result) {
  const pdf = result.image?.format === 'pdf';
  const tips = [
    'Crop or zoom closer so the code fills more of the image',
    'Make sure the whole code is visible, including the white border around it',
    'Blurry or angled photos: try a sharper, straight-on shot',
  ];
  if (pdf) tips.unshift(`Only the first ${Math.min(result.image.pages || 1, 10)} page${(result.image.pages || 1) > 1 ? 's were' : ' was'} scanned`);
  return el('div', { class: 'nocode', 'data-testid': 'no-codes' },
    messageState({ icon: 'qr', title: 'No code found', body: 'QR Reader looked for QR, Aztec, Data Matrix, PDF417 and barcodes, and tried inverted, enhanced and enlarged versions of the image.', tips }));
}

export function errorMessage(err) { return errorInfo(err); }
