// Calendar events (PAYLOADS.md §8): an iCalendar subset — VEVENT (and VTODO summary),
// DATE / UTC / floating / TZID date-times, DURATION, RRULE humanising, VALARM checks,
// plus .ics generation for "Add to Calendar".

import { createReport, hasPrefix, prep, toCrlf, embeddedUrlWarnings, extractUrls, sanitizeFileName, truncate } from './util.js';
import { readContentLines, param, unescapeText, splitStructured } from './contentline.js';
import { stripTrailing } from '../strings.js';

// ---------------------------------------------------------------------------
// Date/time handling
// ---------------------------------------------------------------------------

const pad = (n, w = 2) => String(n).padStart(w, '0');

/** Validates an IANA zone name; returns a formatter or null. */
function zoneFormatter(tz) {
  try {
    return new Intl.DateTimeFormat('en-US', {
      timeZone: tz, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric',
      hour: 'numeric', minute: 'numeric', second: 'numeric',
    });
  } catch {
    return null;
  }
}

/** Offset (ms) of `tz` at the UTC instant `utcMs`. */
function zoneOffset(fmt, utcMs) {
  const p = Object.fromEntries(fmt.formatToParts(new Date(utcMs)).map((x) => [x.type, x.value]));
  const asUtc = Date.UTC(Number(p.year), Number(p.month) - 1, Number(p.day), Number(p.hour) % 24, Number(p.minute), Number(p.second));
  return asUtc - Math.floor(utcMs / 1000) * 1000;
}

/** Wall-clock time in `tz` → UTC ms (two-pass offset resolution handles DST edges). */
function zonedToUtc(fmt, wallMs) {
  const off1 = zoneOffset(fmt, wallMs);
  let utc = wallMs - off1;
  const off2 = zoneOffset(fmt, utc);
  if (off2 !== off1) utc = wallMs - off2;
  return utc;
}

const isoUtc = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const isoWall = (ms) => new Date(ms).toISOString().slice(0, 19);
const isoDate = (ms) => new Date(ms).toISOString().slice(0, 10);

/**
 * Parses a DTSTART/DTEND value (lenient: ISO `-`/`:` separators accepted).
 * @returns {null | { kind: 'date'|'utc'|'floating'|'zoned'|'zone-unknown', wallMs: number,
 *   utcMs: number|null, tzid?: string, iso: string, local?: string }}
 */
export function parseIcalDateTime(value, params = {}) {
  const v = String(value).trim().replace(/[-:]/g, '');
  const m = /^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})?(?:\.\d+)?(Z)?)?$/.exec(v);
  if (!m) return null;
  const [y, mo, d, h, mi, s, z] = [m[1], m[2], m[3], m[4], m[5], m[6], m[7]];
  const wallMs = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h || 0), Number(mi || 0), Number(s || 0));
  const check = new Date(wallMs);
  if (check.getUTCMonth() !== Number(mo) - 1 || check.getUTCDate() !== Number(d) || Number(h || 0) > 23 || Number(mi || 0) > 59 || Number(s || 0) > 60) return null;
  const valueType = (params.VALUE?.[0] || '').toUpperCase();
  if (h === undefined || valueType === 'DATE') return { kind: 'date', wallMs, utcMs: null, iso: isoDate(wallMs) };
  if (z) return { kind: 'utc', wallMs, utcMs: wallMs, iso: isoUtc(wallMs) };
  const tzid = params.TZID?.[0]?.replace(/^\//, '');
  if (tzid) {
    const fmt = zoneFormatter(tzid);
    if (fmt) {
      const utcMs = zonedToUtc(fmt, wallMs);
      return { kind: 'zoned', wallMs, utcMs, tzid, iso: isoUtc(utcMs), local: isoWall(wallMs) };
    }
    return { kind: 'zone-unknown', wallMs, utcMs: null, tzid, iso: isoWall(wallMs), local: isoWall(wallMs) };
  }
  return { kind: 'floating', wallMs, utcMs: null, iso: isoWall(wallMs) };
}

/** ISO 8601 duration (`P1W`, `PT1H30M`, `-PT15M`) → ms, or null. */
export function parseDuration(value) {
  const m = /^([+-])?P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(String(value).trim());
  if (!m || value.trim().replace(/^[+-]/, '') === 'P' || /T$/.test(value.trim())) return null;
  const [, sign, w, d, h, mi, s] = m;
  const ms = ((Number(w || 0) * 7 + Number(d || 0)) * 86400 + Number(h || 0) * 3600 + Number(mi || 0) * 60 + Number(s || 0)) * 1000;
  return sign === '-' ? -ms : ms;
}

/** Shifts a parsed date-time by `ms` (keeps its kind). */
function shift(dt, ms) {
  const wallMs = dt.wallMs + ms;
  if (dt.kind === 'date') return { ...dt, wallMs, iso: isoDate(wallMs) };
  if (dt.kind === 'utc') return { ...dt, wallMs, utcMs: wallMs, iso: isoUtc(wallMs) };
  if (dt.kind === 'zoned') {
    const utcMs = dt.utcMs + ms;
    return { ...dt, utcMs, wallMs, iso: isoUtc(utcMs), local: isoWall(wallMs) };
  }
  return { ...dt, wallMs, iso: isoWall(wallMs), local: dt.local ? isoWall(wallMs) : undefined };
}

const DATE_FMT = { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' };
const TIME_FMT = { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' };

function fmt(ms, opts, timeZone) {
  try {
    return new Intl.DateTimeFormat('en-GB', { ...opts, ...(timeZone ? { timeZone } : {}) }).format(new Date(ms));
  } catch {
    return new Date(ms).toISOString();
  }
}

/** "Tue 1 Dec 2026, 09:00–09:30 (Europe/Berlin)" style description. */
function describeWhen(start, end) {
  if (start.kind === 'date') {
    const startText = fmt(start.wallMs, DATE_FMT, 'UTC');
    if (!end) return `${startText} (all day)`;
    const days = Math.round((end.wallMs - start.wallMs) / 86400000);
    if (days <= 1) return `${startText} (all day)`;
    const last = fmt(end.wallMs - 86400000, DATE_FMT, 'UTC');
    return `${startText} – ${last} (${days} days)`;
  }
  // Show wall time in the event's own zone (UTC for Z times, as written for floating).
  const zone = start.kind === 'zoned' ? start.tzid : 'UTC';
  const ms = start.kind === 'zoned' || start.kind === 'utc' ? start.utcMs : start.wallMs;
  const endMs = end ? (end.utcMs ?? end.wallMs) : null;
  let out = `${fmt(ms, DATE_FMT, zone)}, ${fmt(ms, TIME_FMT, zone)}`;
  if (endMs !== null) {
    const sameDay = fmt(ms, DATE_FMT, zone) === fmt(endMs, DATE_FMT, zone);
    out += sameDay ? `–${fmt(endMs, TIME_FMT, zone)}` : ` – ${fmt(endMs, DATE_FMT, zone)}, ${fmt(endMs, TIME_FMT, zone)}`;
  }
  if (start.kind === 'zoned') out += ` (${start.tzid})`;
  else if (start.kind === 'utc') out += ' (UTC)';
  else if (start.kind === 'zone-unknown') out += ` (${start.tzid})`;
  else out += ' (local time)';
  return out;
}

/** Same moment in the viewer's own time zone (absolute times only). */
function describeLocal(start, end) {
  if (start.utcMs === null) return null;
  let out = `${fmt(start.utcMs, DATE_FMT)}, ${fmt(start.utcMs, TIME_FMT)}`;
  if (end?.utcMs != null) out += `–${fmt(end.utcMs, TIME_FMT)}`;
  return out;
}

// ---------------------------------------------------------------------------
// RRULE
// ---------------------------------------------------------------------------

const DAY_NAMES = { MO: 'Mon', TU: 'Tue', WE: 'Wed', TH: 'Thu', FR: 'Fri', SA: 'Sat', SU: 'Sun' };
const FREQ_WORDS = {
  SECONDLY: ['Every second', 'seconds'], MINUTELY: ['Every minute', 'minutes'], HOURLY: ['Hourly', 'hours'],
  DAILY: ['Daily', 'days'], WEEKLY: ['Weekly', 'weeks'], MONTHLY: ['Monthly', 'months'], YEARLY: ['Yearly', 'years'],
};

/** Parses and humanises an RRULE ("Weekly on Tue, 10 times"). */
export function describeRrule(value) {
  const rule = {};
  for (const part of String(value).split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) rule[part.slice(0, eq).toUpperCase()] = part.slice(eq + 1);
  }
  const freq = (rule.FREQ || '').toUpperCase();
  const words = FREQ_WORDS[freq];
  const interval = Number(rule.INTERVAL || 1);
  let text = words ? (interval > 1 ? `Every ${interval} ${words[1]}` : words[0]) : `Repeats (${value})`;
  if (rule.BYDAY) {
    const days = rule.BYDAY.split(',').map((d) => {
      const m = /^([+-]?\d+)?([A-Z]{2})$/i.exec(d);
      return m ? `${m[1] ? `${m[1]} ` : ''}${DAY_NAMES[m[2].toUpperCase()] || m[2]}` : d;
    });
    text += ` on ${days.join(', ')}`;
  }
  if (rule.BYMONTHDAY) text += ` on day ${rule.BYMONTHDAY}`;
  if (rule.COUNT) text += `, ${rule.COUNT} times`;
  if (rule.UNTIL) {
    const until = parseIcalDateTime(rule.UNTIL);
    text += `, until ${until ? until.iso.slice(0, 10) : rule.UNTIL}`;
  }
  if (!rule.COUNT && !rule.UNTIL && words) text += ', forever';
  return { rule, freq, text };
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/** Splits content lines into components (VEVENT/VTODO) with their VALARMs. */
function components(lines) {
  const out = [];
  const stack = [];
  for (const cl of lines) {
    if (cl.name === 'BEGIN') {
      const kind = cl.value.trim().toUpperCase();
      const comp = { kind, props: [], alarms: [] };
      if (kind === 'VALARM' && stack.length) stack.at(-1).alarms.push(comp);
      else if (kind === 'VEVENT' || kind === 'VTODO') out.push(comp);
      stack.push(comp);
    } else if (cl.name === 'END') {
      const kind = cl.value.trim().toUpperCase();
      const idx = stack.findLastIndex((c) => c.kind === kind);
      if (idx >= 0) {
        for (const c of stack.slice(idx)) c.closed = true;
        stack.length = idx;
      }
    } else if (stack.length) {
      stack.at(-1).props.push(cl);
    }
  }
  return out;
}

const first = (comp, name) => comp.props.find((p) => p.name === name);
const textOf = (comp, name) => {
  const p = first(comp, name);
  return p ? unescapeText(p.value) : undefined;
};

/** Parses one VEVENT/VTODO into plain data; warnings go to `r` (prefixed). */
function parseComponent(comp, r, ctx, who, linkLabel) {
  const P = `${who} `;
  const ev = { kind: comp.kind === 'VTODO' ? 'todo' : 'event' };
  ev.summary = textOf(comp, 'SUMMARY');
  ev.location = textOf(comp, 'LOCATION');
  ev.description = textOf(comp, 'DESCRIPTION');
  ev.url = first(comp, 'URL')?.value.trim();
  ev.uid = textOf(comp, 'UID');
  ev.status = textOf(comp, 'STATUS');
  const cats = first(comp, 'CATEGORIES');
  if (cats) ev.categories = splitStructured(cats.value, ',').map(unescapeText);

  const orgProp = first(comp, 'ORGANIZER');
  if (orgProp) ev.organizer = { address: orgProp.value.replace(/^mailto:/i, ''), name: param(orgProp, 'CN') };
  ev.attendees = comp.props.filter((p) => p.name === 'ATTENDEE').map((p) => ({ address: p.value.replace(/^mailto:/i, ''), name: param(p, 'CN') }));
  ev.attachments = comp.props.filter((p) => p.name === 'ATTACH').map((p) => p.value.trim());

  const geoProp = first(comp, 'GEO');
  if (geoProp) {
    const [lat, lon] = geoProp.value.split(/[;,]/).map(Number);
    if (Number.isFinite(lat) && Number.isFinite(lon)) ev.geo = { lat, lon };
  }

  const dtStartProp = first(comp, 'DTSTART');
  const dtEndProp = first(comp, comp.kind === 'VTODO' ? 'DUE' : 'DTEND');
  const durProp = first(comp, 'DURATION');
  const start = dtStartProp ? parseIcalDateTime(dtStartProp.value, dtStartProp.params) : null;
  let end = dtEndProp ? parseIcalDateTime(dtEndProp.value, dtEndProp.params) : null;
  if (dtStartProp && !start) r.warn('caution', `${P}start time "${truncate(dtStartProp.value, 30)}" is not a valid date`);
  if (dtEndProp && !end) r.warn('caution', `${P}end time "${truncate(dtEndProp.value, 30)}" is not a valid date`);
  if (!end && start && durProp) {
    const ms = parseDuration(durProp.value);
    if (ms === null) r.warn('caution', `${P}invalid duration "${truncate(durProp.value, 30)}"`);
    else {
      end = shift(start, ms);
      ev.duration = durProp.value.trim();
    }
  }
  if (!end && start?.kind === 'date' && comp.kind === 'VEVENT') end = shift(start, 86400000);

  if (start) {
    ev.allDay = start.kind === 'date';
    ev.start = start.iso;
    ev.startKind = start.kind;
    if (start.tzid) ev.tzid = start.tzid;
    if (start.local) ev.startLocal = start.local;
    if (start.kind === 'floating') r.warn('info', `${P}time has no time zone ("floating") — it means local time wherever you are`);
    if (start.kind === 'zone-unknown') r.warn('info', `${P}time zone "${start.tzid}" is not a standard (IANA) name; the time is shown as written`);
  } else if (comp.kind === 'VEVENT') {
    r.warn('caution', `${P}has no start time`);
  }
  if (end) {
    ev.end = end.iso;
    if (end.local) ev.endLocal = end.local;
    if (ev.allDay) ev.days = Math.round((end.wallMs - start.wallMs) / 86400000);
    const a = start?.utcMs ?? start?.wallMs;
    const b = end.utcMs ?? end.wallMs;
    if (start && b < a) r.warn('caution', `${P}ends before it starts — invalid`);
  }
  ev.when = start ? describeWhen(start, end) : undefined;
  ev.whenLocal = start ? describeLocal(start, end) : undefined;

  if (start) {
    const at = start.utcMs ?? start.wallMs;
    const now = ctx.now ?? Date.now();
    if (at - now > 5 * 365.25 * 86400000) r.warn('info', `${P}starts more than 5 years from now`);
  }

  const rruleProp = first(comp, 'RRULE');
  if (rruleProp) {
    const rr = describeRrule(rruleProp.value);
    ev.rrule = rr.rule;
    ev.recurrence = rr.text;
    if (['SECONDLY', 'MINUTELY', 'HOURLY'].includes(rr.freq) && !rr.rule.COUNT && !rr.rule.UNTIL) {
      r.warn('caution', `${P}repeats very frequently, forever (${rr.freq.toLowerCase()})`);
    }
  }

  ev.alarms = comp.alarms.map((a) => ({
    action: (textOf(a, 'ACTION') || '').toUpperCase(),
    trigger: first(a, 'TRIGGER')?.value,
  }));
  for (const a of ev.alarms) {
    if (a.action === 'EMAIL') r.warn('caution', `${P}has an alarm that sends email`);
    if (a.action === 'PROCEDURE') r.warn('caution', `${P}has an alarm that runs a procedure (deprecated, potentially unsafe)`);
  }
  if (ev.attendees.length > 20) r.warn('info', `${P}has ${ev.attendees.length} attendees`);

  // Embedded links.
  if (ev.url) r.warnAll(embeddedUrlWarnings(ev.url, ctx, linkLabel('Link')));
  for (const att of ev.attachments) if (/^[a-z][a-z0-9+.-]*:/i.test(att)) r.warnAll(embeddedUrlWarnings(att, ctx, linkLabel('Attachment')));
  for (const u of extractUrls(ev.description)) r.warnAll(embeddedUrlWarnings(u, ctx, linkLabel('Link in description')));
  for (const u of extractUrls(ev.location)) r.warnAll(embeddedUrlWarnings(u, ctx, linkLabel('Link in location')));
  return ev;
}

function present(r, ev, L) {
  r.field(L('Title'), ev.summary, { singleLine: true });
  r.field(L('When'), ev.when, { check: false });
  r.field(L('Your time'), ev.whenLocal, { check: false });
  r.field(L('Repeats'), ev.recurrence, { check: false });
  r.field(L('Location'), ev.location);
  if (ev.geo) r.field(L('Coordinates'), `${ev.geo.lat}, ${ev.geo.lon}`, { mono: true, check: false });
  r.field(L('Description'), ev.description);
  r.field(L('Link'), ev.url, { mono: true, copy: true });
  if (ev.organizer) r.field(L('Organizer'), ev.organizer.name ? `${ev.organizer.name} <${ev.organizer.address}>` : ev.organizer.address);
  if (ev.attendees.length) {
    r.field(L('Attendees'), ev.attendees.length <= 5
      ? ev.attendees.map((a) => a.name || a.address).join(', ')
      : `${ev.attendees.length} people`);
  }
  for (const a of ev.attachments) r.field(L('Attachment'), a, { mono: true });
  if (ev.alarms.length) r.field(L('Alarms'), ev.alarms.map((a) => `${a.action.toLowerCase() || 'alarm'}${a.trigger ? ` (${a.trigger})` : ''}`).join(', '), { check: false });
  r.field(L('Status'), ev.status);
  r.field(L('Categories'), ev.categories?.join(', '));
}

export const ical = {
  id: 'ical',
  label: 'calendar',
  detect(text) {
    const t = prep(text);
    return hasPrefix(t, 'BEGIN:VCALENDAR') || hasPrefix(t, 'BEGIN:VEVENT');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const t = prep(text);
    const isCalendar = hasPrefix(t, 'BEGIN:VCALENDAR');
    const comps = components(readContentLines(t));
    const multi = comps.length > 1;
    const events = comps.map((c, i) => parseComponent(
      c, r, ctx, multi ? `Event ${i + 1}` : 'Event', (l) => (multi ? `Event ${i + 1}: ${l.toLowerCase()}` : l),
    ));
    if (!comps.length) r.warn('caution', 'No event found in this calendar data');
    if (comps.some((c) => !c.closed)) r.warn('info', 'The calendar data seems truncated (missing END line)');
    if (multi) r.warn('info', `This code contains ${comps.length} calendar entries`);

    events.forEach((ev, i) => present(r, ev, (l) => (multi ? `${i + 1}. ${l}` : l)));

    const primary = events[0] || { kind: 'event', attendees: [], attachments: [], alarms: [] };
    const data = { format: isCalendar ? 'vcalendar' : 'vevent', ...primary, ...(multi ? { events } : {}) };

    if (events.length) {
      let ics = stripTrailing(toCrlf(t), '\r\n');
      if (!isCalendar) ics = `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//QR Reader//EN\r\n${ics}\r\nEND:VCALENDAR`;
      data.ics = `${ics}\r\n`;
      r.save('Add to Calendar (.ics)…', data.ics, `${sanitizeFileName(primary.summary, 'event')}.ics`, 'ics');
    }
    if (primary.summary) r.copy('Copy title', primary.summary);
    if (primary.location) r.copy('Copy location', primary.location);

    const kind = primary.kind === 'todo' ? 'To-do' : 'Event';
    const title = multi ? `${events.length} calendar entries` : primary.kind === 'todo' ? 'To-do' : 'Calendar event';
    const summary = `${kind}: ${primary.summary || 'Untitled'}${primary.when ? ` — ${primary.when}` : ''}`;
    return r.result({ type: 'event', title, summary, data });
  },
};
