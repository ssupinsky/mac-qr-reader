// `geo:` URIs (RFC 5870, PAYLOADS.md §7.1) incl. the Android `?q=…&z=…` extension.

import { createReport, hasPrefix, prep, parseQuery, pctDecode, qget, encodeComponent } from './util.js';
import { hasOwn, setOwn } from '../dict.js';

const COORD = /^-?\d+(?:\.\d+)?$/;

/** 40.71872 → `40°43′07.4″N`. */
export function toDms(value, isLat) {
  const hemi = isLat ? (value < 0 ? 'S' : 'N') : value < 0 ? 'W' : 'E';
  let abs = Math.abs(value);
  let deg = Math.floor(abs);
  let min = Math.floor((abs - deg) * 60);
  let sec = Math.round(((abs - deg) * 60 - min) * 60 * 10) / 10;
  if (sec >= 60) { sec = 0; min += 1; }
  if (min >= 60) { min = 0; deg += 1; }
  return `${deg}°${String(min).padStart(2, '0')}′${sec.toFixed(1).padStart(4, '0')}″${hemi}`;
}

const fixed6 = (n) => (Object.is(n, -0) ? 0 : n).toFixed(6);

export const geo = {
  id: 'geo',
  label: 'geo',
  detect(text) {
    return hasPrefix(prep(text), 'geo:');
  },
  parse(text, ctx = {}) {
    const r = createReport(ctx);
    const rest = prep(text).slice(4);
    const qi = rest.indexOf('?');
    const path = qi < 0 ? rest : rest.slice(0, qi);
    const query = parseQuery(qi < 0 ? '' : rest.slice(qi + 1), { plusAsSpace: true });
    const [coordPart, ...paramParts] = path.split(';');
    const coords = coordPart.split(',');

    const data = { format: 'geo' };
    const params = {};
    const order = [];
    for (const p of paramParts) {
      const eq = p.indexOf('=');
      const name = (eq < 0 ? p : p.slice(0, eq)).toLowerCase();
      if (!name) continue;
      order.push(name);
      setOwn(params, name, eq < 0 ? '' : pctDecode(p.slice(eq + 1)).value);
    }

    let valid = coords.length >= 2 && coords.length <= 3 && coords.every((c) => COORD.test(c));
    if (valid) {
      data.lat = Number(coords[0]) + 0; // + 0 turns -0 into 0
      data.lon = Number(coords[1]) + 0;
      if (coords[2] !== undefined) data.alt = Number(coords[2]) + 0;
    }
    if (hasOwn(params, 'crs')) data.crs = params.crs;
    if (hasOwn(params, 'u')) {
      if (/^\d+(\.\d+)?$/.test(params.u)) data.uncertainty = Number(params.u);
      else r.warn('caution', `Invalid uncertainty "${params.u}"`);
    }
    if (order.includes('crs') && order.indexOf('crs') !== 0) r.warn('info', 'Unusual parameter order (RFC 5870 requires crs first)');
    const extraParams = Object.keys(params).filter((k) => k !== 'crs' && k !== 'u');
    if (extraParams.length) data.params = Object.fromEntries(extraParams.map((k) => [k, params[k]]));

    const wgs84 = !data.crs || data.crs.toLowerCase() === 'wgs84';
    if (!wgs84) r.warn('caution', `Unknown coordinate system "${data.crs}" — the numbers may not be latitude/longitude`);

    // Android query: q=<address> or q=<lat>,<lon>(<label>); z=<zoom>.
    const q = qget(query, 'q');
    const z = qget(query, 'z');
    if (q !== undefined) {
      const m = /^(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)(?:\s*\((.*)\))?$/s.exec(q.trim());
      if (m) {
        if (!valid || (data.lat === 0 && data.lon === 0)) {
          data.lat = Number(m[1]) + 0;
          data.lon = Number(m[2]) + 0;
          valid = true;
        }
        if (m[3]) data.label = m[3];
      } else {
        data.query = q;
        data.label = q;
      }
    }
    if (z !== undefined) data.zoom = /^\d+$/.test(z) ? Number(z) : z;

    if (valid && wgs84 && (Math.abs(data.lat) > 90 || Math.abs(data.lon) > 180)) {
      r.warn('caution', 'Invalid coordinates (latitude must be within ±90°, longitude within ±180°)');
      valid = false;
    }
    if (!valid && !data.query && !(coords.length >= 2 && coords.every((c) => COORD.test(c)))) {
      r.warn('caution', 'Invalid coordinates — this location cannot be read');
    }
    data.valid = valid;

    const placeOnly = data.query && data.lat === 0 && data.lon === 0;
    const ll = valid ? `${fixed6(data.lat)},${fixed6(data.lon)}` : null;
    if (valid && !placeOnly) {
      r.field('Coordinates', `${fixed6(data.lat)}, ${fixed6(data.lon)}`, { mono: true, copy: true, check: false });
      if (wgs84) r.field('As degrees', `${toDms(data.lat, true)} ${toDms(data.lon, false)}`, { mono: true, check: false });
      if (Math.abs(data.lat) === 90) r.warn('info', 'At a pole the longitude is irrelevant');
    }
    r.field('Altitude', data.alt !== undefined ? `${data.alt} m` : '', { check: false });
    r.field('Accuracy', data.uncertainty !== undefined ? `± ${data.uncertainty} m` : '', { check: false });
    r.field('Coordinate system', data.crs);
    r.field(data.query ? 'Place' : 'Label', data.label);
    r.field('Zoom', data.zoom);

    if (valid || data.query) {
      const qs = data.label ? `&q=${encodeComponent(data.label)}` : '';
      const apple = placeOnly || !ll ? `https://maps.apple.com/?q=${encodeComponent(data.query)}` : `https://maps.apple.com/?ll=${ll}${qs}`;
      const google = `https://www.google.com/maps/search/?api=1&query=${placeOnly || !ll ? encodeComponent(data.query) : ll}`;
      if (wgs84) {
        data.appleMapsUrl = apple;
        data.googleMapsUrl = google;
        r.warn('info', 'Opening a map shows this place to that map service');
        r.open('Open in Apple Maps…', apple);
        r.open('Open in Google Maps…', google);
        r.copy('Copy Apple Maps link', apple);
      }
      if (ll && !placeOnly) r.copy('Copy coordinates', ll);
    }

    const where = placeOnly ? data.query : valid ? `${fixed6(data.lat)}, ${fixed6(data.lon)}` : 'invalid coordinates';
    const label = data.label && !placeOnly ? ` (${data.label})` : '';
    return r.result({ type: 'geo', title: 'Location', summary: `Location: ${where}${label}`, data });
  },
};
