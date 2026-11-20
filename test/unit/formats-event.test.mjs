import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, assertWarning, assertNoWarning, field, action, fuzz } from './_formats-helper.mjs';
import { parseIcalDateTime, parseDuration, describeRrule } from '../../src/renderer/parsers/formats/event.js';

test('VEVENT with UTC times; "+" kept literally', () => {
  const a = analyze('BEGIN:VEVENT\nSUMMARY:Summer+Vacation!\nDTSTART:20180601T070000Z\nDTEND:20180831T070000Z\nEND:VEVENT');
  assert.equal(a.type, 'event');
  assert.equal(a.data.format, 'vevent');
  assert.equal(a.data.summary, 'Summer+Vacation!');
  assert.equal(a.data.start, '2018-06-01T07:00:00Z');
  assert.equal(a.data.end, '2018-08-31T07:00:00Z');
  assert.equal(a.data.allDay, false);
  const save = action(a, /Calendar/);
  assert.equal(save.saveAs.kind, 'ics');
  assert.equal(save.saveAs.suggestedName, 'Summer+Vacation!.ics');
  assert.ok(save.value.startsWith('BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//QR Reader//EN\r\nBEGIN:VEVENT\r\n'));
  assert.ok(save.value.endsWith('END:VEVENT\r\nEND:VCALENDAR\r\n'));
});

test('VCALENDAR with TZID, DURATION, RRULE and escaped text', () => {
  const a = analyze('BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nSUMMARY:Team sync\\, weekly\r\nDTSTART;TZID=Europe/Berlin:20261201T090000\r\nDURATION:PT30M\r\nRRULE:FREQ=WEEKLY;BYDAY=TU;COUNT=10\r\nLOCATION:Room 4\\; 2nd floor\r\nEND:VEVENT\r\nEND:VCALENDAR');
  assert.equal(a.data.format, 'vcalendar');
  assert.equal(a.data.summary, 'Team sync, weekly');
  assert.equal(a.data.start, '2026-12-01T08:00:00Z');
  assert.equal(a.data.startLocal, '2026-12-01T09:00:00');
  assert.equal(a.data.tzid, 'Europe/Berlin');
  assert.equal(a.data.end, '2026-12-01T08:30:00Z');
  assert.deepEqual(a.data.rrule, { FREQ: 'WEEKLY', BYDAY: 'TU', COUNT: '10' });
  assert.equal(a.data.recurrence, 'Weekly on Tue, 10 times');
  assert.equal(a.data.location, 'Room 4; 2nd floor');
  assert.match(field(a, 'When').value, /1 Dec 2026, 09:00–09:30 \(Europe\/Berlin\)/);
  assert.ok(action(a, /Calendar/).value.startsWith('BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT'), 'VCALENDAR kept as-is');
  assertNoWarning(a, 'caution');
});

test('all-day event with exclusive end; shortened link in description', () => {
  const a = analyze('BEGIN:VEVENT\nSUMMARY:Holiday\nDTSTART;VALUE=DATE:20261224\nDTEND;VALUE=DATE:20261227\nDESCRIPTION:Info: https://bit.ly/x\nEND:VEVENT');
  assert.equal(a.data.allDay, true);
  assert.equal(a.data.start, '2026-12-24');
  assert.equal(a.data.end, '2026-12-27');
  assert.equal(a.data.days, 3);
  assert.match(field(a, 'When').value, /24 Dec 2026 – .*26 Dec 2026 \(3 days\)/);
  assertWarning(a, 'caution', /shortened/);
});

test('RRULE very frequent forever', () => {
  const a = analyze('BEGIN:VEVENT\nSUMMARY:Spam\nDTSTART:20261201T090000Z\nRRULE:FREQ=MINUTELY\nEND:VEVENT');
  assertWarning(a, 'caution', /very frequently, forever/);
  assertNoWarning(analyze('BEGIN:VEVENT\nDTSTART:20261201T090000Z\nRRULE:FREQ=HOURLY;COUNT=3\nEND:VEVENT'), 'caution', /frequently/);
});

test('date-time forms: floating, unknown zone, ISO separators, invalid dates', () => {
  const f = analyze('BEGIN:VEVENT\nDTSTART:20180601T070000\nEND:VEVENT');
  assert.equal(f.data.start, '2018-06-01T07:00:00');
  assertWarning(f, 'info', /floating/);
  const o = analyze('BEGIN:VEVENT\nDTSTART;TZID=W. Europe Standard Time:20261201T090000\nEND:VEVENT');
  assert.equal(o.data.startKind, 'zone-unknown');
  assertWarning(o, 'info', /IANA/);
  assert.equal(analyze('BEGIN:VEVENT\nDTSTART:2018-06-01T07:00:00Z\nEND:VEVENT').data.start, '2018-06-01T07:00:00Z');
  assertWarning(analyze('BEGIN:VEVENT\nDTSTART:20261340T250000Z\nEND:VEVENT'), 'caution', /not a valid date/);
  assert.equal(parseIcalDateTime('20260230'), null);
  // DST: 2026-03-29 02:30 does not exist in Berlin; 2026-10-25 02:30 is ambiguous — both resolve.
  assert.ok(parseIcalDateTime('20260329T023000', { TZID: ['Europe/Berlin'] }).iso);
  assert.equal(parseIcalDateTime('20260701T120000', { TZID: ['America/New_York'] }).iso, '2026-07-01T16:00:00Z');
});

test('durations and recurrence text', () => {
  assert.equal(parseDuration('PT1H30M'), 5400000);
  assert.equal(parseDuration('P1D'), 86400000);
  assert.equal(parseDuration('-PT15M'), -900000);
  assert.equal(parseDuration('P2W'), 14 * 86400000);
  assert.equal(parseDuration('P'), null);
  assert.equal(parseDuration('PT'), null);
  assert.equal(describeRrule('FREQ=DAILY;INTERVAL=2;UNTIL=20261231T000000Z').text, 'Every 2 days, until 2026-12-31');
  assert.equal(describeRrule('FREQ=MONTHLY;BYDAY=1MO').text, 'Monthly on 1 Mon, forever');
});

test('warnings: end before start, alarms, attendees, far future, organizer', () => {
  assertWarning(analyze('BEGIN:VEVENT\nDTSTART:20261201T090000Z\nDTEND:20261201T080000Z\nEND:VEVENT'), 'caution', /ends before it starts/);
  const al = analyze('BEGIN:VEVENT\nDTSTART:20261201T090000Z\nBEGIN:VALARM\nACTION:EMAIL\nTRIGGER:-PT15M\nEND:VALARM\nBEGIN:VALARM\nACTION:PROCEDURE\nEND:VALARM\nEND:VEVENT');
  assertWarning(al, 'caution', /sends email/);
  assertWarning(al, 'caution', /procedure/);
  assert.equal(al.data.alarms.length, 2);
  const many = Array.from({ length: 21 }, (_, i) => `ATTENDEE;CN=P${i}:mailto:p${i}@x.com`).join('\n');
  assertWarning(analyze(`BEGIN:VEVENT\nDTSTART:20261201T090000Z\n${many}\nEND:VEVENT`), 'info', /21 attendees/);
  assertWarning(analyze('BEGIN:VEVENT\nDTSTART:20991201T090000Z\nEND:VEVENT'), 'info', /5 years/);
  const org = analyze('BEGIN:VEVENT\nDTSTART:20261201T090000Z\nORGANIZER;CN="Doe, J":mailto:j@x.com\nURL:http://x.example/\nEND:VEVENT');
  assert.equal(field(org, 'Organizer').value, 'Doe, J <j@x.com>');
  assertWarning(org, 'caution', /^Link: .*http/);
});

test('multiple events, VTODO, truncation, empty calendar', () => {
  const m = analyze('BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:A\nDTSTART:20261201\nEND:VEVENT\nBEGIN:VEVENT\nSUMMARY:B\nDTSTART:20261202\nEND:VEVENT\nEND:VCALENDAR');
  assert.equal(m.data.events.length, 2);
  assertWarning(m, 'info', /2 calendar entries/);
  assert.equal(m.data.end, '2026-12-02', 'all-day default end is next day');
  const todo = analyze('BEGIN:VCALENDAR\nBEGIN:VTODO\nSUMMARY:Buy milk\nEND:VTODO\nEND:VCALENDAR');
  assert.equal(todo.data.kind, 'todo');
  assert.equal(todo.summary, 'To-do: Buy milk');
  assertWarning(analyze('BEGIN:VEVENT\nSUMMARY:Cut'), 'info', /truncated/);
  const empty = analyze('BEGIN:VCALENDAR\nEND:VCALENDAR');
  assertWarning(empty, 'caution', /No event/);
  assert.ok(!empty.actions.some((x) => x.kind === 'save'));
});

test('event parser never throws on malformed input', () => {
  fuzz('BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:T\\, w\r\nDTSTART;TZID=Europe/Berlin:20261201T090000\r\nDURATION:PT30M\r\nRRULE:FREQ=WEEKLY;BYDAY=TU\r\nBEGIN:VALARM\r\nACTION:EMAIL\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR', { step: 5 });
});
