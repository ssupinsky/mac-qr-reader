import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, assertWarning, assertNoWarning, field, action, fuzz } from './_formats-helper.mjs';
import { toDms } from '../../src/renderer/parsers/formats/geo.js';

test('geo: lat, lon, altitude', () => {
  const a = analyze('geo:40.71872,-73.98905,100');
  assert.equal(a.type, 'geo');
  assert.equal(a.data.format, 'geo');
  assert.equal(a.data.lat, 40.71872);
  assert.equal(a.data.lon, -73.98905);
  assert.equal(a.data.alt, 100);
  assert.equal(field(a, 'As degrees').value, '40°43′07.4″N 73°59′20.6″W');
  assert.equal(action(a, /Copy coordinates/).value, '40.718720,-73.989050');
  assert.equal(action(a, /Open in Apple Maps/).value, 'https://maps.apple.com/?ll=40.718720,-73.989050');
  assert.equal(action(a, /Open in Google Maps/).value, 'https://www.google.com/maps/search/?api=1&query=40.718720,-73.989050');
  assertNoWarning(a, 'caution');
});

test('geo: crs and uncertainty, both parameter orders', () => {
  const a = analyze('GEO:37.786971,-122.399677;crs=wgs84;u=35');
  assert.equal(a.data.uncertainty, 35);
  assert.equal(a.data.crs, 'wgs84');
  assertNoWarning(a, 'info', /order/);
  const b = analyze('geo:37.786971,-122.399677;u=35;crs=wgs84');
  assert.equal(b.data.uncertainty, 35);
  assertWarning(b, 'info', /order/);
});

test('geo: Android query form', () => {
  const a = analyze('geo:0,0?q=1600+Amphitheatre+Pkwy');
  assert.equal(a.data.query, '1600 Amphitheatre Pkwy');
  assert.equal(a.summary, 'Location: 1600 Amphitheatre Pkwy');
  assert.equal(action(a, /Apple Maps/).value, 'https://maps.apple.com/?q=1600%20Amphitheatre%20Pkwy');
  const b = analyze('geo:0,0?q=34.99,-106.61(Treasure)&z=11');
  assert.equal(b.data.lat, 34.99);
  assert.equal(b.data.label, 'Treasure');
  assert.equal(b.data.zoom, 11);
  const c = analyze('geo:37.7749,-122.4194?q=San%20Francisco');
  assert.equal(c.data.label, 'San Francisco');
  assert.match(c.summary, /37\.774900, -122\.419400/);
});

test('geo: invalid coordinates and unknown CRS', () => {
  const a = analyze('geo:91,0');
  assertWarning(a, 'caution', /Invalid coordinates/);
  assert.ok(!a.actions.some((x) => x.kind === 'open'));
  assertWarning(analyze('geo:48.2010,16.3695;crs=Moon-2011'), 'caution', /coordinate system/);
  assertWarning(analyze('geo:abc'), 'caution', /Invalid coordinates/);
  assertWarning(analyze('geo:1,2;u=x'), 'caution', /uncertainty/);
  assertWarning(analyze('geo:90,10'), 'info', /pole/);
  assert.equal(Object.is(analyze('geo:-0,-0').data.lat, 0), true);
});

test('DMS formatting rounds without 60″', () => {
  assert.equal(toDms(10.9999999, true), '11°00′00.0″N');
  assert.equal(toDms(-0.5, false), '0°30′00.0″W');
});

test('geo parser never throws on malformed input', () => {
  fuzz('geo:40.71872,-73.98905,100;crs=wgs84;u=35?q=a%20b(c)&z=3');
});
