import assert from 'node:assert/strict';
import { test } from 'node:test';
import { proxyRequest } from './worker.mjs';

const origin = 'https://project.arils.jp';
const neverFetch = () => { throw new Error('Unexpected fetch'); };

test('only the exact TrustAuto boundary is handled, with a canonical slash', async () => {
  const redirect = await proxyRequest(new Request(origin + '/trustauto?test=1'), neverFetch);
  assert.equal(redirect.status, 308);
  assert.equal(redirect.headers.get('Location'), origin + '/trustauto/?test=1');
  for (const path of ['/', '/blog', '/local', '/girlfriend', '/trustauto-other/']) {
    assert.equal((await proxyRequest(new Request(origin + path), neverFetch)).status, 404);
  }
});

test('Japanese, English, CSS and icons keep their paths and query strings', async () => {
  for (const suffix of ['', 'en/', 'style.css?v=2', 'favicon.svg']) {
    let calls = 0;
    const result = await proxyRequest(new Request(origin + '/trustauto/' + suffix), async (url, options) => {
      calls++;
      assert.equal(url.href, 'https://methurcoder.github.io/TrustAuto/' + suffix);
      assert.equal(options.method, 'GET');
      assert.equal(options.redirect, 'manual');
      return new Response('public content', { headers: { ETag: '"version"' } });
    });
    assert.equal(calls, 1);
    assert.equal(result.status, 200);
    assert.equal(await result.text(), 'public content');
    assert.equal(result.headers.get('ETag'), '"version"');
  }
});

test('other applications credentials are not forwarded in either direction', async () => {
  const request = new Request(origin + '/trustauto/', { headers: {
    Cookie: 'private=value', Authorization: 'Bearer example', 'X-Private': 'value',
    'If-None-Match': '"v1"', Accept: 'text/html',
  } });
  const response = await proxyRequest(request, async (_url, { headers }) => {
    assert.equal(headers.get('Cookie'), null);
    assert.equal(headers.get('Authorization'), null);
    assert.equal(headers.get('X-Private'), null);
    assert.equal(headers.get('If-None-Match'), '"v1"');
    assert.equal(headers.get('Accept'), 'text/html');
    return new Response(null, { status: 304, headers: { 'Set-Cookie': 'unwanted=1', ETag: '"v1"' } });
  });
  assert.equal(response.status, 304);
  assert.equal(response.headers.get('Set-Cookie'), null);
  assert.match(response.headers.get('Cache-Control'), /must-revalidate/);
});

test('upstream directory redirects stay on the public TrustAuto path', async () => {
  const response = await proxyRequest(new Request(origin + '/trustauto/en?x=1'), async () =>
    new Response(null, { status: 301, headers: { Location: 'https://methurcoder.github.io/TrustAuto/en/?x=1' } }));
  assert.equal(response.status, 301);
  assert.equal(response.headers.get('Location'), origin + '/trustauto/en/?x=1');
  for (const location of ['https://example.com/', '/another-repository/']) {
    const rejected = await proxyRequest(new Request(origin + '/trustauto/'), async () =>
      new Response(null, { status: 302, headers: { Location: location } }));
    assert.equal(rejected.status, 502);
  }
});

test('HEAD and missing files keep upstream HTTP semantics', async () => {
  const head = await proxyRequest(new Request(origin + '/trustauto/', { method: 'HEAD' }), async (_url, { method }) => {
    assert.equal(method, 'HEAD');
    return new Response(null, { headers: { 'Content-Length': '123' } });
  });
  assert.equal(await head.text(), '');
  assert.equal(head.headers.get('Content-Length'), '123');
  const missing = await proxyRequest(new Request(origin + '/trustauto/missing'), async () => new Response('missing', { status: 404 }));
  assert.equal(missing.status, 404);
  assert.equal(missing.headers.get('Cache-Control'), 'no-store');
});

test('unsupported methods, invalid encodings, and upstream failures fail locally', async () => {
  assert.equal((await proxyRequest(new Request(origin + '/trustauto/', { method: 'POST' }), neverFetch)).status, 405);
  for (const suffix of ['%ZZ', '%2foutside', '%5coutside', '%252e%252e/', '%00']) {
    assert.equal((await proxyRequest(new Request(origin + '/trustauto/' + suffix), neverFetch)).status, 400, suffix);
  }
  const failed = await proxyRequest(new Request(origin + '/trustauto/'), async () => { throw new Error('offline'); });
  assert.equal(failed.status, 502);
});
