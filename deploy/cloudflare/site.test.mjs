import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const siteRoot = fileURLToPath(new URL('../../site/', import.meta.url)).replace(/\/$/, '');

for (const file of ['index.html', 'en/index.html']) {
  test(`${file}: local assets, section links, languages, and both host paths resolve`, () => {
    const source = readFileSync(resolve(siteRoot, file), 'utf8');
    const ids = new Set([...source.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]));
    assert.doesNotMatch(source, /<script\b|\son\w+\s*=|<meta name="robots" content="noindex">/i);
    assert.match(source, /Content-Security-Policy/);
    assert.match(source, /https:\/\/project\.arils\.jp\/trustauto\//);
    assert.match(source, /href="https:\/\/project\.arils\.jp\/"/);
    for (const [, value] of source.matchAll(/\b(?:href|src)="([^"]+)"/g)) {
      if (value.startsWith('#')) { assert.ok(ids.has(value.slice(1)), value); continue; }
      if (/^https?:/.test(value)) continue;
      const disk = resolve(dirname(resolve(siteRoot, file)), value);
      assert.ok(disk.startsWith(siteRoot + '/') || disk === siteRoot, value);
      assert.ok(existsSync(disk), value);
      for (const base of ['https://methurcoder.github.io/TrustAuto/', 'https://project.arils.jp/trustauto/']) {
        const target = new URL(value, new URL(file, base));
        assert.ok(target.pathname.startsWith(new URL(base).pathname), target.href);
      }
    }
  });
}

test('Pages publishes only site/ and the Cloudflare routes are strictly scoped', () => {
  const workflow = readFileSync(new URL('../../.github/workflows/pages.yml', import.meta.url), 'utf8');
  assert.match(workflow, /branches: \[main\]/);
  assert.match(workflow, /path: site\s/);
  assert.match(workflow, /pages: write/);
  assert.match(workflow, /id-token: write/);
  const config = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url), 'utf8'));
  assert.deepEqual(config.routes.map(route => route.pattern), ['project.arils.jp/trustauto', 'project.arils.jp/trustauto/*']);
  assert.ok(config.routes.every(route => !route.custom_domain));
  assert.equal(config.workers_dev, false);
});
