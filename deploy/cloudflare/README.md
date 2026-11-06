# TrustAuto web publication

- Public URL: https://project.arils.jp/trustauto/
- GitHub Pages origin: https://methurcoder.github.io/TrustAuto/
- Repository: https://github.com/Methurcoder/TrustAuto

The Pages workflow uploads only `site/`. GitHub Pages settings use the
`GitHub Actions` source (`build_type: workflow`). Japanese/English navigation,
CSS and the icon use relative paths, so both public URLs work.

The `trustauto-pages` Cloudflare Worker proxies only `/trustauto` and
`/trustauto/*` to that fixed Pages origin. Cloudflare's route is `/trustauto*`
because its route matching includes query strings, including `/trustauto?x=1`.
The handler enforces the exact path boundary and returns 404 for lookalike
prefixes such as `/trustauto-other/`. It preserves directory redirects,
query strings, conditional requests and missing-file status. It does not forward
visitor cookies or authorization headers. No secret or storage binding is needed.
Never assign it the whole `project.arils.jp` custom domain: the `atemoya` Worker
owns the homepage; the separate `project` Worker owns Blog, Local and diagnosis.

The entry document (`/trustauto/` and `index.html`) chooses its initial language
from trusted Cloudflare `request.cf.country`: Japan uses Japanese; other known
countries redirect temporarily to `/trustauto/en/`. When country is unavailable,
supported browser language preferences are used; other browser languages fall
back to English, and an absent preference falls back to Japanese. An explicit
`?lang=ja` or `?lang=en` takes precedence. The English page's Japanese link uses
`?lang=ja` so an overseas visitor can switch without being redirected back.
Direct English URLs always stay English. Country/language decisions are not
cached across visitors. No country/IP data, cookies, local storage or external
geolocation service is added. GitHub Pages remains a static origin: geographic
selection runs only on the public Arils URL, and direct Pages visitors use the
ordinary manual language links.

Pages updates automatically when the GitHub `main` branch changes `site/` or
the workflow. Its existing daily run refreshes the static star count. Future
content updates need only a Pages deployment; redeploy this Worker only when
the routing code or origin changes.

```sh
node --test deploy/cloudflare/worker.test.mjs
wrangler deploy --dry-run --config deploy/cloudflare/wrangler.jsonc
wrangler deploy --config deploy/cloudflare/wrangler.jsonc
```

Use an installed stable Wrangler and an authenticated Cloudflare session.
Check Japanese/English HTML, CSS, icon, redirects and a missing file after
publication, plus the existing homepage, Blog, Local and diagnosis URLs.

Publication uses the existing GitHub `main` history. The original development
checkout's older commits and untracked local experiments are never pushed by
this website deployment. Linux privilege-elevation commands shown on the site
are documentation; website deployment does not run or install TrustAuto.
