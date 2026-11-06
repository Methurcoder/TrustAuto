const PUBLIC_ORIGIN = 'https://project.arils.jp';
const PUBLIC_BASE = '/trustauto/';
const PAGES_ORIGIN = 'https://methurcoder.github.io';
const PAGES_BASE = '/TrustAuto/';

function plain(message, status, extra = {}) {
  return new Response(message, {
    status,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', ...extra },
  });
}

function browserLanguage(header) {
  const languages = (header || '').split(',').map((entry, index) => {
    const [tag, ...parameters] = entry.trim().split(';');
    const quality = parameters.find(value => /^\s*q=/i.test(value));
    const weight = quality === undefined ? 1 : Number(quality.split('=')[1]);
    return { tag: tag.toLowerCase(), weight, index };
  }).filter(({ tag, weight }) => /^[a-z]{2,8}(?:-[a-z0-9]{1,8})*$/i.test(tag)
    && Number.isFinite(weight) && weight > 0 && weight <= 1)
    .sort((a, b) => b.weight - a.weight || a.index - b.index);
  const supported = languages.find(({ tag }) => /^(ja|en)(-|$)/.test(tag));
  return supported ? (supported.tag.startsWith('ja') ? 'ja' : 'en') : languages.length ? 'en' : 'ja';
}

function initialLanguage(request, url) {
  const explicit = url.searchParams.get('lang');
  if (explicit === 'ja' || explicit === 'en') return explicit;
  // Read trusted edge metadata only. Country/IP/cookies are never sent to Pages
  // or persisted. Client-supplied CF-IPCountry is deliberately not consulted.
  const country = request.cf?.country;
  if (typeof country === 'string' && /^[A-Z]{2}$/i.test(country) && country.toUpperCase() !== 'XX') {
    return country.toUpperCase() === 'JP' ? 'ja' : 'en';
  }
  return browserLanguage(request.headers.get('Accept-Language'));
}

// This Worker serves only public GitHub Pages files. Cookies and authorization
// from the other applications on project.arils.jp never go to GitHub Pages.
export async function proxyRequest(request, upstreamFetch = fetch) {
  const url = new URL(request.url);
  if (url.pathname === '/trustauto') {
    return Response.redirect(`${PUBLIC_ORIGIN}${PUBLIC_BASE}${url.search}`, 308);
  }
  if (!url.pathname.startsWith(PUBLIC_BASE)) return plain('Not found', 404);
  if (!['GET', 'HEAD'].includes(request.method)) return plain('Method not allowed', 405, { Allow: 'GET, HEAD' });

  const suffix = url.pathname.slice(PUBLIC_BASE.length);
  try {
    for (const part of suffix.split('/')) {
      const decoded = decodeURIComponent(part);
      if (decoded === '.' || decoded === '..' || /[\\/%\u0000-\u001f\u007f]/u.test(decoded)) {
        return plain('Invalid path', 400);
      }
    }
  } catch {
    return plain('Invalid path', 400);
  }

  const entryDocument = suffix === '' || suffix === 'index.html';
  if (entryDocument && initialLanguage(request, url) === 'en') {
    return new Response(null, {
      status: 302,
      headers: {
        Location: `${PUBLIC_ORIGIN}${PUBLIC_BASE}en/${url.search}`,
        // Each visitor can have a different country/preference. Never reuse
        // a visitor's language redirect for someone else.
        'Cache-Control': 'private, no-store',
        Vary: 'Accept-Language',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
      },
    });
  }

  const upstream = new URL(PAGES_ORIGIN);
  upstream.pathname = PAGES_BASE + suffix;
  upstream.search = url.search;
  const headers = new Headers();
  for (const name of ['Accept', 'If-None-Match', 'If-Modified-Since', 'Range', 'If-Range']) {
    const value = request.headers.get(name);
    if (value !== null) headers.set(name, value);
  }

  let response;
  try {
    response = await upstreamFetch(upstream, {
      method: request.method,
      headers,
      redirect: 'manual',
      signal: AbortSignal.timeout(15000),
    });
  } catch {
    return plain('The site is temporarily unavailable. Please try again.', 502);
  }

  const outputHeaders = new Headers(response.headers);
  outputHeaders.delete('Set-Cookie');
  const location = response.headers.get('Location');
  if (response.status >= 300 && response.status < 400 && location) {
    const destination = new URL(location, upstream);
    if (destination.origin !== PAGES_ORIGIN || !destination.pathname.startsWith(PAGES_BASE)) {
      return plain('Unexpected upstream redirect', 502);
    }
    outputHeaders.set('Location', `${PUBLIC_ORIGIN}${PUBLIC_BASE}${destination.pathname.slice(PAGES_BASE.length)}${destination.search}${destination.hash}`);
  }
  outputHeaders.set('Cache-Control', entryDocument ? 'private, no-store'
    : response.status < 400 ? 'public, max-age=0, must-revalidate' : 'no-store');
  if (entryDocument) outputHeaders.set('Vary', '*');
  outputHeaders.set('X-Content-Type-Options', 'nosniff');
  outputHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  return new Response(request.method === 'HEAD' ? null : response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: outputHeaders,
  });
}

export default { fetch: request => proxyRequest(request) };
