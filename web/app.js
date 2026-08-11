// dev.site — profile rendering, Shoo sign-in, and opening a local service over Iroh.
//
// The website reads; `devsite` writes. Links, exposures, sharing and themes are
// all set from the CLI, so the only thing here that changes server state is
// claiming a handle — which has to happen in the browser because that is where
// you finish signing in. Anything else that mutates a profile belongs in the
// CLI, next to the rest of it.
//
// The markup this file produces is a contract, not an implementation detail: a
// profile's theme is a list of --pico-* assignments that only mean anything
// against the elements below. Keep it semantic, keep it documented, and change
// it in step with docs/profile-template.md.

const SHOO = 'https://shoo.dev';
const $ = (id) => document.getElementById(id);
const main = $('main');

/** The browser's Iroh endpoint. Created lazily, once per tab session. */
let endpoint = null;
let me = null;
/** Resolved from the versioned wasm bundle at boot. */
let BrowserEndpoint = null;

// -- utilities -----------------------------------------------------------------

const esc = (value) =>
  String(value).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `${response.status}`);
  }
  return response.status === 204 ? null : response.json();
}

// -- Shoo sign-in (authorization code + PKCE, run entirely in the browser) ------

const b64url = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function randomVerifier() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const bytes = crypto.getRandomValues(new Uint8Array(64));
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('');
}

async function startSignIn() {
  const verifier = randomVerifier();
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));

  // The verifier never leaves the browser; only its hash goes to Shoo.
  sessionStorage.setItem('pkce_verifier', verifier);
  sessionStorage.setItem('pkce_state', state);
  sessionStorage.setItem('return_to', location.pathname);

  const redirectUri = `${location.origin}/auth/callback`;
  const url = new URL('/authorize', SHOO);
  url.searchParams.set('response_type', 'code');
  // Shoo derives the client id from the redirect origin; sending it explicitly keeps the
  // value we verify `aud` against and the value Shoo registers identical.
  url.searchParams.set('client_id', `origin:${location.origin}`);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', 'openid');
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  location.assign(url.toString());
}

async function completeSignIn() {
  const params = new URLSearchParams(location.search);
  const code = params.get('code');
  const state = params.get('state');
  const verifier = sessionStorage.getItem('pkce_verifier');
  const expectedState = sessionStorage.getItem('pkce_state');
  const returnTo = sessionStorage.getItem('return_to') || '/';

  sessionStorage.removeItem('pkce_verifier');
  sessionStorage.removeItem('pkce_state');

  if (params.get('error')) throw new Error(params.get('error_description') || params.get('error'));
  if (!code || !verifier) throw new Error('sign-in did not complete');
  // Guards against an attacker pasting their own authorization code into your session.
  if (!state || state !== expectedState) throw new Error('sign-in state did not match');

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: `${location.origin}/auth/callback`,
    client_id: `origin:${location.origin}`,
    code_verifier: verifier,
  });
  const tokenResponse = await fetch(`${SHOO}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!tokenResponse.ok) throw new Error(`token exchange failed (${tokenResponse.status})`);
  const { id_token } = await tokenResponse.json();
  if (!id_token) throw new Error('no id_token was returned');

  // The control plane verifies this independently against Shoo's JWKS and mints its own
  // session. Nothing after this point trusts the id_token again.
  const session = await api('/api/auth/session', {
    method: 'POST',
    body: JSON.stringify({ id_token }),
  });
  return { session, returnTo };
}

// -- themes --------------------------------------------------------------------

/// Apply a profile's theme.
///
/// The server has already checked every property against its whitelist and every
/// value against a grammar, so this is only assembly: one rule, scoped to the
/// profile, holding nothing but custom-property assignments. It is the last
/// stylesheet in the document, so equal specificity is enough — no user rule
/// ever has to out-rank Pico.
function applyTheme(handle, declarations = []) {
  const root = document.documentElement;
  // Belt and braces: handles are already restricted to this alphabet server-side.
  const scope = String(handle).replace(/[^A-Za-z0-9_-]/g, '');
  root.dataset.profile = scope;

  // The one key that is not a Pico variable — it picks which of Pico's own
  // palettes the profile starts from.
  const scheme = declarations.find((d) => d.property === '--devsite-scheme')?.value;
  if (scheme === 'light' || scheme === 'dark') {
    root.dataset.theme = scheme;
  } else {
    delete root.dataset.theme;
  }

  const body = declarations
    .filter((d) => d.property !== '--devsite-scheme')
    .map((d) => `  ${d.property}: ${d.value};`)
    .join('\n');
  $('profile-theme').textContent = body
    ? `[data-profile="${scope}"] {\n${body}\n}\n`
    : '';
}

function clearTheme() {
  delete document.documentElement.dataset.profile;
  delete document.documentElement.dataset.theme;
  $('profile-theme').textContent = '';
}

// -- rendering -----------------------------------------------------------------

function renderSession() {
  const session = $('session');
  if (!me) {
    session.innerHTML = '<li><a href="#" id="signin" role="button" class="outline">Sign in</a></li>';
    $('signin').addEventListener('click', (e) => { e.preventDefault(); startSignIn(); });
    return;
  }
  session.innerHTML = me.handle
    ? `<li><a href="/@${esc(me.handle)}">@${esc(me.handle)}</a></li>`
    : '<li><small>no handle yet</small></li>';
}

/// One row of a profile.
///
/// Links are anchors and services are buttons, because a link goes somewhere and
/// a service opens here.
///
/// A service carries no reachability state. Nothing on this page knows whether
/// the far end is running — the control plane is not told, and the only thing
/// that could answer is a connection attempt. So the row makes no claim, and
/// clicking it finds out.
function entry({ kind, name, state, href, onClick }) {
  const li = document.createElement('li');
  li.className = 'entry';
  li.dataset.kind = kind;

  if (href) {
    li.innerHTML =
      `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${name}</a>` +
      `<small class="state">${esc(state)}</small>`;
  } else {
    li.innerHTML = `<button class="outline">${name}</button>`;
    if (onClick) li.querySelector('button').addEventListener('click', onClick);
  }
  return li;
}

/// Where a link goes, or just an arrow when its name already says so.
///
/// `www.` is ignored in the comparison: a link named `klot.ski` pointing at
/// `www.klot.ski` is the same claim written twice.
function linkHost(item) {
  const host = new URL(item.url).host;
  const same = host.replace(/^www\./, '').toLowerCase()
    === item.name.replace(/^www\./, '').toLowerCase();
  return same ? '↗' : `${host} ↗`;
}

function group(title, visibility, rows) {
  const section = document.createElement('section');
  section.className = 'group';
  section.dataset.visibility = visibility;
  section.innerHTML = `<h2>${esc(title)}</h2>`;

  const list = document.createElement('ul');
  list.className = 'entries';
  rows.forEach((row) => list.append(row));
  section.append(list);
  return section;
}

function renderProfile(profile) {
  applyTheme(profile.handle, profile.theme);
  main.innerHTML = '';

  const article = document.createElement('article');
  article.id = 'profile';

  const counts = [
    profile.entries.filter((e) => e.kind === 'service').length,
    profile.entries.filter((e) => e.kind === 'link').length,
  ];
  const summary = [
    counts[0] === 1 ? '1 service' : `${counts[0]} services`,
    counts[1] === 1 ? '1 link' : `${counts[1]} links`,
  ].join(' · ');

  const heading = document.createElement('hgroup');
  heading.innerHTML = `<h1>@${esc(profile.handle)}</h1><p>${summary}</p>`;
  article.append(heading);

  const buckets = { public: [], private: [], shared: [] };
  for (const item of profile.entries) {
    if (item.kind === 'link') {
      buckets.public.push(entry({
        kind: 'link',
        name: esc(item.name),
        // The host is there to say where a link goes when its name does not.
        // When someone names a link after its domain — which is the honest thing
        // to do for a site that has no other name — repeating it says nothing,
        // so only the arrow remains.
        state: linkHost(item),
        href: item.url,
      }));
    } else {
      buckets[item.visibility].push(entry({
        kind: 'service',
        name: esc(item.name),
        onClick: () => openService(item),
      }));
    }
  }

  const titles = { public: 'Public', private: 'Private', shared: 'Shared' };
  for (const visibility of ['public', 'private', 'shared']) {
    if (buckets[visibility].length) {
      article.append(group(titles[visibility], visibility, buckets[visibility]));
    }
  }

  if (profile.shared_with_me.length) {
    const rows = profile.shared_with_me.map((item) => entry({
      kind: 'service',
      name: `${esc(item.name)} <small>from @${esc(item.owner_handle)}</small>`,
      onClick: () => openService(item),
    }));
    article.append(group('Shared with me', 'shared-with-me', rows));
  }

  if (!article.querySelector('.entry')) {
    const empty = document.createElement('p');
    empty.innerHTML = '<small>Nothing published yet.</small>';
    article.append(empty);
  }

  main.append(article);
}

// -- opening a service ---------------------------------------------------------

const HOPS = ['this browser', 'iroh relay', 'the daemon', 'the service'];

function paintHops(reached) {
  $('viewer-hops').innerHTML = HOPS.map((hop, i) => {
    const state = i < reached ? 'yes' : i === reached ? 'now' : 'no';
    const arrow = i < HOPS.length - 1 ? ' →' : '';
    return `<li data-reached="${state}"><small>${hop}${arrow}</small></li>`;
  }).join('');
}

/// Put the fetched page on screen, in an iframe built for this one service.
///
/// Building it here rather than reusing one from the markup is not tidiness: an
/// iframe that is `display:none` when its `srcdoc` is first assigned never
/// renders that document, and no later assignment recovers it. A fresh element
/// also means each service starts in a brand-new opaque-origin document, and
/// closing the viewer destroys it rather than blanking it.
function mountFrame(html) {
  const frame = document.createElement('iframe');
  // allow-scripts WITHOUT allow-same-origin: the fetched page gets an opaque
  // origin, so it can run its own code but cannot reach dev.site's DOM, storage
  // or cookies.
  frame.setAttribute('sandbox', 'allow-scripts');
  frame.title = 'Local service';
  frame.srcdoc = html;
  $('viewer-body').replaceChildren(frame);
}

/// Pico's modal convention: the `open` attribute on the dialog, and a lock class
/// on the document while it is up.
function openViewer() {
  document.documentElement.classList.add('modal-is-open', 'modal-is-opening');
  $('viewer').setAttribute('open', '');
  setTimeout(() => document.documentElement.classList.remove('modal-is-opening'), 400);
}

function closeViewer() {
  document.documentElement.classList.remove('modal-is-open', 'modal-is-opening');
  $('viewer').removeAttribute('open');
  $('viewer-body').replaceChildren();
}

async function openService(item) {
  const status = $('viewer-status');

  $('viewer-title').textContent = item.owner_handle
    ? `${item.name} — @${item.owner_handle}`
    : item.name;
  $('viewer-body').replaceChildren();
  status.removeAttribute('aria-invalid');
  status.setAttribute('aria-busy', 'true');
  status.textContent = 'Creating a browser endpoint';
  paintHops(0);
  openViewer();

  try {
    if (!endpoint) endpoint = await BrowserEndpoint.create();
    paintHops(1);

    status.textContent = 'Requesting a capability';
    // The capability is bound to this endpoint's key; the daemon checks that binding
    // against the authenticated peer of the connection.
    const grant = await api('/api/capability', {
      method: 'POST',
      body: JSON.stringify({
        resource_id: item.resource_id,
        browser_endpoint_id: endpoint.endpointId,
      }),
    });

    paintHops(2);
    status.textContent = 'Looking up the daemon and connecting';
    // The daemon is named, not located: `fetchPage` takes an endpoint id and lets
    // iroh resolve where it currently is. This is also the step that discovers
    // whether it is running at all, and it gives up after a few seconds.
    const html = await endpoint.fetchPage(grant.daemon_endpoint_id, grant.capability, '/');

    paintHops(3);
    mountFrame(html);
    status.removeAttribute('aria-busy');
    status.textContent = '';
  } catch (err) {
    status.removeAttribute('aria-busy');
    status.setAttribute('aria-invalid', 'true');
    status.innerHTML = unreachable(err)
      ? `<span class="error">Couldn't reach ${esc(item.name)}.</span> ` +
        `Nothing answered on that machine — is <code>devsite daemon run</code> running?`
      : `<span class="error">${esc(String(err.message || err))}</span>`;
  }
}

/// Whether a failure means "nobody answered" rather than "they said no".
///
/// Worth distinguishing in the message: a refusal is a decision the daemon made
/// and the viewer cannot fix, while silence is nearly always a daemon that is
/// not running.
function unreachable(err) {
  const message = String(err?.message || err);
  return message.includes('no answer from the daemon')
    || message.includes('connecting to daemon');
}

// -- setup views ---------------------------------------------------------------

function renderSignedOut() {
  clearTheme();
  main.innerHTML = `
    <article>
      <hgroup>
        <h1>Your public work and your private local services, on one page.</h1>
        <p>
          Private services stay on your machine. Nothing is deployed, no port is opened,
          and the page you are reading never carries their traffic.
        </p>
      </hgroup>
      <button id="start">Sign in</button>
    </article>`;
  $('start').addEventListener('click', startSignIn);
}

function renderClaimHandle() {
  clearTheme();
  main.innerHTML = `
    <article>
      <hgroup>
        <h1>Choose a handle.</h1>
        <p>It becomes the address of your profile. Letters, digits, hyphens and underscores.</p>
      </hgroup>
      <form id="claim-form">
        <fieldset role="group">
          <input id="handle" name="handle" placeholder="yourhandle" autocomplete="off"
                 spellcheck="false" aria-label="Handle" required>
          <button type="submit">Claim</button>
        </fieldset>
        <small id="claim-note"></small>
      </form>
    </article>`;

  $('claim-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const field = $('handle');
    const note = $('claim-note');
    try {
      const result = await api('/api/profile', {
        method: 'POST',
        body: JSON.stringify({ handle: field.value }),
      });
      location.assign(`/@${result.handle}`);
    } catch (err) {
      field.setAttribute('aria-invalid', 'true');
      note.innerHTML = `<span class="error">${esc(err.message)}</span>`;
    }
  });
}

/// Shown once, immediately after signing in, and never persisted.
function renderCliToken(token) {
  const article = document.createElement('article');
  article.innerHTML = `
    <header><strong>Configure this machine</strong></header>
    <p>Run <code>devsite login</code> and paste:</p>
    <pre><code class="token">${esc(token)}</code></pre>`;
  main.append(article);
}

// -- routing -------------------------------------------------------------------

async function route() {
  const path = location.pathname;

  if (path === '/auth/callback') {
    main.innerHTML = '<article aria-busy="true">Signing you in…</article>';
    try {
      const { session, returnTo } = await completeSignIn();
      me = { account_id: session.account_id, handle: session.handle };
      history.replaceState({}, '', session.handle ? `/@${session.handle}` : '/');
      renderSession();
      if (!session.handle) {
        renderClaimHandle();
      } else {
        await showProfile(session.handle);
      }
      renderCliToken(session.token);
      void returnTo;
    } catch (err) {
      main.innerHTML = `
        <article>
          <hgroup><h1>Sign-in failed.</h1><p class="error">${esc(err.message)}</p></hgroup>
          <button id="retry">Try again</button>
        </article>`;
      $('retry').addEventListener('click', startSignIn);
    }
    return;
  }

  try {
    me = await api('/api/me');
  } catch {
    me = null;
  }
  renderSession();

  const handleMatch = path.match(/^\/@([^/]+)$/);
  if (handleMatch) {
    await showProfile(decodeURIComponent(handleMatch[1]));
    return;
  }

  if (!me) { renderSignedOut(); return; }
  if (!me.handle) { renderClaimHandle(); return; }
  location.replace(`/@${me.handle}`);
}

async function showProfile(handle) {
  try {
    renderProfile(await api(`/api/profile/${encodeURIComponent(handle)}`));
  } catch (err) {
    clearTheme();
    main.innerHTML = `
      <article>
        <hgroup>
          <h1>No such profile.</h1>
          <p>@${esc(handle)} ${esc(err.message === '404' ? 'does not exist' : err.message)}</p>
        </hgroup>
      </article>`;
  }
}

// -- boot ----------------------------------------------------------------------

/// Load the wasm bundle named by the manifest.
///
/// The bundle lives under a content-hashed path so it can be cached immutably; only this
/// small manifest is ever revalidated. Without it, a deploy would leave browsers running
/// the previous bundle from cache.
async function loadEndpointModule() {
  const { version } = await (await fetch('/pkg/manifest.json', { cache: 'no-cache' })).json();
  const module = await import(`/pkg/${version}/devsite_web.js`);
  await module.default();
  return module.BrowserEndpoint;
}

$('viewer-close').addEventListener('click', closeViewer);
$('viewer').addEventListener('click', (e) => { if (e.target === $('viewer')) closeViewer(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeViewer(); });

BrowserEndpoint = await loadEndpointModule();
main.removeAttribute('aria-busy');
await route();
