// dev.site — profile rendering, Shoo sign-in, and opening a local service over Iroh.

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

// -- rendering -----------------------------------------------------------------

function renderSession() {
  const session = $('session');
  if (!me) {
    session.innerHTML = '<a id="signin">sign in</a>';
    $('signin').addEventListener('click', startSignIn);
    return;
  }
  const where = me.handle ? `<a href="/@${esc(me.handle)}">@${esc(me.handle)}</a>` : 'no handle yet';
  session.innerHTML = `${where}`;
}

function entryRow({ name, state, className, accentClass, href, onClick, disabled }) {
  const tag = href ? 'a' : 'button';
  const el = document.createElement(tag);
  el.className = `entry ${accentClass} ${className || ''}`.trim();
  if (href) { el.href = href; el.target = '_blank'; el.rel = 'noopener noreferrer'; }
  if (disabled) el.disabled = true;
  el.innerHTML = `
    <span class="name">${name}</span>
    <span class="leader"></span>
    <span class="state">${state}</span>`;
  if (onClick && !disabled) el.addEventListener('click', onClick);
  return el;
}

function group(title, kind, rows) {
  const section = document.createElement('section');
  section.className = `group ${kind}`;
  const head = document.createElement('div');
  head.className = 'group-head';
  head.innerHTML = `<h2>${esc(title)}</h2><span class="rule"></span>`;
  section.append(head);
  if (rows.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'empty';
    empty.textContent = 'nothing here';
    section.append(empty);
  } else {
    rows.forEach((row) => section.append(row));
  }
  return section;
}

function serviceState(entry) {
  return entry.online ? '<em>online</em>' : '<em>offline</em>';
}

function renderProfile(profile) {
  main.innerHTML = '';

  const identity = document.createElement('div');
  identity.className = 'identity';
  identity.innerHTML = `
    <h1 class="handle"><span class="at">@</span>${esc(profile.handle)}</h1>
    <p class="sub">${profile.is_owner ? 'your profile' : 'profile'}</p>`;
  main.append(identity);

  const buckets = { public: [], private: [], shared: [] };
  for (const entry of profile.entries) {
    const accent = `is-${entry.visibility}`;
    if (entry.kind === 'link') {
      buckets.public.push(entryRow({
        name: esc(entry.name),
        state: `${esc(new URL(entry.url).host)} ↗`,
        accentClass: accent,
        href: entry.url,
      }));
    } else {
      buckets[entry.visibility].push(entryRow({
        name: esc(entry.name),
        state: serviceState(entry),
        accentClass: accent,
        className: entry.online ? 'online' : 'offline',
        disabled: !entry.online,
        onClick: () => openService(entry),
      }));
    }
  }

  if (buckets.public.length) main.append(group('public', 'public', buckets.public));
  if (buckets.private.length) main.append(group('private', 'private', buckets.private));
  if (buckets.shared.length) main.append(group('shared', 'shared', buckets.shared));

  if (profile.shared_with_me.length) {
    const rows = profile.shared_with_me.map((entry) => entryRow({
      name: `<span class="owner">@${esc(entry.owner_handle)}’s</span> ${esc(entry.name)}`,
      state: serviceState(entry),
      accentClass: 'is-shared',
      className: entry.online ? 'online' : 'offline',
      disabled: !entry.online,
      onClick: () => openService(entry),
    }));
    main.append(group('shared with me', 'shared', rows));
  }

  if (!main.querySelector('.entry')) {
    const empty = document.createElement('p');
    empty.className = 'empty';
    empty.textContent = 'nothing published yet';
    main.append(empty);
  }
}

// -- opening a service ---------------------------------------------------------

const HOPS = ['this browser', 'iroh relay', 'the daemon', 'the service'];

function paintPath(reached) {
  $('path').innerHTML = HOPS.map((hop, i) => {
    const cls = i < reached ? 'done' : i === reached ? 'live' : '';
    const sep = i < HOPS.length - 1 ? '<span class="sep">→</span>' : '';
    return `<span class="hop ${cls}">${hop}</span>${sep}`;
  }).join(' ');
}

function closeViewer() {
  const viewer = $('viewer');
  viewer.classList.remove('open');
  viewer.hidden = true;
  $('frame').srcdoc = '';
}

async function openService(entry) {
  const viewer = $('viewer');
  const status = $('viewer-status');

  viewer.hidden = false;
  viewer.classList.add('open');
  $('viewer-title').innerHTML = entry.owner_handle
    ? `<span class="of">@${esc(entry.owner_handle)}’s</span> ${esc(entry.name)}`
    : esc(entry.name);
  $('frame').srcdoc = '';
  status.className = 'viewer-status';
  status.textContent = 'creating a browser endpoint';
  paintPath(0);

  try {
    if (!endpoint) endpoint = await BrowserEndpoint.create();
    paintPath(1);

    status.textContent = 'requesting a capability';
    // The capability is bound to this endpoint's key; the daemon checks that binding
    // against the authenticated peer of the connection.
    const grant = await api('/api/capability', {
      method: 'POST',
      body: JSON.stringify({
        resource_id: entry.resource_id,
        browser_endpoint_id: endpoint.endpointId,
      }),
    });

    paintPath(2);
    status.textContent = 'connecting through the relay';
    const html = await endpoint.fetchPage(
      grant.daemon_endpoint_id,
      grant.relay_url,
      grant.capability,
      '/',
    );

    paintPath(3);
    $('frame').srcdoc = html;
    status.classList.add('hidden');
  } catch (err) {
    status.className = 'viewer-status err';
    status.textContent = String(err.message || err);
  }
}

// -- setup views ---------------------------------------------------------------

function renderSignedOut() {
  main.innerHTML = `
    <div class="block">
      <h1>Your public work and your <em>private</em> local services, on one page.</h1>
      <p>
        Private services stay on your machine. Nothing is deployed, no port is opened, and
        the page you are reading never carries their traffic.
      </p>
      <button class="action" id="start">sign in</button>
    </div>`;
  $('start').addEventListener('click', startSignIn);
}

function renderClaimHandle() {
  main.innerHTML = `
    <div class="block">
      <h1>Choose a <em>handle</em>.</h1>
      <p>It becomes the address of your profile. Letters, digits, hyphens and underscores.</p>
      <div class="field">
        <input id="handle" placeholder="dami" autocomplete="off" spellcheck="false">
        <button class="action" id="claim">claim</button>
      </div>
      <p class="error" id="handle-error" hidden></p>
    </div>`;

  const submit = async () => {
    const error = $('handle-error');
    error.hidden = true;
    try {
      const result = await api('/api/profile', {
        method: 'POST',
        body: JSON.stringify({ handle: $('handle').value }),
      });
      location.assign(`/@${result.handle}`);
    } catch (err) {
      error.textContent = err.message;
      error.hidden = false;
    }
  };
  $('claim').addEventListener('click', submit);
  $('handle').addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
}

function renderCliToken(token) {
  const block = document.createElement('div');
  block.className = 'token-box';
  block.innerHTML = `
    <p>To configure this machine, run <code style="display:inline;color:var(--ink-dim)">devsite login</code> and paste:</p>
    <code>${esc(token)}</code>`;
  main.querySelector('.block')?.append(block);
}

// -- routing -------------------------------------------------------------------

async function route() {
  const path = location.pathname;

  if (path === '/auth/callback') {
    main.innerHTML = '<div class="block"><h1>Signing you in…</h1></div>';
    try {
      const { session, returnTo } = await completeSignIn();
      me = { account_id: session.account_id, handle: session.handle };
      // Keep the CLI token in memory only for this render; it is not persisted anywhere.
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
      main.innerHTML = `<div class="block"><h1>Sign-in failed.</h1><p class="error">${esc(err.message)}</p><button class="action" id="retry">try again</button></div>`;
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
    main.innerHTML = `<div class="block"><h1>No such profile.</h1><p>@${esc(handle)} ${esc(err.message === '404' ? 'does not exist' : err.message)}</p></div>`;
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
await route();
