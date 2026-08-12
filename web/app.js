// dev.site — profiles, sharing controls, and TCP service connection instructions.
//
// The public profile reads. The signed-in homepage is a deliberately small
// dashboard for account-bound controls: privacy, share revocation and machine
// credentials. Creating links and exposures remains in the CLI.
//
// The markup this file produces is a contract, not an implementation detail: a
// profile's theme is a list of --pico-* assignments that only mean anything
// against the elements below. Keep it semantic, keep it documented, and change
// it in step with docs/profile-template.md.

const SHOO = 'https://shoo.dev';
const $ = (id) => document.getElementById(id);
const main = $('main');
const pageFooter = $('page-footer');

let me = null;

// -- utilities -----------------------------------------------------------------

const esc = (value) =>
  String(value).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function setPageTitle(suffix = '') {
  document.title = suffix ? `dev.site - ${suffix}` : 'dev.site';
}

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
/// profile, holding nothing but custom-property assignments.
///
/// The `:root` in the selector is load-bearing. Pico sets its palette on
/// `:root:not([data-theme=dark])`, which is specificity (0,2,0) because `:not()`
/// contributes its argument's weight. A bare `[data-profile="…"]` is (0,1,0) and
/// loses to it outright — no matter how late in the document it appears. With
/// `:root` in front we match that (0,2,0) and win on source order, being the last
/// stylesheet in the page. This was wrong until it was tested in a browser, and
/// the failure was silent: themes stored, served, and ignored.
function applyTheme(handle, declarations = []) {
  document.querySelector('.brand strong').hidden = false;
  const root = document.documentElement;
  // Belt and braces: handles are already restricted to this alphabet server-side.
  const scope = String(handle).replace(/[^A-Za-z0-9_-]/g, '');
  root.dataset.profile = scope;

  // The one key that is not a Pico variable — it picks which of Pico's own
  // palettes the profile starts from. Pico also sets the root color-scheme,
  // so CSS light-dark() values follow this choice without a second switcher.
  const scheme = declarations.find((d) => d.property === '--devsite-scheme')?.value;
  if (scheme === 'light' || scheme === 'dark') {
    root.dataset.theme = scheme;
  } else {
    delete root.dataset.theme;
  }

  const body = declarations
    // Layout declarations are data for renderProfile, not CSS. Restricting the
    // generated rule positively to Pico variables keeps quoted folder names out
    // of the style element regardless of what printable Unicode they contain.
    .filter((d) => d.property.startsWith('--pico-'))
    .map((d) => `  ${d.property}: ${d.value};`)
    .join('\n');
  $('profile-theme').textContent = body
    ? `:root[data-profile="${scope}"] {\n${body}\n}\n`
    : '';
  requestAnimationFrame(updateLogoContrast);
}

function clearTheme() {
  document.querySelector('.brand strong').hidden = false;
  delete document.documentElement.dataset.profile;
  delete document.documentElement.dataset.theme;
  $('profile-theme').textContent = '';
  pageFooter.replaceChildren();
  pageFooter.hidden = true;
  requestAnimationFrame(updateLogoContrast);
}

function parseComputedColor(value) {
  const match = value.match(/^rgba?\(\s*([\d.]+)[, ]+\s*([\d.]+)[, ]+\s*([\d.]+)(?:\s*[,/]\s*([\d.]+))?\s*\)$/i);
  if (!match) return null;
  return {
    rgb: [Number(match[1]), Number(match[2]), Number(match[3])],
    alpha: match[4] === undefined ? 1 : Number(match[4]),
  };
}

/// Composite the rendered background layers behind the mark. This observes the
/// color itself rather than a theme label, so custom dark colors work in either mode.
function logoBackground() {
  let node = document.querySelector('.brand');
  let alpha = 0;
  const premultiplied = [0, 0, 0];
  while (node instanceof Element) {
    const layer = parseComputedColor(getComputedStyle(node).backgroundColor);
    if (layer && layer.alpha > 0) {
      for (let channel = 0; channel < 3; channel += 1) {
        premultiplied[channel] += layer.rgb[channel] * layer.alpha * (1 - alpha);
      }
      alpha += layer.alpha * (1 - alpha);
      if (alpha >= 0.999) break;
    }
    node = node.parentElement;
  }
  return premultiplied.map((channel) => channel + 255 * (1 - alpha));
}

function updateLogoContrast() {
  if (!$('dev-logo-ring')) return;
  const luminance = logoBackground()
    .map((channel) => channel / 255)
    .map((channel) => channel <= 0.04045
      ? channel / 12.92
      : ((channel + 0.055) / 1.055) ** 2.4)
    .reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
  document.documentElement.style.setProperty(
    '--devsite-logo-ring',
    luminance < 0.179 ? 'rgb(255,255,255)' : 'rgb(0,0,0)',
  );
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
/// Everything on a profile is a site. The only difference between them is how you
/// get there: a link is reached at its own address, so it is an anchor and takes
/// you away; a service is reached through its owner's daemon, so it is a button
/// and opens here. That is the whole of the distinction, and the row says it with
/// an arrow rather than by sorting the page into kinds.
///
/// A service carries no reachability state. Nothing on this page knows whether
/// the far end is running — the control plane is not told, and the only thing
/// that could answer is a connection attempt. So the row makes no claim, and
/// clicking it finds out.
function siteRow(item, { onClick, from } = {}) {
  const li = document.createElement('li');
  li.className = 'entry';
  li.dataset.kind = item.kind;
  li.dataset.visibility = item.visibility;

  const name = esc(item.name)
    + (from ? ` <small>from @${esc(from)}</small>` : '');

  if (item.kind === 'link') {
    const note = item.visibility === 'public' ? '' : `${esc(item.visibility)} - `;
    li.innerHTML =
      `<a href="${esc(item.url)}" target="_blank" rel="ugc nofollow noopener noreferrer">${name}</a>` +
      `<small class="state">${note}${linkHost(item)}</small>`;
    return li;
  }

  // Visibility is worth saying only where it is not the default. On someone
  // else's profile it also explains why you can see a thing at all.
  const note = item.visibility === 'public' ? '' : esc(item.visibility);
  li.innerHTML = `<button class="outline">${name}</button>`
    + (note ? `<small class="state">${note}</small>` : '');
  if (onClick) li.querySelector('button').addEventListener('click', onClick);
  return li;
}

/// Where a link goes: always in the markup, revealed one row at a time.
///
/// Every link carries its host, including the ones named after it. The arrow is
/// what you see at rest; pointing at a row expands the host leftward out of it.
/// So `github.com` is there on both repos without two rows saying the same thing
/// at once, and a link named `klot.ski` is not silently missing information the
/// others have — it is just never showing it and its neighbour at the same time.
///
/// The nested span is what makes it animate: the outer element is an inline grid
/// whose single column goes 0fr → 1fr, which transitions to exactly the content's
/// width without anyone having to guess a max-width. The trailing space lives
/// inside the clipped span so it collapses with the text rather than leaving a
/// gap before the arrow.
function linkHost(item) {
  const host = esc(new URL(item.url).host);
  return `<span class="host"><span>${host}&nbsp;</span></span>↗`;
}

function entryList(items, options = {}) {
  const list = document.createElement('ul');
  list.className = 'entries';
  for (const item of items) {
    list.append(siteRow(item, {
      ...options,
      from: item.owner_handle,
      onClick: () => openService(item),
    }));
  }
  return list;
}

/// The folders on a profile, in the order they first appear.
///
/// Derived from the entries rather than stored anywhere: a folder is a name
/// repeated across the sites that share it, so this is the only place the set of
/// them exists. A folder that a viewer may see nothing inside does not appear at
/// all, because it never gets built.
function foldersOf(entries) {
  const folders = new Map();
  for (const item of entries) {
    if (!item.folder) continue;
    if (!folders.has(item.folder)) folders.set(item.folder, []);
    folders.get(item.folder).push(item);
  }
  return folders;
}

/// Validated layout declarations arrive in canonical JSON-string-list form.
/// Parsing them again here is assembly rather than trust: malformed values can
/// only mean an older/newer server mismatch, in which case the safe default is
/// the original all-open, first-appearance layout.
function profileLayout(declarations = []) {
  const value = (property) =>
    declarations.find((declaration) => declaration.property === property)?.value;
  const names = (property) => {
    const list = value(property);
    if (!list) return [];
    try {
      const parsed = JSON.parse(`[${list}]`);
      return Array.isArray(parsed) && parsed.every((name) => typeof name === 'string')
        ? parsed
        : [];
    } catch {
      return [];
    }
  };
  return {
    foldersOpen: value('--devsite-folders') !== 'closed',
    openFolders: new Set(names('--devsite-open-folders')),
    folderOrder: names('--devsite-folder-order'),
  };
}

/// Named folders come first in the requested order. A name that does not exist
/// for this viewer is ignored, and unlisted visible folders retain the order in
/// which they first appeared.
function orderedFolders(folders, order) {
  const result = [];
  const placed = new Set();
  for (const name of order) {
    if (folders.has(name)) {
      result.push([name, folders.get(name)]);
      placed.add(name);
    }
  }
  for (const entry of folders) {
    if (!placed.has(entry[0])) result.push(entry);
  }
  return result;
}

/// One semantic fold. Layout declarations choose only its initial state; once
/// rendered, the reader owns the ordinary `<details>` interaction.
function folder(name, items, layout) {
  const details = document.createElement('details');
  details.className = 'folder';
  details.open = layout.foldersOpen || layout.openFolders.has(name);
  details.innerHTML =
    `<summary>${esc(name)} <small>${items.length}</small></summary>`;
  details.append(entryList(items));
  return details;
}

function renderProfile(profile) {
  setPageTitle(`@${profile.handle}`);
  applyTheme(profile.handle, profile.theme);
  const layout = profileLayout(profile.theme);
  main.innerHTML = '';

  const article = document.createElement('article');
  article.id = 'profile';

  // Accepted shares are ordinary service rows once they reach the profile. Their
  // owner annotation preserves provenance without making sharing a top-level section.
  const entries = [...profile.entries, ...profile.shared_with_me];
  const total = entries.length;
  const heading = document.createElement('hgroup');
  heading.innerHTML = `<h1>@${esc(profile.handle)}</h1>`
    + `<p>${total === 1 ? '1 site' : `${total} sites`}</p>`;
  article.append(heading);

  // Loose sites first, in the order they were published, then a fold per folder
  // in the order those first appear. No sections by kind or by visibility: a
  // profile is a list of sites, and sorting it into "links" and "services" would
  // be publishing an implementation detail as a heading. Folders are different —
  // they are the owner's own grouping, and they say so in the owner's words.
  if (total) {
    const loose = entries.filter((item) => !item.folder);
    if (loose.length) article.append(entryList(loose));

    for (const [name, items] of orderedFolders(foldersOf(entries), layout.folderOrder)) {
      article.append(folder(name, items, layout));
    }
  } else {
    const empty = document.createElement('p');
    empty.innerHTML = '<small>Nothing published yet.</small>';
    article.append(empty);
  }

  main.append(article);
}

// -- opening a service ---------------------------------------------------------

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

function maskedSecret(secret) {
  const prefix = String(secret).match(/^[a-z]+_/)?.[0] || '';
  return `${prefix}***`;
}

/// The one presentation for secrets handed to the CLI. Only the prefix and a
/// mask enter the DOM; the full command stays in this closure for clipboard use.
function renderSecretCommand(container, verb, secret) {
  const command = `devsite ${verb} ${secret}`;
  const group = document.createElement('div');
  group.className = 'secret-command';
  group.setAttribute('role', 'group');
  group.setAttribute('aria-label', `devsite ${verb} command`);

  const code = document.createElement('code');
  const executable = document.createElement('span');
  executable.className = 'command-executable';
  executable.textContent = 'devsite';
  const action = document.createElement('span');
  action.className = 'command-verb';
  action.textContent = verb;
  const masked = document.createElement('span');
  masked.className = 'command-secret';
  masked.textContent = maskedSecret(secret);
  code.append(executable, ' ', action, ' ', masked);
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = 'Copy';

  const status = document.createElement('small');
  status.className = 'secret-copy-status';
  status.setAttribute('aria-live', 'polite');
  button.addEventListener('click', async () => {
    await navigator.clipboard.writeText(command);
    status.textContent = 'Copied.';
  });

  group.append(code, button);
  container.replaceChildren(group, status);
}

function renderTicketPrompt(resourceId, container, status) {
  container.innerHTML = `
    <p>This is a private TCP service. Mint a short-lived ticket, then connect it to a loopback port with the CLI.</p>
    <button type="button" class="get-ticket">Get ticket</button>`;
  status.textContent = '';

  container.querySelector('.get-ticket').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.setAttribute('aria-busy', 'true');
    status.textContent = '';
    try {
      const result = await api(`/api/services/${encodeURIComponent(resourceId)}/ticket`, {
        method: 'POST',
        body: '{}',
      });
      container.innerHTML = `
        <p>This ticket can be redeemed once and expires shortly.</p>
        <div class="secret-command-slot"></div>`;
      renderSecretCommand(container.querySelector('.secret-command-slot'), 'connect', result.ticket);
    } catch (err) {
      button.removeAttribute('aria-busy');
      status.textContent = err.message;
    }
  });
}

function openService(item) {
  $('viewer-title').textContent = item.owner_handle
    ? `${item.name} — @${item.owner_handle}`
    : item.name;
  renderTicketPrompt(item.resource_id, $('viewer-body'), $('viewer-status'));
  openViewer();
}

// -- setup views ---------------------------------------------------------------

function prefersHomebrewInstall() {
  const platform = navigator.userAgentData?.platform || navigator.platform || '';
  return /mac/i.test(platform) || /Macintosh|Mac OS X/i.test(navigator.userAgent);
}

function installControlMarkup() {
  return prefersHomebrewInstall()
    ? `<fieldset role="group">
        <input id="install-command" aria-label="Homebrew install command"
               value="brew install FelineStateMachine/tap/devsite" readonly>
        <button id="copy-install" type="button">Copy</button>
      </fieldset>`
    : `<fieldset role="group">
        <input aria-label="Latest binary release"
               value="GitHub · latest devsite binary release" readonly>
        <a href="https://github.com/FelineStateMachine/devsite/releases/latest"
           role="button">Download</a>
      </fieldset>`;
}

function bindInstallControl() {
  const installCommand = $('install-command');
  const copyInstall = $('copy-install');
  if (!installCommand || !copyInstall) return;

  let copyReset;
  copyInstall.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(installCommand.value);
      copyInstall.textContent = 'Copied';
      clearTimeout(copyReset);
      copyReset = setTimeout(() => { copyInstall.textContent = 'Copy'; }, 1400);
    } catch {
      copyInstall.textContent = 'Select';
      installCommand.select();
    }
  });
}

function renderSignedOut() {
  setPageTitle('home');
  clearTheme();
  document.querySelector('.brand strong').hidden = true;
  main.innerHTML = `
    <article>
      <hgroup>
        <h1 aria-label="dev.site"><span aria-hidden="true">    █                                ▀      ▄
 ▄▄▄█   ▄▄▄   ▄   ▄          ▄▄▄   ▄▄▄    ▄▄█▄▄   ▄▄▄
█▀ ▀█  █▀  █  ▀▄ ▄▀         █   ▀    █      █    █▀  █
█   █  █▀▀▀▀   █▄█           ▀▀▀▄    █      █    █▀▀▀▀
▀█▄██  ▀█▄▄▀    █      █    ▀▄▄▄▀  ▄▄█▄▄    ▀▄▄  ▀█▄▄▀</span></h1>
        <p>links and services across all of your development sites</p>
      </hgroup>
      <figure class="sequence">
        <figcaption>authorization only - no service bytes</figcaption>
        <header aria-hidden="true">
          <strong>host cli</strong>
          <strong>dev.site</strong>
          <strong>approved user</strong>
        </header>
        <div>
          <i aria-hidden="true"></i><i aria-hidden="true"></i><i aria-hidden="true"></i>
          <ol aria-label="A host publishes as an endpoint. An approved user redeems a one-use ticket into a client-bound session, requests a signed capability for each connection, then opens an end-to-end encrypted Iroh QUIC stream to the host service.">
            <li><span>publish endpoint id</span></li>
            <li><span>redeem one-use ticket + client key</span></li>
            <li><span>client-bound session</span></li>
            <li><span>request one-stream capability</span></li>
            <li><span>signed capability + daemon id</span></li>
            <li><span>end-to-end encrypted Iroh QUIC</span></li>
          </ol>
        </div>
      </figure>
    </article>

    <section aria-labelledby="install-title">
      <h2 id="install-title">Install</h2>
      ${installControlMarkup()}
    </section>

    <hr>

    <details>
      <summary>Overview</summary>
      <p>Store useful URLs, shared services, and temporary access</p>
      <article>
        <h3>Machine Enrollment</h3>
        <pre><code>devsite login dsm_***</code></pre>
        <blockquote>Use a revocable machine credential from your dashboard</blockquote>
      </article>
      <article>
        <h3>Add Links to your site</h3>
        <pre><code>devsite link set --name docs --url https://docs.example.com --public</code></pre>
        <blockquote>List a public, private, shared URLs on your page</blockquote>
      </article>
      <article>
        <h3>Share your Services</h3>
        <pre><code>devsite service host 5432 --name postgres</code></pre>
        <blockquote>
          <p>Access any local TCP port. never publicly accessible</p>
          <p>Service is accessed anywhere with a single use ticket.</p>
        </blockquote>
        <pre><code>devsite connect dst_***</code></pre>
      </article>
      <article>
        <h3>Persist the Daemon</h3>
        <pre><code>devsite daemon run</code></pre>
        <blockquote>autorun it with Homebrew services or systemd</blockquote>
      </article>
    </details>`;

  pageFooter.innerHTML = `
    <nav aria-label="Footer">
      <ul><li><a href="https://github.com/FelineStateMachine/devsite"
                 target="_blank" rel="noopener">GitHub</a></li></ul>
    </nav>`;
  pageFooter.hidden = false;
  bindInstallControl();
}

function renderClaimHandle() {
  setPageTitle('dashboard');
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
      location.assign('/');
    } catch (err) {
      field.setAttribute('aria-invalid', 'true');
      note.innerHTML = `<span class="error">${esc(err.message)}</span>`;
    }
  });
}

function formatTime(seconds) {
  return seconds ? new Date(seconds * 1000).toLocaleString() : 'never';
}

function resourceControl(resource) {
  const item = document.createElement('li');
  const shares = resource.shares || (resource.shared_with || [])
    .map((handle) => ({ handle, status: 'accepted' }));
  item.innerHTML = `
    <div>
      <strong>${esc(resource.name)}</strong>
      <small>${esc(resource.kind)} - ${esc(resource.visibility)}</small>
    </div>
    <div class="dashboard-actions"></div>`;
  const actions = item.querySelector('.dashboard-actions');
  for (const share of shares) {
    const button = document.createElement('button');
    button.className = 'secondary outline revoke-share';
    button.type = 'button';
    button.textContent = `Revoke @${share.handle} - ${share.status}`;
    button.addEventListener('click', async () => {
      button.setAttribute('aria-busy', 'true');
      try {
        await api(`/api/resources/${encodeURIComponent(resource.resource_id)}/shares`, {
          method: 'PUT',
          body: JSON.stringify({
            share_with: shares
              .filter((value) => value.handle !== share.handle)
              .map((value) => value.handle),
          }),
        });
        await showDashboard();
      } catch (err) {
        button.removeAttribute('aria-busy');
        button.setAttribute('aria-invalid', 'true');
        button.title = err.message;
      }
    });
    actions.append(button);
  }
  if (!shares.length) actions.innerHTML = '<small>No individual shares</small>';
  return item;
}

function incomingShareControl(share) {
  const item = document.createElement('li');
  const destination = share.url
    ? ` - <span data-selectable>${esc(share.url)}</span>`
    : '';
  item.innerHTML = `
    <div>
      <strong>${esc(share.name)}</strong>
      <small>from @${esc(share.owner_handle)} - ${esc(share.kind)}${destination}</small>
    </div>
    <div class="dashboard-actions"></div>`;
  const actions = item.querySelector('.dashboard-actions');

  if (share.status === 'pending') {
    const accept = document.createElement('button');
    accept.type = 'button';
    accept.textContent = 'Accept';
    accept.addEventListener('click', async () => {
      accept.setAttribute('aria-busy', 'true');
      try {
        await api(`/api/share-invitations/${encodeURIComponent(share.resource_id)}/accept`, {
          method: 'POST',
        });
        await showDashboard();
      } catch (err) {
        accept.removeAttribute('aria-busy');
        accept.setAttribute('aria-invalid', 'true');
        accept.title = err.message;
      }
    });
    actions.append(accept);
  }

  const decline = document.createElement('button');
  decline.className = 'secondary outline';
  decline.type = 'button';
  decline.textContent = share.status === 'pending' ? 'Decline' : 'Remove';
  decline.addEventListener('click', async () => {
    decline.setAttribute('aria-busy', 'true');
    try {
      await api(`/api/share-invitations/${encodeURIComponent(share.resource_id)}`, {
        method: 'DELETE',
      });
      await showDashboard();
    } catch (err) {
      decline.removeAttribute('aria-busy');
      decline.setAttribute('aria-invalid', 'true');
      decline.title = err.message;
    }
  });
  actions.append(decline);
  return item;
}

function credentialControl(credential) {
  const item = document.createElement('li');
  item.innerHTML = `
    <div>
      <strong>${esc(credential.name)}</strong>
      <small>last used ${esc(formatTime(credential.last_used_at))}</small>
    </div>`;
  const button = document.createElement('button');
  button.className = 'secondary outline';
  button.type = 'button';
  button.textContent = 'Revoke';
  button.addEventListener('click', async () => {
    button.setAttribute('aria-busy', 'true');
    try {
      await api(`/api/machine-credentials/${encodeURIComponent(credential.id)}`, {
        method: 'DELETE',
      });
      await showDashboard();
    } catch (err) {
      button.removeAttribute('aria-busy');
      button.setAttribute('aria-invalid', 'true');
      button.title = err.message;
    }
  });
  item.append(button);
  return item;
}

async function signOut(button) {
  button.setAttribute('aria-busy', 'true');
  try {
    await api('/api/auth/session', { method: 'DELETE' });
  } catch (err) {
    button.removeAttribute('aria-busy');
    button.setAttribute('aria-invalid', 'true');
    button.title = err.message;
    return;
  }

  try {
    if (window.Shoo?.clearIdentity) await window.Shoo.clearIdentity();
  } catch (err) {
    // The dev.site session is already gone; a Shoo cleanup failure must not
    // leave the dashboard looking authenticated.
    console.warn('Shoo identity cleanup failed', err);
  }
  sessionStorage.removeItem('pkce_verifier');
  sessionStorage.removeItem('pkce_state');
  sessionStorage.removeItem('return_to');
  me = null;
  history.replaceState({}, '', '/');
  clearTheme();
  renderSession();
  renderSignedOut();
}

async function showDashboard(newCredential = null) {
  setPageTitle('dashboard');
  clearTheme();
  main.setAttribute('aria-busy', 'true');
  const [resourceListing, incomingListing, credentialListing, settings] = await Promise.all([
    api('/api/resources'),
    api('/api/share-invitations'),
    api('/api/machine-credentials'),
    api('/api/profile/settings'),
  ]);

  main.innerHTML = `
    <hgroup>
      <h1>@${esc(me.handle)}</h1>
      <p>Manage what your profile reveals and which machines may change it.</p>
    </hgroup>

    <article>
      <header><strong>Profile</strong></header>
      <p><a href="/@${esc(me.handle)}">View your profile</a></p>
      <label>
        <input id="private-only" type="checkbox" role="switch"
               ${settings.private_only ? 'checked' : ''}>
        Private-only profile
      </label>
      <small>When enabled, only you can open the profile page. Services accepted by other
      people still appear as ordinary entries on their own profiles.</small>
      <p id="profile-settings-status"></p>
    </article>

    <article>
      <details>
        <summary><strong>Incoming shares</strong></summary>
        <p>Nothing is added to your profile until you accept it. Link destinations are shown
        as text so you can inspect them without opening them.</p>
        <ul class="dashboard-list" id="incoming-shares"></ul>
      </details>
    </article>

    <article>
      <details>
        <summary><strong>Shared by you</strong></summary>
        <ul class="dashboard-list" id="dashboard-resources"></ul>
      </details>
    </article>

    <article>
      <details${newCredential ? ' open' : ''}>
        <summary><strong>Machine credentials</strong></summary>
        <p>Each credential remains valid until you revoke it. Its secret is shown once.</p>
        <form id="credential-form">
          <fieldset role="group">
            <input id="credential-name" name="name" maxlength="60"
                   placeholder="This MacBook" aria-label="Machine name" required>
            <button type="submit">Create</button>
          </fieldset>
          <small id="credential-note"></small>
        </form>
        <div id="new-machine-token"></div>
        <ul class="dashboard-list" id="machine-credentials"></ul>
      </details>
    </article>

    <article aria-labelledby="install-title">
      <header id="install-title">Install</header>
      ${installControlMarkup()}
    </article>

    <article>
      <header><strong>Session</strong></header>
      <button id="logout" type="button" class="secondary outline">Log out</button>
    </article>`;

  const resources = $('dashboard-resources');
  if (resourceListing.resources.length) {
    resourceListing.resources.forEach((resource) => resources.append(resourceControl(resource)));
  } else {
    resources.innerHTML = '<li><small>No resources yet. Add one with the CLI.</small></li>';
  }

  const incoming = $('incoming-shares');
  if (incomingListing.shares.length) {
    incomingListing.shares.forEach((share) => incoming.append(incomingShareControl(share)));
  } else {
    incoming.innerHTML = '<li><small>No incoming shares.</small></li>';
  }

  const credentials = $('machine-credentials');
  if (credentialListing.credentials.length) {
    credentialListing.credentials.forEach((credential) =>
      credentials.append(credentialControl(credential)));
  } else {
    credentials.innerHTML = '<li><small>No machine credentials yet.</small></li>';
  }

  if (newCredential) {
    $('new-machine-token').innerHTML = `
      <p><strong>${esc(newCredential.name)}</strong> is ready.</p>
      <div class="secret-command-slot"></div>`;
    renderSecretCommand(
      $('new-machine-token').querySelector('.secret-command-slot'),
      'login',
      newCredential.token,
    );
  }

  $('logout').addEventListener('click', (event) => signOut(event.currentTarget));
  bindInstallControl();

  $('private-only').addEventListener('change', async (event) => {
    const input = event.currentTarget;
    const status = $('profile-settings-status');
    input.setAttribute('aria-busy', 'true');
    try {
      await api('/api/profile/settings', {
        method: 'PUT',
        body: JSON.stringify({ private_only: input.checked }),
      });
      status.innerHTML = '<small class="ok">Saved.</small>';
    } catch (err) {
      input.checked = !input.checked;
      status.innerHTML = `<small class="error">${esc(err.message)}</small>`;
    } finally {
      input.removeAttribute('aria-busy');
    }
  });

  $('credential-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector('button');
    const note = $('credential-note');
    button.setAttribute('aria-busy', 'true');
    try {
      const created = await api('/api/machine-credentials', {
        method: 'POST',
        body: JSON.stringify({ name: $('credential-name').value }),
      });
      await showDashboard({ name: created.credential.name, token: created.token });
    } catch (err) {
      button.removeAttribute('aria-busy');
      note.innerHTML = `<span class="error">${esc(err.message)}</span>`;
    }
  });

  main.removeAttribute('aria-busy');
}

// -- routing -------------------------------------------------------------------

async function route() {
  const path = location.pathname;
  setPageTitle();

  if (path === '/auth/callback') {
    main.innerHTML = '<article aria-busy="true">Signing you in…</article>';
    try {
      const { session, returnTo } = await completeSignIn();
      me = { account_id: session.account_id, handle: session.handle };
      history.replaceState({}, '', '/');
      renderSession();
      if (!session.handle) {
        renderClaimHandle();
      } else {
        await showDashboard();
      }
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

  const serviceMatch = path.match(/^\/s\/(res_[a-z2-7]+)$/);
  if (serviceMatch) {
    clearTheme();
    main.innerHTML = `
      <article>
        <hgroup>
          <h1>Private TCP service</h1>
          <p>Access is checked for each connection.</p>
        </hgroup>
        <div id="service-connect"></div>
        <p id="service-status"></p>
        <p><small>The CLI opens a loopback port and carries its byte stream through Iroh.</small></p>
      </article>`;
    if (me) {
      renderTicketPrompt(serviceMatch[1], $('service-connect'), $('service-status'));
    } else {
      $('service-connect').innerHTML = '<p>Sign in from the header to request access.</p>';
    }
    return;
  }

  if (!me) { renderSignedOut(); return; }
  if (!me.handle) { renderClaimHandle(); return; }
  await showDashboard();
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

$('viewer-close').addEventListener('click', closeViewer);
$('viewer').addEventListener('click', (e) => { if (e.target === $('viewer')) closeViewer(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeViewer(); });

updateLogoContrast();
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () =>
  requestAnimationFrame(updateLogoContrast));
main.removeAttribute('aria-busy');
await route();
