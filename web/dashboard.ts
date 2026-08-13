import { bindInstallControl, installControlMarkup } from './install';
import { renderSecretCommand } from './secrets';
import {
  api,
  element,
  errorMessage,
  escapeHtml,
  query,
  setPageTitle,
} from './shared';
import { clearTheme } from './theme';

type Visibility = 'public' | 'private' | 'shared';
type SiteKind = 'link' | 'service';

interface ShareRecipient {
  handle: string;
  status: string;
}

interface Resource {
  resource_id: string;
  name: string;
  kind: SiteKind;
  visibility: Visibility;
  shares?: ShareRecipient[];
  shared_with?: string[];
}

interface IncomingShare {
  resource_id: string;
  name: string;
  kind: SiteKind;
  url?: string;
  owner_handle: string;
  status: string;
}

interface MachineCredential {
  id: string;
  name: string;
  last_used_at: number | null;
  scopes?: string[];
}

interface NewCredential {
  name: string;
  ticket: string;
}

interface FixiEventDetail {
  cfg: {
    response: Response;
    text: string;
  };
  error?: unknown;
}

const main = element('main');

export function renderClaimHandle() {
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

  element('claim-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const field = element<HTMLInputElement>('handle');
    const note = element('claim-note');
    try {
      await api<{ handle: string }>('/api/profile', {
        method: 'POST',
        body: JSON.stringify({ handle: field.value }),
      });
      location.assign('/');
    } catch (error) {
      field.setAttribute('aria-invalid', 'true');
      note.innerHTML = `<span class="error">${escapeHtml(errorMessage(error))}</span>`;
    }
  });
}

function formatTime(seconds: number | null): string {
  return seconds ? new Date(seconds * 1000).toLocaleString() : 'never';
}

function resourceControl(resource: Resource): HTMLLIElement {
  const item = document.createElement('li');
  const shares = resource.shares || (resource.shared_with || [])
    .map((handle) => ({ handle, status: 'accepted' }));
  item.innerHTML = `
    <div>
      <strong>${escapeHtml(resource.name)}</strong>
      <small>${escapeHtml(resource.kind)} - ${escapeHtml(resource.visibility)}</small>
    </div>
    <div class="dashboard-actions"></div>`;
  const actions = query<HTMLElement>('.dashboard-actions', item);
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
      } catch (error) {
        button.removeAttribute('aria-busy');
        button.setAttribute('aria-invalid', 'true');
        button.title = errorMessage(error);
      }
    });
    actions.append(button);
  }
  if (!shares.length) actions.innerHTML = '<small>No individual shares</small>';
  return item;
}

function configureFixiShareAction(
  button: HTMLButtonElement,
  action: string,
  method: 'POST' | 'DELETE',
) {
  button.setAttribute('fx-action', action);
  button.setAttribute('fx-method', method);
  button.setAttribute('fx-target', '#incoming-shares');
  button.setAttribute('fx-swap', 'innerHTML');
}

function shareActionButton(event: Event): HTMLButtonElement | null {
  const button = event.target;
  if (!(button instanceof HTMLButtonElement)) return null;
  return button.getAttribute('fx-action')?.startsWith('/ui/share-invitations/')
    ? button
    : null;
}

document.addEventListener('fx:before', (event) => {
  shareActionButton(event)?.setAttribute('aria-busy', 'true');
});

document.addEventListener('fx:after', (event) => {
  const button = shareActionButton(event);
  if (!button) return;
  const detail = (event as CustomEvent<FixiEventDetail>).detail;
  if (detail.cfg.response.ok) return;
  event.preventDefault();
  button.setAttribute('aria-invalid', 'true');
  try {
    const body = JSON.parse(detail.cfg.text) as { error?: string };
    button.title = body.error ?? `${detail.cfg.response.status}`;
  } catch {
    button.title = `${detail.cfg.response.status}`;
  }
});

document.addEventListener('fx:error', (event) => {
  const button = shareActionButton(event);
  if (!button) return;
  const detail = (event as CustomEvent<FixiEventDetail>).detail;
  button.setAttribute('aria-invalid', 'true');
  button.title = errorMessage(detail.error);
});

document.addEventListener('fx:finally', (event) => {
  shareActionButton(event)?.removeAttribute('aria-busy');
});

function incomingShareControl(share: IncomingShare): HTMLLIElement {
  const item = document.createElement('li');
  const destination = share.url
    ? ` - <span data-selectable>${escapeHtml(share.url)}</span>`
    : '';
  item.innerHTML = `
    <div>
      <strong>${escapeHtml(share.name)}</strong>
      <small>from @${escapeHtml(share.owner_handle)} - ${escapeHtml(share.kind)}${destination}</small>
    </div>
    <div class="dashboard-actions"></div>`;
  const actions = query<HTMLElement>('.dashboard-actions', item);

  if (share.status === 'pending') {
    const accept = document.createElement('button');
    accept.type = 'button';
    accept.textContent = 'Accept';
    configureFixiShareAction(
      accept,
      `/ui/share-invitations/${encodeURIComponent(share.resource_id)}/accept`,
      'POST',
    );
    actions.append(accept);
  }

  const decline = document.createElement('button');
  decline.className = 'secondary outline';
  decline.type = 'button';
  decline.textContent = share.status === 'pending' ? 'Decline' : 'Remove';
  configureFixiShareAction(
    decline,
    `/ui/share-invitations/${encodeURIComponent(share.resource_id)}`,
    'DELETE',
  );
  actions.append(decline);
  return item;
}

function credentialControl(credential: MachineCredential): HTMLLIElement {
  const item = document.createElement('li');
  const scopes = credential.scopes?.length
    ? ` - ${credential.scopes.map((scope) => escapeHtml(scope)).join(', ')}`
    : '';
  item.innerHTML = `
    <div>
      <strong>${escapeHtml(credential.name)}</strong>
      <small>last used ${escapeHtml(formatTime(credential.last_used_at))}${scopes}</small>
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
    } catch (error) {
      button.removeAttribute('aria-busy');
      button.setAttribute('aria-invalid', 'true');
      button.title = errorMessage(error);
    }
  });
  item.append(button);
  return item;
}

let currentHandle = '';
let signOutCallback: (() => void) | undefined;

async function signOut(button: HTMLButtonElement) {
  button.setAttribute('aria-busy', 'true');
  try {
    await api('/api/auth/session', { method: 'DELETE' });
  } catch (error) {
    button.removeAttribute('aria-busy');
    button.setAttribute('aria-invalid', 'true');
    button.title = errorMessage(error);
    return;
  }
  signOutCallback?.();
}

export async function showDashboard(
  handle = currentHandle,
  onSignOut = signOutCallback,
  newCredential: NewCredential | null = null,
) {
  if (!handle) throw new Error('the dashboard needs a profile handle');
  currentHandle = handle;
  signOutCallback = onSignOut;
  setPageTitle('dashboard');
  clearTheme();
  main.setAttribute('aria-busy', 'true');
  const [resourceListing, incomingListing, credentialListing, settings] = await Promise.all([
    api<{ resources: Resource[] }>('/api/resources'),
    api<{ shares: IncomingShare[] }>('/api/share-invitations'),
    api<{ credentials: MachineCredential[] }>('/api/machine-credentials'),
    api<{ private_only: boolean }>('/api/profile/settings'),
  ]);

  main.innerHTML = `
    <hgroup>
      <h1>@${escapeHtml(handle)}</h1>
      <p>Manage what your profile reveals and which machines may change it.</p>
    </hgroup>

    <article>
      <header><strong>Profile</strong></header>
      <p><a href="/@${escapeHtml(handle)}">View your profile</a></p>
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
        <p>Create a single-use ticket that enrolls one Ed25519 machine identity.</p>
        <form id="credential-form">
          <fieldset role="group">
            <input id="credential-name" name="name" maxlength="60"
                   placeholder="This MacBook" aria-label="Machine name" required>
            <button type="submit">Create</button>
          </fieldset>
          <label>
            <input id="credential-service-grants" type="checkbox">
            Allow this machine to issue endpoint-bound service grants
          </label>
          <small>This authority is server-enforced and can be removed by revoking the
          machine credential.</small>
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

  const resources = element('dashboard-resources');
  if (resourceListing.resources.length) {
    resourceListing.resources.forEach((resource) => {
      resources.append(resourceControl(resource));
    });
  } else {
    resources.innerHTML = '<li><small>No resources yet. Add one with the CLI.</small></li>';
  }

  const incoming = element('incoming-shares');
  if (incomingListing.shares.length) {
    incomingListing.shares.forEach((share) => {
      incoming.append(incomingShareControl(share));
    });
  } else {
    incoming.innerHTML = '<li><small>No incoming shares.</small></li>';
  }

  const credentials = element('machine-credentials');
  if (credentialListing.credentials.length) {
    credentialListing.credentials.forEach((credential) => {
      credentials.append(credentialControl(credential));
    });
  } else {
    credentials.innerHTML = '<li><small>No machine credentials yet.</small></li>';
  }

  if (newCredential) {
    element('new-machine-token').innerHTML = `
      <p><strong>${escapeHtml(newCredential.name)}</strong> is ready.</p>
      <div class="secret-command-slot"></div>`;
    renderSecretCommand(
      query('.secret-command-slot', element('new-machine-token')),
      'login',
      newCredential.ticket,
    );
  }

  element('logout').addEventListener('click', (event) =>
    signOut(event.currentTarget as HTMLButtonElement));
  bindInstallControl();

  element('private-only').addEventListener('change', async (event) => {
    const input = event.currentTarget as HTMLInputElement;
    const status = element('profile-settings-status');
    input.setAttribute('aria-busy', 'true');
    try {
      await api('/api/profile/settings', {
        method: 'PUT',
        body: JSON.stringify({ private_only: input.checked }),
      });
      status.innerHTML = '<small class="ok">Saved.</small>';
    } catch (error) {
      input.checked = !input.checked;
      status.innerHTML = `<small class="error">${escapeHtml(errorMessage(error))}</small>`;
    } finally {
      input.removeAttribute('aria-busy');
    }
  });

  element('credential-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const button = query<HTMLButtonElement>('button', form);
    const note = element('credential-note');
    button.setAttribute('aria-busy', 'true');
    try {
      const created = await api<{ credential: { name: string }; ticket: string }>(
        '/api/machine-credentials',
        {
          method: 'POST',
          body: JSON.stringify({
            name: element<HTMLInputElement>('credential-name').value,
            scopes: element<HTMLInputElement>('credential-service-grants').checked
              ? ['service_grants:issue']
              : [],
          }),
        },
      );
      await showDashboard(
        currentHandle,
        signOutCallback,
        { name: created.credential.name, ticket: created.ticket },
      );
    } catch (error) {
      button.removeAttribute('aria-busy');
      note.innerHTML = `<span class="error">${escapeHtml(errorMessage(error))}</span>`;
    }
  });

  main.removeAttribute('aria-busy');
}
