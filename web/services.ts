import { api, element, errorMessage, query } from './shared';
import { renderSecretCommand } from './secrets';
import { clearTheme } from './theme';

interface ServicePrompt {
  resource_id: string;
  name: string;
  owner_handle?: string;
}

function openServiceTicketDialog() {
  document.documentElement.classList.add('modal-is-open', 'modal-is-opening');
  element('service-ticket-dialog').setAttribute('open', '');
  setTimeout(() => document.documentElement.classList.remove('modal-is-opening'), 400);
}

function closeServiceTicketDialog() {
  document.documentElement.classList.remove('modal-is-open', 'modal-is-opening');
  element('service-ticket-dialog').removeAttribute('open');
  element('service-ticket-body').replaceChildren();
}

export function renderServiceTicketPrompt(
  resourceId: string,
  container: HTMLElement,
  status: HTMLElement,
) {
  container.innerHTML = `
    <p>This is a private TCP service. Mint a short-lived ticket, then connect it to a loopback port with the CLI.</p>
    <button type="button" class="get-ticket">Get ticket</button>`;
  status.textContent = '';

  query<HTMLButtonElement>('.get-ticket', container).addEventListener('click', async (event) => {
    const button = event.currentTarget as HTMLButtonElement;
    button.setAttribute('aria-busy', 'true');
    status.textContent = '';
    try {
      const result = await api<{ ticket: string }>(
        `/api/services/${encodeURIComponent(resourceId)}/ticket`,
        { method: 'POST', body: '{}' },
      );
      container.innerHTML = `
        <p>This ticket can be redeemed once and expires shortly.</p>
        <div class="secret-command-slot"></div>`;
      renderSecretCommand(query('.secret-command-slot', container), 'connect', result.ticket);
    } catch (error) {
      button.removeAttribute('aria-busy');
      status.textContent = errorMessage(error);
    }
  });
}

function showServiceTicketDialog(item: ServicePrompt) {
  element('service-ticket-title').textContent = item.owner_handle
    ? `${item.name} - @${item.owner_handle}`
    : item.name;
  renderServiceTicketPrompt(
    item.resource_id,
    element('service-ticket-body'),
    element('service-ticket-status'),
  );
  openServiceTicketDialog();
}

export function showServiceRoute(resourceId: string, signedIn: boolean) {
  clearTheme();
  const main = element('main');
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
  if (signedIn) {
    renderServiceTicketPrompt(resourceId, element('service-connect'), element('service-status'));
  } else {
    element('service-connect').innerHTML = '<p>Sign in from the header to request access.</p>';
  }
}

export function bindServiceDialogs(main: HTMLElement) {
  main.addEventListener('click', (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest<HTMLButtonElement>('button[data-service-id]');
    if (!button?.dataset.serviceId || !button.dataset.serviceName) return;
    showServiceTicketDialog({
      resource_id: button.dataset.serviceId,
      name: button.dataset.serviceName,
      ...(button.dataset.serviceOwner ? { owner_handle: button.dataset.serviceOwner } : {}),
    });
  });

  element('service-ticket-close').addEventListener('click', closeServiceTicketDialog);
  element('service-ticket-dialog').addEventListener('click', (event) => {
    if (event.target === element('service-ticket-dialog')) closeServiceTicketDialog();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeServiceTicketDialog();
  });
}
