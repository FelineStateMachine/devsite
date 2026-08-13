import 'fixi-js';
import '@bigskysoftware/paxi-js';
import '@bigskysoftware/ssexi-js';

import { element, escapeHtml, setPageTitle } from './shared';
import { clearTheme, updateLogoContrast } from './theme';

interface FixiConfig {
  action: string;
  response: Response;
  ssePauseOnHidden?: boolean;
  sseReconnect?: boolean;
  sseSwap?: (target: Element, html: string) => void;
  text: string;
  target: Element;
}

interface FixiEventDetail {
  cfg: FixiConfig;
}

interface SsexiEventDetail extends FixiEventDetail {
  message: {
    data: string;
    event: string;
    id: string;
  };
}

declare global {
  interface Window {
    morph(target: Element, html: string): void;
  }
}

const main = element('main');
let folderState = new Map<string, boolean>();

function profileRequest(config: FixiConfig): boolean {
  return config.action.startsWith('/ui/profile/');
}

function renderMissingProfile(handle: string, message = 'does not exist') {
  clearTheme();
  main.removeAttribute('data-profile-handle');
  main.removeAttribute('data-profile-scheme');
  main.removeAttribute('aria-busy');
  main.innerHTML = `
    <article>
      <hgroup>
        <h1>No such profile.</h1>
        <p>@${escapeHtml(handle)} ${escapeHtml(message)}</p>
      </hgroup>
    </article>`;
}

document.addEventListener('fx:config', (event) => {
  const config = (event as CustomEvent<FixiEventDetail>).detail.cfg;
  if (!profileRequest(config)) return;
  config.sseReconnect = true;
  config.ssePauseOnHidden = true;
  config.sseSwap = (target, html) => window.morph(target, html);
});

document.addEventListener('fx:sse:message', (event) => {
  const detail = (event as CustomEvent<SsexiEventDetail>).detail;
  if (!profileRequest(detail.cfg)) return;
  folderState = new Map(
    [...main.querySelectorAll<HTMLDetailsElement>('details[data-folder]')]
      .map((folder) => [folder.dataset.folder ?? '', folder.open]),
  );
});

document.addEventListener('fx:sse:swapped', (event) => {
  const detail = (event as CustomEvent<SsexiEventDetail>).detail;
  if (!profileRequest(detail.cfg) || event.target !== main) return;
  const handle = main.dataset.profileHandle;
  const scheme = main.dataset.profileScheme;
  if (!handle) return;
  document.documentElement.dataset.profile = handle;
  if (scheme === 'light' || scheme === 'dark') {
    document.documentElement.dataset.theme = scheme;
  } else {
    delete document.documentElement.dataset.theme;
  }
  for (const folder of main.querySelectorAll<HTMLDetailsElement>('details[data-folder]')) {
    const open = folderState.get(folder.dataset.folder ?? '');
    if (open !== undefined) folder.open = open;
  }
  folderState.clear();
  setPageTitle(`@${handle}`);
  requestAnimationFrame(updateLogoContrast);
});

document.addEventListener('fx:after', (event) => {
  const detail = (event as CustomEvent<FixiEventDetail>).detail;
  if (!profileRequest(detail.cfg) || detail.cfg.response.ok) return;
  event.preventDefault();
  renderMissingProfile(decodeURIComponent(location.pathname.slice(2)));
});

document.addEventListener('fx:sse:unavailable', () => {
  renderMissingProfile(decodeURIComponent(location.pathname.slice(2)));
});

export function showProfile(handle: string) {
  setPageTitle(`@${handle}`);
  clearTheme();
  main.setAttribute('aria-busy', 'true');
  main.innerHTML = '<article><p>Loading profile.</p></article>';
  main.setAttribute('fx-action', `/ui/profile/${encodeURIComponent(handle)}/stream`);
  main.setAttribute('fx-method', 'GET');
  main.setAttribute('fx-swap', 'morph');
  main.setAttribute('fx-trigger', 'profile:load');
  main.dispatchEvent(new CustomEvent('fx:process', { bubbles: true, composed: true }));
  main.dispatchEvent(new Event('profile:load'));
}
