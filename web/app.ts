import { renderClaimHandle, showDashboard } from './dashboard';
import { renderSignedOut } from './home';
import { showProfile } from './profile';
import { bindServiceDialogs, showServiceRoute } from './services';
import { api, element, escapeHtml, type Me, setPageTitle } from './shared';
import { clearTheme, watchLogoContrast } from './theme';

const main = element('main');
let me: Me | null = null;

function startSignIn() {
  const returnTo = `${location.pathname}${location.search}`;
  location.assign(`/auth/start?return_to=${encodeURIComponent(returnTo)}`);
}

function renderSession() {
  const session = element('session');
  if (!me) {
    session.innerHTML = '<li><a href="#" id="signin" role="button" class="outline">Sign in</a></li>';
    element('signin').addEventListener('click', (event) => {
      event.preventDefault();
      startSignIn();
    });
    return;
  }
  session.innerHTML = me.handle
    ? `<li><a href="/@${escapeHtml(me.handle)}">@${escapeHtml(me.handle)}</a></li>`
    : '<li><small>no handle yet</small></li>';
}

function showSignedOutHome() {
  me = null;
  history.replaceState({}, '', '/');
  clearTheme();
  renderSession();
  renderSignedOut();
}

async function route() {
  const path = location.pathname;
  setPageTitle();
  try {
    me = await api<Me | null>('/api/me');
  } catch {
    me = null;
  }
  renderSession();

  const handleMatch = path.match(/^\/@([^/]+)$/);
  if (handleMatch) {
    showProfile(decodeURIComponent(handleMatch[1] ?? ''));
    return;
  }

  const serviceMatch = path.match(/^\/s\/(res_[a-z2-7]+)$/);
  if (serviceMatch) {
    showServiceRoute(serviceMatch[1] ?? '', me !== null);
    return;
  }

  if (!me) {
    renderSignedOut();
    return;
  }
  if (!me.handle) {
    renderClaimHandle();
    return;
  }
  await showDashboard(me.handle, showSignedOutHome);
}

bindServiceDialogs(main);
watchLogoContrast();
main.removeAttribute('aria-busy');
await route();
