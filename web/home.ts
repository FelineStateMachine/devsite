import { bindInstallControl, installControlMarkup } from './install';
import { element, query, setPageTitle } from './shared';
import { clearTheme } from './theme';

const CLI_VERBS = new Set([
  'access', 'connect', 'daemon', 'grant', 'host', 'link', 'login', 'request',
  'resolve', 'run', 'service', 'set',
]);

function highlightCliExamples(container: Element) {
  container.querySelectorAll('pre > code').forEach((code) => {
    const source = code.textContent;
    if (!source.trimStart().startsWith('devsite ')) return;

    const highlighted = document.createDocumentFragment();
    let wordIndex = 0;
    source.split(/(\s+)/).forEach((token) => {
      if (!token || /^\s+$/.test(token)) {
        highlighted.append(token);
        if (token.includes('\n')) wordIndex = 0;
        return;
      }

      const span = document.createElement('span');
      if (wordIndex === 0 && token === 'devsite') span.className = 'command-executable';
      else if (wordIndex <= 2 && CLI_VERBS.has(token)) span.className = 'command-verb';
      else if (token.startsWith('--')) span.className = 'command-option';
      else if (/^(?:dmt|dsp|dss|dst)_/.test(token)) span.className = 'command-secret';
      else span.className = 'command-value';
      span.textContent = token;
      highlighted.append(span);
      wordIndex += 1;
    });
    code.replaceChildren(highlighted);
  });
}

export function renderSignedOut() {
  setPageTitle('home');
  clearTheme();
  query<HTMLElement>('.brand strong').hidden = true;
  const main = element('main');
  const template = element<HTMLTemplateElement>('home-template');
  main.replaceChildren(template.content.cloneNode(true));
  query<HTMLElement>('[data-install-control]', main).innerHTML = installControlMarkup();

  const footer = element('page-footer');
  footer.innerHTML = `
    <nav aria-label="Footer">
      <ul><li><a href="https://github.com/FelineStateMachine/devsite"
                 target="_blank" rel="noopener">GitHub</a></li></ul>
    </nav>`;
  footer.hidden = false;
  bindInstallControl();
  highlightCliExamples(main);
}
