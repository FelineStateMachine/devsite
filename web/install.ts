interface NavigatorWithUserAgentData extends Navigator {
  userAgentData?: { platform?: string };
}

function prefersHomebrewInstall() {
  const platform = (navigator as NavigatorWithUserAgentData).userAgentData?.platform
    || navigator.platform || '';
  return /mac/i.test(platform) || /Macintosh|Mac OS X/i.test(navigator.userAgent);
}

export function installControlMarkup() {
  return prefersHomebrewInstall()
    ? `<fieldset role="group">
        <input id="install-command" aria-label="Homebrew install command"
               value="brew install FelineStateMachine/tap/devsite" readonly>
        <button id="copy-install" type="button">Copy</button>
      </fieldset>`
    : `<fieldset role="group">
        <input aria-label="Latest binary release"
               value="GitHub - latest devsite binary release" readonly>
        <a href="https://github.com/FelineStateMachine/devsite/releases/latest"
           role="button">Download</a>
      </fieldset>`;
}

export function bindInstallControl() {
  const installCommand = document.getElementById('install-command');
  const copyInstall = document.getElementById('copy-install');
  if (!(installCommand instanceof HTMLInputElement)
      || !(copyInstall instanceof HTMLButtonElement)) return;

  let copyReset: ReturnType<typeof setTimeout> | undefined;
  copyInstall.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(installCommand.value);
      copyInstall.textContent = 'Copied';
      clearTimeout(copyReset);
      copyReset = setTimeout(() => {
        copyInstall.textContent = 'Copy';
      }, 1400);
    } catch {
      copyInstall.textContent = 'Select';
      installCommand.select();
    }
  });
}
