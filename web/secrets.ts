function maskedSecret(secret: string): string {
  const prefix = String(secret).match(/^[a-z]+_/)?.[0] || '';
  return `${prefix}***`;
}

export function renderSecretCommand(container: Element, verb: string, secret: string) {
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
