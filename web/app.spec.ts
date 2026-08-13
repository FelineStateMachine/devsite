import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
import { expect, test, type Route } from '@playwright/test';

const webRoot = join(process.cwd(), 'web');

const contentTypes: Record<string, string> = {
  '.css': 'text/css',
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.woff2': 'font/woff2',
};

async function staticResponse(route: Route, pathname: string) {
  const relativePath = pathname === '/' || pathname.startsWith('/@')
    ? 'index.html' : pathname.replace(/^\//, '');
  if (relativePath.includes('..')) {
    await route.fulfill({ status: 404 });
    return;
  }
  const body = await readFile(join(webRoot, relativePath));
  await route.fulfill({
    body,
    contentType: contentTypes[extname(relativePath)] ?? 'application/octet-stream',
  });
}

function sseEvent(data: string, event?: string, id?: string): string {
  return `${event ? `event: ${event}\n` : ''}${id ? `id: ${id}\n` : ''}`
    + `${data.split('\n').map((line) => `data: ${line}\n`).join('')}\n`;
}

test('an incoming share uses the Fixi UI endpoint', async ({ page }) => {
  let acceptRequests = 0;
  let removeRequests = 0;
  await page.route('https://dev.site.test/**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const json = async (value: unknown) => route.fulfill({ json: value });

    if (pathname === '/api/me') {
      await json({ account_id: 'acct_test', handle: 'alice' });
    } else if (pathname === '/api/resources') {
      await json({ resources: [] });
    } else if (pathname === '/api/share-invitations') {
      await json({
        shares: [{
          kind: 'link',
          name: 'runbook',
          owner_handle: 'bob',
          resource_id: 'res_test',
          status: 'pending',
          url: 'https://example.com/runbook',
        }],
      });
    } else if (pathname === '/api/machine-credentials') {
      await json({ credentials: [] });
    } else if (pathname === '/api/profile/settings') {
      await json({ private_only: false });
    } else if (pathname === '/ui/share-invitations/res_test/accept') {
      acceptRequests += 1;
      expect(request.method()).toBe('POST');
      expect(request.headers()['fx-request']).toBe('true');
      await route.fulfill({
        body: `<li><div><strong>runbook</strong><small>from @bob - link</small></div>
          <div class="dashboard-actions"><button class="secondary outline" type="button"
            fx-action="/ui/share-invitations/res_test" fx-method="DELETE"
            fx-target="#incoming-shares" fx-swap="innerHTML">Remove</button></div></li>`,
        contentType: 'text/html',
      });
    } else if (pathname === '/ui/share-invitations/res_test') {
      removeRequests += 1;
      expect(request.method()).toBe('DELETE');
      expect(request.headers()['fx-request']).toBe('true');
      await route.fulfill({
        body: '<li><small>No incoming shares.</small></li>',
        contentType: 'text/html',
      });
    } else {
      await staticResponse(route, pathname);
    }
  });

  await page.goto('https://dev.site.test/');
  await expect(page.getByRole('heading', { name: '@alice' })).toBeVisible();
  await page.getByText('Incoming shares', { exact: true }).click();
  await page.getByRole('button', { name: 'Accept' }).click();
  await expect(page.getByRole('button', { name: 'Remove' })).toBeVisible();
  expect(acceptRequests).toBe(1);

  await page.getByRole('button', { name: 'Remove' }).click();

  await expect(page.getByText('No incoming shares.')).toBeVisible();
  expect(removeRequests).toBe(1);
});

test('a profile hydrates and updates from one SSEXi response', async ({ page }) => {
  let streamRequests = 0;
  await page.route('https://dev.site.test/**', async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname === '/api/me') {
      await route.fulfill({ status: 204 });
    } else if (pathname === '/ui/profile/alice/stream') {
      streamRequests += 1;
      const themeEvent = JSON.stringify({ target: '#profile-theme', swap: 'textContent' });
      const initial = '<main class="container" id="main" data-profile-handle="alice" '
        + 'data-profile-scheme="dark"><article id="profile"><hgroup><h1>@alice</h1>'
        + '<p>1 site</p></hgroup><ul class="entries"><li class="entry" id="site-res_one" '
        + 'data-kind="link" data-visibility="public"><a href="https://one.example">one</a>'
        + '</li></ul></article></main>';
      const updated = '<main class="container" id="main" data-profile-handle="alice" '
        + 'data-profile-scheme="dark"><article id="profile"><hgroup><h1>@alice</h1>'
        + '<p>2 sites</p></hgroup><ul class="entries"><li class="entry" id="site-res_one" '
        + 'data-kind="link" data-visibility="public"><a href="https://one.example">one</a>'
        + '</li><li class="entry" id="site-res_two" data-kind="link" '
        + 'data-visibility="public"><a href="https://two.example">two</a></li></ul>'
        + '</article></main>';
      await route.fulfill({
        body: sseEvent(':root[data-profile="alice"] { --pico-primary: rebeccapurple; }', themeEvent, '1')
          + sseEvent(initial, undefined, '1')
          + sseEvent(updated, undefined, '2'),
        contentType: 'text/event-stream',
      });
    } else {
      await staticResponse(route, pathname);
    }
  });

  await page.goto('https://dev.site.test/@alice');
  await expect(page.getByRole('heading', { name: '@alice' })).toBeVisible();
  await expect(page.getByText('2 sites')).toBeVisible();
  await expect(page.getByRole('link', { name: 'two' })).toBeVisible();
  await expect(page.locator('html[data-profile="alice"][data-theme="dark"]')).toBeAttached();
  expect(await page.locator('#profile-theme').textContent()).toContain('rebeccapurple');
  expect(streamRequests).toBe(1);
});
