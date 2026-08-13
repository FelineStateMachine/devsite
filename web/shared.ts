export interface Me {
  account_id: string;
  handle: string | null;
}

export function element<T extends HTMLElement = HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!(found instanceof HTMLElement)) throw new Error(`#${id} is missing`);
  return found as T;
}

export function query<T extends Element = HTMLElement>(
  selector: string,
  root: ParentNode = document,
): T {
  const found = root.querySelector(selector);
  if (!found) throw new Error(`${selector} is missing`);
  return found as T;
}

export const escapeHtml = (value: unknown) =>
  String(value).replace(/[&<>"']/g, (character) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]
      ?? character));

export function setPageTitle(suffix = '') {
  document.title = suffix ? `dev.site - ${suffix}` : 'dev.site';
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as { error?: string };
    throw new Error(body.error ?? `${response.status}`);
  }
  return (response.status === 204 ? null : await response.json()) as T;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
