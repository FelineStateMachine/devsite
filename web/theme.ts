import { element, query } from './shared';

function parseComputedColor(
  value: string,
): { rgb: [number, number, number]; alpha: number } | null {
  const match = value.match(
    /^rgba?\(\s*([\d.]+)[, ]+\s*([\d.]+)[, ]+\s*([\d.]+)(?:\s*[,/]\s*([\d.]+))?\s*\)$/i,
  );
  if (!match) return null;
  return {
    rgb: [Number(match[1]), Number(match[2]), Number(match[3])],
    alpha: match[4] === undefined ? 1 : Number(match[4]),
  };
}

function logoBackground() {
  let node = document.querySelector('.brand');
  let alpha = 0;
  const premultiplied: [number, number, number] = [0, 0, 0];
  while (node instanceof Element) {
    const layer = parseComputedColor(getComputedStyle(node).backgroundColor);
    if (layer && layer.alpha > 0) {
      for (const channel of [0, 1, 2] as const) {
        premultiplied[channel] += (layer.rgb[channel] ?? 0) * layer.alpha * (1 - alpha);
      }
      alpha += layer.alpha * (1 - alpha);
      if (alpha >= 0.999) break;
    }
    node = node.parentElement;
  }
  return premultiplied.map((channel) => channel + 255 * (1 - alpha));
}

export function updateLogoContrast() {
  if (!document.getElementById('dev-logo-ring')) return;
  const luminance = logoBackground()
    .map((channel) => channel / 255)
    .map((channel) => channel <= 0.04045
      ? channel / 12.92
      : ((channel + 0.055) / 1.055) ** 2.4)
    .reduce(
      (sum, channel, index) => sum + channel * ([0.2126, 0.7152, 0.0722][index] ?? 0),
      0,
    );
  document.documentElement.style.setProperty(
    '--devsite-logo-ring',
    luminance < 0.179 ? 'rgb(255,255,255)' : 'rgb(0,0,0)',
  );
}

export function clearTheme() {
  query<HTMLElement>('.brand strong').hidden = false;
  delete document.documentElement.dataset.profile;
  delete document.documentElement.dataset.theme;
  element('profile-theme').textContent = '';
  const footer = element('page-footer');
  footer.replaceChildren();
  footer.hidden = true;
  requestAnimationFrame(updateLogoContrast);
}

export function watchLogoContrast() {
  updateLogoContrast();
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () =>
    requestAnimationFrame(updateLogoContrast));
}
