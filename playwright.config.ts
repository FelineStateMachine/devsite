import { defineConfig } from '@playwright/test';

export default defineConfig({
  outputDir: 'output/playwright/test-results',
  reporter: 'line',
  testDir: 'web',
  use: {
    browserName: 'chromium',
    headless: true,
    trace: 'retain-on-failure',
  },
});
