import { defineConfig } from '@playwright/test';

// Local preview port unique to this lab (fleet uses 4173/42xx/43xx elsewhere;
// 4317 is unused by any sibling). Never 4173 — a shared port makes
// reuseExistingServer silently scan a different lab's preview.
export default defineConfig({
  testDir: './e2e',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4317/crypto-lab-protocol-checker/',
    colorScheme: 'dark',
  },
  webServer: {
    command: 'npm run preview -- --port 4317 --strictPort',
    url: 'http://localhost:4317/crypto-lab-protocol-checker/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
