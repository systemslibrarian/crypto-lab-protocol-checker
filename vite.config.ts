/// <reference types="vitest" />
import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-protocol-checker/',
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
});
