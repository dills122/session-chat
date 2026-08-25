import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://dills122.github.io',
  base: '/session-chat',
  output: 'static',
  trailingSlash: 'always',
  build: {
    format: 'directory',
  },
});
