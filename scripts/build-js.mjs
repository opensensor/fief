import { build } from 'esbuild';

const options = {
  bundle: true,
  minify: true,
  format: 'iife',
  platform: 'browser',
  target: ['es2022'],
  logLevel: 'info',
};

await Promise.all([
  build({ ...options, entryPoints: ['js/code-editor.mjs'], outfile: 'fief/static/code-editor.bundle.js' }),
  build({ ...options, entryPoints: ['js/dependencies.mjs'], outfile: 'fief/static/dependencies.bundle.js' }),
  build({ ...options, entryPoints: ['js/webauthn.mjs'], outfile: 'fief/static/webauthn.bundle.js', globalName: 'fiefWebauthn' }),
]);
