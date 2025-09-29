import { build } from 'esbuild';

const config = {
  entryPoints: ['src/cli.ts'],
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'cjs',
  outfile: 'dist/cli.js',
  minify: true,
  treeShaking: true,
  splitting: false, // Not needed for single entry
  metafile: true, // For bundle analysis
  external: [
  ]
};

build(config).then(result => {
  if (result.metafile) {
    console.log(`📦 Bundle size: ${(require('fs').statSync('dist/cli.js').size / 1024 / 1024).toFixed(2)}MB`);
  }
}).catch(() => process.exit(1));