import esbuild from 'esbuild';
import { mkdir, copyFile } from 'node:fs/promises';
await mkdir('dist', { recursive: true });
const options = {
  entryPoints: ['src/main.ts'],
  outfile: 'dist/main.js',
  bundle: true,
  external: ['obsidian', 'electron', '@codemirror/*', '@lezer/*'],
  format: 'cjs',
  platform: 'browser',
  target: 'es2020',
  sourcemap: false,
  logLevel: 'info',
  banner: { js: '/* Folder Lock 0.2.1 - generated build; source in src/ */' },
};
await Promise.all(['manifest.json', 'styles.css'].map(f => copyFile(f, `dist/${f}`)));
if (process.argv.includes('--watch')) {
  const ctx = await esbuild.context(options);
  await ctx.watch();
} else {
  await esbuild.build(options);
}
