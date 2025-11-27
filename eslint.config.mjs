import js from '@eslint/js';
import globals from 'globals';
import { defineConfig } from 'eslint/config';
import eslintConfigPrettier from 'eslint-config-prettier/flat';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';

export default defineConfig([
  { files: ['**/*.{js,mjs,cjs}'], plugins: { js }, extends: ['js/recommended'], languageOptions: { globals: { ...globals.node } } },
  { files: ['**/*.js'], languageOptions: { sourceType: 'commonjs' } },
  { files: ['test/**/*.js'], languageOptions: { globals: { ...globals.node, ...globals.mocha } } },
  {
    rules: {
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' }],
    },
  },
  eslintPluginPrettierRecommended,
  eslintConfigPrettier,
]);
