/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import config from '@digitalbazaar/eslint-config/node-recommended';
import globals from 'globals';

export default [
  ...config,
  {
    // this repo is a JS + JSDoc monorepo; tests use Jest in __tests__/,
    // not mocha in test/ (which the base preset assumes)
    files: ['**/__tests__/**/*.js'],
    languageOptions: {
      globals: {
        ...globals.jest
      }
    }
  },
  {
    // spikes are disposable de-risk scratch files, not production code; the
    // web client is a separate Vue + TypeScript toolchain (linted/typed by
    // vue-tsc, not this node-recommended JSDoc preset), and web/public is its
    // build output
    ignores: ['**/spikes/**', 'web/client/**', 'web/public/**']
  }
];
