/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/// <reference types="vite/client" />

declare module '*.vue' {
  import type {DefineComponent} from 'vue';
  const component: DefineComponent<{}, {}, any>;
  export default component;
}
