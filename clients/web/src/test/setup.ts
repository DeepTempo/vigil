/**
 * Test setup and configuration
 */

import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';
import '@testing-library/jest-dom';

// Cleanup after each test
afterEach(() => {
  cleanup();
});

// Node >= 22 ships its own `localStorage` global. It is inert unless the
// runtime was started with --localstorage-file, and under `globals: true` it
// shadows jsdom's window.localStorage — so a bare `localStorage.setItem(...)`
// in a test throws "not a function" on Node 22+ and works on Node 20. Pin the
// global to a real in-memory Storage so the suite behaves the same on both.
const memoryStorage = () => {
  const store = new Map<string, string>();
  return {
    get length() {
      return store.size;
    },
    key: (i: number) => Array.from(store.keys())[i] ?? null,
    getItem: (k: string) => (store.has(String(k)) ? store.get(String(k))! : null),
    setItem: (k: string, v: string) => {
      store.set(String(k), String(v));
    },
    removeItem: (k: string) => {
      store.delete(String(k));
    },
    clear: () => store.clear(),
  } as Storage;
};

const localStorageShim = memoryStorage();
const sessionStorageShim = memoryStorage();
Object.defineProperty(globalThis, 'localStorage', {
  configurable: true,
  get: () => localStorageShim,
});
Object.defineProperty(globalThis, 'sessionStorage', {
  configurable: true,
  get: () => sessionStorageShim,
});

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => {},
  }),
});

// Mock IntersectionObserver
global.IntersectionObserver = class IntersectionObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  takeRecords() {
    return [];
  }
  unobserve() {}
} as any;

