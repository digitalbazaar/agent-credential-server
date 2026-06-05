/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Tests for provider selection and the API-key preflight in getModel. The
 * preflight must fail fast with a clear message when a key-requiring provider
 * has no key — not defer to a cryptic error in the first inference call.
 */
import {getModel, resolveProviderName} from '../providers.js';

describe('resolveProviderName', () => {
  const original = process.env.AGENT_PROVIDER;
  afterEach(() => {
    if(original === undefined) {
      delete process.env.AGENT_PROVIDER;
    } else {
      process.env.AGENT_PROVIDER = original;
    }
  });

  it('prefers the explicit name', () => {
    expect(resolveProviderName('Ollama')).toBe('ollama');
  });
  it('falls back to AGENT_PROVIDER', () => {
    process.env.AGENT_PROVIDER = 'OLLAMA';
    expect(resolveProviderName()).toBe('ollama');
  });
  it('defaults to anthropic', () => {
    delete process.env.AGENT_PROVIDER;
    expect(resolveProviderName()).toBe('anthropic');
  });
});

describe('getModel key preflight', () => {
  const originalKey = process.env.ANTHROPIC_API_KEY;
  afterEach(() => {
    if(originalKey === undefined) {
      delete process.env.ANTHROPIC_API_KEY;
    } else {
      process.env.ANTHROPIC_API_KEY = originalKey;
    }
  });

  it('throws a clear error when anthropic has no API key', () => {
    delete process.env.ANTHROPIC_API_KEY;
    expect(() => getModel('anthropic')).toThrow(/ANTHROPIC_API_KEY/);
  });

  it('mentions the ollama escape hatch in the error', () => {
    delete process.env.ANTHROPIC_API_KEY;
    expect(() => getModel('anthropic')).toThrow(/ollama/i);
  });

  it('builds anthropic when the key is present', () => {
    process.env.ANTHROPIC_API_KEY = 'sk-ant-test';
    const {name, model} = getModel('anthropic');
    expect(name).toBe('anthropic');
    expect(model).toBeDefined();
  });

  it('builds ollama with no key required', () => {
    delete process.env.ANTHROPIC_API_KEY;
    const {name, model} = getModel('ollama');
    expect(name).toBe('ollama');
    expect(model).toBeDefined();
  });

  it('throws on an unknown provider', () => {
    expect(() => getModel('mystery')).toThrow(/Unknown/);
  });
});

describe('getModel openai-compatible', () => {
  const saved = {
    key: process.env.OPENAI_COMPATIBLE_API_KEY,
    base: process.env.OPENAI_COMPATIBLE_BASE_URL,
    model: process.env.OPENAI_COMPATIBLE_MODEL
  };
  /**
   * Restore one env var to its saved value (deleting if it was unset).
   *
   * @param {string} key - The env var name.
   * @param {string | undefined} value - The saved value.
   * @returns {void}
   */
  function restore(key, value) {
    if(value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  afterEach(() => {
    restore('OPENAI_COMPATIBLE_API_KEY', saved.key);
    restore('OPENAI_COMPATIBLE_BASE_URL', saved.base);
    restore('OPENAI_COMPATIBLE_MODEL', saved.model);
  });

  it('throws a clear error when the API key is missing', () => {
    delete process.env.OPENAI_COMPATIBLE_API_KEY;
    process.env.OPENAI_COMPATIBLE_BASE_URL = 'https://api.deepseek.com/v1';
    process.env.OPENAI_COMPATIBLE_MODEL = 'deepseek-chat';
    expect(() => getModel('openai-compatible'))
      .toThrow(/OPENAI_COMPATIBLE_API_KEY/);
  });

  it('throws when the base URL or model is missing', () => {
    process.env.OPENAI_COMPATIBLE_API_KEY = 'sk-test';
    delete process.env.OPENAI_COMPATIBLE_BASE_URL;
    delete process.env.OPENAI_COMPATIBLE_MODEL;
    expect(() => getModel('openai-compatible'))
      .toThrow(/OPENAI_COMPATIBLE_BASE_URL/);
  });

  it('builds a model when key, base URL, and model are set', () => {
    process.env.OPENAI_COMPATIBLE_API_KEY = 'sk-test';
    process.env.OPENAI_COMPATIBLE_BASE_URL = 'https://api.deepseek.com/v1';
    process.env.OPENAI_COMPATIBLE_MODEL = 'deepseek-chat';
    const {name, model} = getModel('openai-compatible');
    expect(name).toBe('openai-compatible');
    expect(model).toBeDefined();
  });
});
