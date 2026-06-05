/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Model-provider selection for the demo agent. The agent loop is
 * provider-agnostic (it speaks the Vercel AI SDK's unified tool-calling
 * interface); this module maps a provider name to a concrete model.
 *
 * Anthropic, Ollama, and a generic OpenAI-compatible provider (DeepSeek,
 * Kimi/Moonshot, OpenAI, HuggingFace TGI, …) are wired up. Others drop in with
 * the same shape via their AI SDK providers.
 */
import {anthropic} from '@ai-sdk/anthropic';
import {createOllama} from 'ollama-ai-provider-v2';
import {createOpenAICompatible} from '@ai-sdk/openai-compatible';

const DEFAULT_ANTHROPIC_MODEL = 'claude-sonnet-4-6';
const DEFAULT_OLLAMA_MODEL = 'qwen2.5';

/**
 * Resolve the provider name from an explicit argument, the AGENT_PROVIDER env
 * var, or the default (anthropic).
 *
 * @param {string} [explicit] - An explicit provider name from a CLI flag.
 * @returns {string} The resolved provider name.
 */
export function resolveProviderName(explicit) {
  const name = explicit ?? process.env.AGENT_PROVIDER ?? 'anthropic';
  return name.toLowerCase();
}

/**
 * The API-key env var each provider requires, or null if it needs none. A
 * provider with a key var is preflighted in getModel so a missing key fails
 * fast with a clear message — not a cryptic error deep in the first inference
 * call. New providers (OpenAI-compatible, etc.) add a row here.
 *
 * @type {Record<string, string | null>}
 */
const PROVIDER_KEY_ENV = {
  anthropic: 'ANTHROPIC_API_KEY',
  ollama: null, // local, no key
  'openai-compatible': 'OPENAI_COMPATIBLE_API_KEY'
};

/**
 * Build the AI-SDK model for the given provider. Throws a clear error at
 * startup if the provider requires an API key that is not set.
 *
 * @param {string} [explicit] - An explicit provider name; else env/default.
 * @returns {{name: string, model: unknown}} The provider name and model.
 */
export function getModel(explicit) {
  const name = resolveProviderName(explicit);

  // preflight: a provider that needs a key must have it before we do any work
  const keyEnv = PROVIDER_KEY_ENV[name];
  if(keyEnv && !process.env[keyEnv]) {
    throw new Error(
      `Provider "${name}" requires the ${keyEnv} environment variable. ` +
      `Set it in a .env file at the repo root (see .env.example) or in your ` +
      `environment. To run without an API key, use --provider=ollama.`
    );
  }

  switch(name) {
    case 'anthropic': {
      const id = process.env.ANTHROPIC_MODEL ?? DEFAULT_ANTHROPIC_MODEL;
      return {name, model: anthropic(id)};
    }
    case 'ollama': {
      // local, free, no API key — ideal for a runnable reference. qwen2.5
      // tool-calling is best-effort: a small local model may mis-call or skip
      // check_delegation, yielding a wrong or NO-DECISION verdict on a run that
      // anthropic decides correctly. This is safe — the tool is authoritative,
      // so a skipped/bad call denies rather than false-grants (R-X-1) — but it
      // makes the ollama demo non-deterministic. Use anthropic for a reliable
      // demo; override the model with OLLAMA_MODEL (a larger model helps).
      const ollama = createOllama();
      const id = process.env.OLLAMA_MODEL ?? DEFAULT_OLLAMA_MODEL;
      return {name, model: ollama(id)};
    }
    case 'openai-compatible': {
      // any OpenAI-compatible endpoint (DeepSeek, Kimi/Moonshot, OpenAI,
      // a HuggingFace TGI server, …) — point it with env vars. Lower-cost
      // hosted models are a common reason to use this. Tool-calling quality
      // varies by model; the authorization guarantee holds regardless (R-X-1).
      const baseURL = process.env.OPENAI_COMPATIBLE_BASE_URL;
      const id = process.env.OPENAI_COMPATIBLE_MODEL;
      if(!baseURL || !id) {
        throw new Error(
          'Provider "openai-compatible" requires OPENAI_COMPATIBLE_BASE_URL ' +
          'and OPENAI_COMPATIBLE_MODEL (plus OPENAI_COMPATIBLE_API_KEY). ' +
          'See .env.example.'
        );
      }
      const provider = createOpenAICompatible({
        name: 'openai-compatible',
        baseURL,
        apiKey: process.env.OPENAI_COMPATIBLE_API_KEY
      });
      return {name, model: provider(id)};
    }
    default:
      throw new Error(
        `Unknown AGENT_PROVIDER "${name}". Supported: ` +
        `${Object.keys(PROVIDER_KEY_ENV).join(', ')}.`
      );
  }
}
