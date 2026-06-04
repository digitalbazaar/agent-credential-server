/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Model-provider selection for the demo agent. The agent loop is
 * provider-agnostic (it speaks the Vercel AI SDK's unified tool-calling
 * interface); this module maps a provider name to a concrete model.
 *
 * Anthropic and Ollama are wired up now. OpenAI and Gemini drop in later with
 * the same shape via their AI SDK providers.
 */
import {anthropic} from '@ai-sdk/anthropic';
import {createOllama} from 'ollama-ai-provider-v2';

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
 * Build the AI-SDK model for the given provider.
 *
 * @param {string} [explicit] - An explicit provider name; else env/default.
 * @returns {{name: string, model: unknown}} The provider name and model.
 */
export function getModel(explicit) {
  const name = resolveProviderName(explicit);
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
    default:
      throw new Error(
        `Unknown AGENT_PROVIDER "${name}". Supported: anthropic, ollama.`
      );
  }
}
