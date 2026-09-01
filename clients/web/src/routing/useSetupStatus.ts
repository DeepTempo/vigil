import { useCallback, useEffect, useState } from 'react'
import { llmProviderApi, LLMProvider } from '../services/api'
import { anyRoutableBifrostProvider } from '../services/bifrostApi'

// "Configured" = EITHER a legacy active+default provider, OR a routable Bifrost
// provider. Requiring is_default on the legacy side (not just is_active) matches
// the runtime: active-but-no-default is exactly where default-resolution fails
// and chat breaks. We don't require an API key there — local providers (Ollama,
// or an OpenAI-compatible server like vLLM/LM Studio) can be keyless. The
// Bifrost side instead requires a key the gateway verified. Kept in sync with
// setupSteps' llm-provider predicate.
const isProviderReady = (p: LLMProvider): boolean => p.is_active && p.is_default

export interface SetupStatus {
  configured: boolean
  loading: boolean
  refetch: () => void
}

const useSetupStatus = (): SetupStatus => {
  const [configured, setConfigured] = useState(false)
  const [loading, setLoading] = useState(true)

  const refetch = useCallback(() => {
    setLoading(true)
    // Two independent stores back "a provider exists"; either satisfies the
    // gate. Each fails open on its own error so a transient hiccup in one
    // can't trap an already-configured user behind the wizard. A genuinely
    // fresh install returns empty/false from both (successes, not errors), so
    // the gate still fires for new users.
    Promise.all([
      llmProviderApi
        .list()
        .then((res) => (res.data || []).some(isProviderReady))
        .catch(() => true),
      anyRoutableBifrostProvider().catch(() => false),
    ])
      .then(([legacy, bifrost]) => setConfigured(legacy || bifrost))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    refetch()
  }, [refetch])

  return { configured, loading, refetch }
}

export default useSetupStatus
