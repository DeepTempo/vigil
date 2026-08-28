import { useCallback, useEffect, useState } from 'react'
import { llmProviderApi, LLMProvider } from '../services/api'

// is_default, not just is_active: active-but-no-default is exactly where
// default-resolution fails and chat breaks. No API key is required — local
// providers can be keyless, and the wizard's Test step is what proves one works.
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
    llmProviderApi
      .list()
      .then((res) => setConfigured((res.data || []).some(isProviderReady)))
      // Fail open: UX routing, not a security control. A fresh install returns
      // an empty list (a success), so the gate still fires for new users.
      .catch(() => setConfigured(true))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    refetch()
  }, [refetch])

  return { configured, loading, refetch }
}

export default useSetupStatus
