// Purely additive: the hard gate lives in useSetupStatus / SetupGate.
import { useCallback, useEffect, useState } from 'react'
import { llmProviderApi, aiConfigApi, budgetsApi, configApi } from '../../services/api'
import { anyRoutableBifrostProvider } from '../../services/bifrostApi'
import {
  SETUP_STEPS,
  emptySetupState,
  type SetupState,
  type SetupStep,
} from './setupSteps'

export interface ChecklistStep extends SetupStep {
  ready: boolean
}

export interface SetupChecklist {
  steps: ChecklistStep[]
  requiredReady: boolean
  incompleteCount: number
  loading: boolean
  refetch: () => void
}

// every source fail-opens to its empty default, so one flaky endpoint can't
// crash the page. Advisory, not a security control.
const fetchSetupState = async (): Promise<SetupState> => {
  const base = emptySetupState()
  const [providers, bifrost, integrations, aiConfig, budget, orchestrator] =
    await Promise.allSettled([
      llmProviderApi.list(),
      anyRoutableBifrostProvider(),
      configApi.getIntegrations(),
      aiConfigApi.getConfig(),
      budgetsApi.get(),
      configApi.getOrchestrator(),
    ])

  if (providers.status === 'fulfilled') base.providers = providers.value.data || []
  if (bifrost.status === 'fulfilled') base.bifrostRoutable = bifrost.value
  if (integrations.status === 'fulfilled')
    base.enabledIntegrations = integrations.value.data?.enabled_integrations ?? []
  if (aiConfig.status === 'fulfilled') base.assignments = aiConfig.value.data?.assignments ?? {}
  if (budget.status === 'fulfilled') base.budget = budget.value.data ?? null
  if (orchestrator.status === 'fulfilled')
    base.orchestratorEnabled = !!orchestrator.value.data?.enabled

  return base
}

const useSetupChecklist = (): SetupChecklist => {
  const [state, setState] = useState<SetupState>(emptySetupState)
  const [loading, setLoading] = useState(true)

  // initial load only: blanking the list to the loader mid-save made it flash
  const refetch = useCallback(() => {
    fetchSetupState()
      .then(setState)
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    refetch()
  }, [refetch])

  const steps: ChecklistStep[] = SETUP_STEPS.map((step) => ({
    ...step,
    ready: step.selectReady(state),
  }))
  const requiredReady = steps.every((s) => s.tier !== 'required' || s.ready)
  const incompleteCount = steps.filter((s) => s.tier !== 'required' && !s.ready).length

  return { steps, requiredReady, incompleteCount, loading, refetch }
}

export default useSetupChecklist
