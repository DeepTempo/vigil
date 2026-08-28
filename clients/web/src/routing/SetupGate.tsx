import { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import useSetupStatus from './useSetupStatus'
import Loader from './Loader'

interface Props {
  children: ReactNode
}

// The /setup route lives OUTSIDE this gate, so it stays reachable when
// unconfigured and there is no redirect loop.
const SetupGate = ({ children }: Props) => {
  const { configured, loading } = useSetupStatus()

  if (loading) {
    return <Loader label="Checking setup…" />
  }

  if (!configured) {
    return <Navigate to="/setup" replace />
  }

  return <>{children}</>
}

export default SetupGate
