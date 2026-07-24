import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import Loader from '../../redesign/shell/Loader';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredPermission?: string;
  requiredPermissions?: string[];
  requireAll?: boolean; // If true, requires all permissions; if false, requires any
}

function AccessDenied({ detail }: { detail: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 p-6 min-h-screen">
      <h2 className="text-xl font-semibold" style={{ color: 'var(--crit)' }}>Access Denied</h2>
      <p className="text-sm text-tx-3">You don't have permission to access this page.</p>
      <p className="text-xs text-tx-3">{detail}</p>
    </div>
  );
}

export default function ProtectedRoute({
  children,
  requiredPermission,
  requiredPermissions,
  requireAll = false,
}: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, hasPermission, hasAnyPermission, hasAllPermissions } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return <Loader />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredPermission && !hasPermission(requiredPermission)) {
    return <AccessDenied detail={`Required permission: ${requiredPermission}`} />;
  }

  if (requiredPermissions && requiredPermissions.length > 0) {
    const hasAccess = requireAll
      ? hasAllPermissions(...requiredPermissions)
      : hasAnyPermission(...requiredPermissions);

    if (!hasAccess) {
      const scope = requireAll ? 'all' : 'any';
      return <AccessDenied detail={`Required permissions (${scope}): ${requiredPermissions.join(', ')}`} />;
    }
  }

  return <>{children}</>;
}
