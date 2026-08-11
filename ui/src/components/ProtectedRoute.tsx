import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/stores/authStore'

interface Props {
  requiredRole?: 'admin'
}

export default function ProtectedRoute({ requiredRole }: Props) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const roles = useAuthStore((s) => s.roles)
  const location = useLocation()

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  if (requiredRole && !roles.includes(requiredRole)) {
    return <Navigate to="/dashboard" replace />
  }

  return <Outlet />
}
