import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom'
import { Suspense, lazy } from 'react'
import ProtectedRoute from '@/components/ProtectedRoute'
import AppShell from '@/components/layout/AppShell'
import Login from '@/pages/Login'

const Dashboard = lazy(() => import('@/pages/Dashboard'))
const Events = lazy(() => import('@/pages/Events'))
const Alerts = lazy(() => import('@/pages/Alerts'))
const Decisions = lazy(() => import('@/pages/Decisions'))
const Cases = lazy(() => import('@/pages/Cases'))
const CaseDetail = lazy(() => import('@/pages/CaseDetail'))
const Incidents = lazy(() => import('@/pages/Incidents'))
const IncidentDetail = lazy(() => import('@/pages/IncidentDetail'))
const Rules = lazy(() => import('@/pages/Rules'))
const NetworkGraph = lazy(() => import('@/pages/NetworkGraph'))
const ApiKeys = lazy(() => import('@/pages/admin/ApiKeys'))
const Plugins = lazy(() => import('@/pages/admin/Plugins'))
const Policies = lazy(() => import('@/pages/admin/Policies'))
const ResponseActions = lazy(() => import('@/pages/admin/ResponseActions'))

const router = createBrowserRouter([
  { path: '/login', element: <Login /> },
  {
    element: <ProtectedRoute />,
    children: [
      {
        element: <AppShell />,
        children: [
          { path: '/', element: <Navigate to="/dashboard" replace /> },
          { path: '/dashboard', element: <Suspense fallback={null}><Dashboard /></Suspense> },
          { path: '/events', element: <Suspense fallback={null}><Events /></Suspense> },
          { path: '/alerts', element: <Suspense fallback={null}><Alerts /></Suspense> },
          { path: '/decisions', element: <Suspense fallback={null}><Decisions /></Suspense> },
          { path: '/cases', element: <Suspense fallback={null}><Cases /></Suspense> },
          { path: '/cases/:id', element: <Suspense fallback={null}><CaseDetail /></Suspense> },
          { path: '/incidents', element: <Suspense fallback={null}><Incidents /></Suspense> },
          { path: '/incidents/:id', element: <Suspense fallback={null}><IncidentDetail /></Suspense> },
          { path: '/rules', element: <Suspense fallback={null}><Rules /></Suspense> },
          { path: '/network', element: <Suspense fallback={null}><NetworkGraph /></Suspense> },
          {
            element: <ProtectedRoute requiredRole="admin" />,
            children: [
              { path: '/admin/response-actions', element: <Suspense fallback={null}><ResponseActions /></Suspense> },
              { path: '/admin/api-keys',         element: <Suspense fallback={null}><ApiKeys /></Suspense> },
              { path: '/admin/plugins',          element: <Suspense fallback={null}><Plugins /></Suspense> },
              { path: '/admin/policies',         element: <Suspense fallback={null}><Policies /></Suspense> },
            ],
          },
        ],
      },
    ],
  },
])

export default function App() {
  return <RouterProvider router={router} />
}
