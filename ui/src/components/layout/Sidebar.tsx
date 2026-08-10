import { NavLink } from 'react-router-dom'
import { useAlertStore } from '@/stores/alertStore'

const navItems = [
  { to: '/dashboard', label: 'Dashboard', icon: '⬛' },
  { to: '/events', label: 'Événements', icon: '📋' },
  { to: '/alerts', label: 'Alertes', icon: '🔔' },
  { to: '/decisions', label: 'Décisions', icon: '⚖️' },
  { to: '/cases', label: 'Cases', icon: '📁' },
  { to: '/incidents', label: 'Incidents', icon: '🚨' },
  { to: '/rules', label: 'Règles', icon: '📏' },
  { to: '/network', label: 'Graphe', icon: '🕸️' },
]

export default function Sidebar() {
  const openCount = useAlertStore((s) => s.openCount)

  return (
    <>
      {/* Desktop sidebar */}
      <nav className="hidden md:flex flex-col w-52 shrink-0 bg-gray-50 dark:bg-gray-900 border-r border-gray-200 dark:border-gray-800 py-4">
        {navItems.map(({ to, label, icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-2.5 px-4 py-2.5 text-sm transition-colors ${
                isActive
                  ? 'bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white font-medium'
                  : 'text-gray-400 dark:text-gray-400 hover:text-gray-900 dark:text-white hover:bg-gray-200 dark:bg-gray-800/50'
              }`
            }
          >
            <span aria-hidden="true">{icon}</span>
            <span>{label}</span>
            {to === '/alerts' && openCount > 0 && (
              <span className="ml-auto text-xs bg-red-600 text-gray-900 dark:text-white rounded-full px-1.5 py-0.5 min-w-[1.25rem] text-center">
                {openCount > 99 ? '99+' : openCount}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Mobile bottom nav */}
      <nav className="md:hidden fixed bottom-0 left-0 right-0 z-10 flex bg-gray-50 dark:bg-gray-900 border-t border-gray-200 dark:border-gray-800">
        {navItems.slice(0, 5).map(({ to, label, icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex-1 flex flex-col items-center py-2 text-xs transition-colors ${
                isActive ? 'text-gray-900 dark:text-white' : 'text-gray-400 dark:text-gray-500'
              }`
            }
          >
            <span className="text-base" aria-hidden="true">{icon}</span>
            <span className="mt-0.5">{label}</span>
          </NavLink>
        ))}
      </nav>
    </>
  )
}
