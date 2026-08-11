import { useState } from 'react'
import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  List,
  Bell,
  Scale,
  FolderOpen,
  AlertTriangle,
  Shield,
  Network,
  Monitor,
  Key,
  Puzzle,
  ShieldAlert,
  SlidersHorizontal,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'
import { useAlertStore } from '@/stores/alertStore'
import { useAuthStore } from '@/stores/authStore'
import type { LucideIcon } from 'lucide-react'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
}

const SURVEILLANCE: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard',  icon: LayoutDashboard },
  { to: '/events',    label: 'Événements', icon: List },
  { to: '/agents',    label: 'Agents',     icon: Monitor },
  { to: '/network',   label: 'Graphe',     icon: Network },
]

const RESPONSE: NavItem[] = [
  { to: '/alerts',    label: 'Alertes',    icon: Bell },
  { to: '/incidents', label: 'Incidents',  icon: AlertTriangle },
  { to: '/cases',     label: 'Cases',      icon: FolderOpen },
  { to: '/decisions', label: 'Décisions',  icon: Scale },
]

const CONFIG: NavItem[] = [
  { to: '/rules',     label: 'Règles',     icon: Shield },
]

const ADMIN: NavItem[] = [
  { to: '/admin/response-actions', label: 'Actions réponse', icon: ShieldAlert },
  { to: '/admin/api-keys',         label: 'API Keys',        icon: Key },
  { to: '/admin/plugins',          label: 'Plugins',         icon: Puzzle },
  { to: '/admin/policies',         label: 'Policies',        icon: SlidersHorizontal },
]

function SectionLabel({ children, collapsed }: { children: string; collapsed: boolean }) {
  if (collapsed) {
    return <div className="h-px mx-3 my-3 bg-gray-200 dark:bg-gray-800" />
  }
  return (
    <p className="px-4 pt-4 pb-1 text-[10px] font-semibold uppercase tracking-widest text-gray-400 dark:text-gray-600 select-none">
      {children}
    </p>
  )
}

function NavItem({
  to, label, icon: Icon, badge, collapsed,
}: NavItem & { badge?: number; collapsed: boolean }) {
  return (
    <NavLink
      to={to}
      title={collapsed ? label : undefined}
      className={({ isActive }) =>
        `flex items-center py-2 text-sm transition-colors ${
          collapsed ? 'justify-center px-0' : 'gap-2.5 px-4'
        } ${
          isActive
            ? 'bg-gray-200 dark:bg-gray-800 text-gray-900 dark:text-white font-medium'
            : 'text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800/60'
        }`
      }
    >
      <div className="relative shrink-0">
        <Icon className="w-4 h-4" strokeWidth={1.75} />
        {/* Show badge as dot on icon when collapsed */}
        {collapsed && badge != null && badge > 0 && (
          <span className="absolute -top-1 -right-1 w-2 h-2 bg-red-600 rounded-full" />
        )}
      </div>
      {!collapsed && (
        <>
          <span className="flex-1">{label}</span>
          {badge != null && badge > 0 && (
            <span className="text-[10px] font-bold bg-red-600 text-white rounded-full px-1.5 py-0.5 min-w-[1.25rem] text-center tabular-nums">
              {badge > 99 ? '99+' : badge}
            </span>
          )}
        </>
      )}
    </NavLink>
  )
}

export default function Sidebar() {
  const openCount = useAlertStore((s) => s.openCount)
  const isAdmin   = useAuthStore((s) => s.roles.includes('admin'))
  const [collapsed, setCollapsed] = useState(false)

  return (
    <>
      {/* Desktop sidebar */}
      <nav
        className={`hidden md:flex flex-col shrink-0 bg-gray-50 dark:bg-gray-900 border-r border-gray-200 dark:border-gray-800 py-2 overflow-y-auto transition-all duration-200 ${
          collapsed ? 'w-12' : 'w-52'
        }`}
      >
        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed((v) => !v)}
          aria-label={collapsed ? 'Déplier la sidebar' : 'Replier la sidebar'}
          className={`flex items-center py-2 mb-1 text-gray-400 dark:text-gray-500 hover:text-gray-700 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800/60 transition-colors ${
            collapsed ? 'justify-center px-0' : 'px-4 gap-2'
          }`}
        >
          {collapsed
            ? <ChevronRight className="w-4 h-4" strokeWidth={1.75} />
            : <><ChevronLeft className="w-4 h-4" strokeWidth={1.75} /><span className="text-xs">Replier</span></>
          }
        </button>

        <SectionLabel collapsed={collapsed}>Surveillance</SectionLabel>
        {SURVEILLANCE.map((item) => (
          <NavItem key={item.to} {...item} collapsed={collapsed} />
        ))}

        <SectionLabel collapsed={collapsed}>Réponse</SectionLabel>
        {RESPONSE.map((item) => (
          <NavItem
            key={item.to}
            {...item}
            collapsed={collapsed}
            badge={item.to === '/alerts' ? openCount : undefined}
          />
        ))}

        <SectionLabel collapsed={collapsed}>Config</SectionLabel>
        {CONFIG.map((item) => (
          <NavItem key={item.to} {...item} collapsed={collapsed} />
        ))}

        {isAdmin && (
          <>
            <SectionLabel collapsed={collapsed}>Admin</SectionLabel>
            {ADMIN.map((item) => (
              <NavItem key={item.to} {...item} collapsed={collapsed} />
            ))}
          </>
        )}
      </nav>

      {/* Mobile bottom nav — admin items not included */}
      <nav className="md:hidden fixed bottom-0 left-0 right-0 z-10 flex bg-gray-50 dark:bg-gray-900 border-t border-gray-200 dark:border-gray-800">
        {[...SURVEILLANCE.slice(0, 2), ...RESPONSE.slice(0, 2), CONFIG[0]].map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex-1 flex flex-col items-center py-2 text-xs transition-colors ${
                isActive ? 'text-gray-900 dark:text-white' : 'text-gray-400 dark:text-gray-500'
              }`
            }
          >
            <Icon className="w-5 h-5" strokeWidth={1.75} />
            <span className="mt-0.5">{label}</span>
          </NavLink>
        ))}
      </nav>
    </>
  )
}
