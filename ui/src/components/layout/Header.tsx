import { Sun, Moon, LogOut, Wifi, WifiOff, Loader2 } from 'lucide-react'
import { useAuthStore } from '@/stores/authStore'
import { useWSStore } from '@/stores/wsStore'
import { useTheme } from '@/hooks/useTheme'
import { useNavigate } from 'react-router-dom'

const WS_DOT: Record<string, string> = {
  connected:    'text-green-400',
  connecting:   'text-yellow-400',
  disconnected: 'text-gray-500',
  error:        'text-red-500',
}

function WsIndicator({ status }: { status: string }) {
  if (status === 'connecting') {
    return <Loader2 className="w-3.5 h-3.5 text-yellow-400 animate-spin" />
  }
  if (status === 'connected') {
    return <Wifi className={`w-3.5 h-3.5 ${WS_DOT[status]}`} />
  }
  return <WifiOff className={`w-3.5 h-3.5 ${WS_DOT[status] ?? 'text-gray-500'}`} />
}

export default function Header() {
  const logout = useAuthStore((s) => s.logout)
  const wsStatus = useWSStore((s) => s.status)
  const { isDark, toggle } = useTheme()
  const navigate = useNavigate()

  function handleLogout() {
    logout()
    navigate('/login', { replace: true })
  }

  return (
    <header className="h-14 flex items-center justify-between px-4 border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-900 shrink-0">
      <span className="font-semibold text-gray-900 dark:text-white tracking-tight select-none">OSEye</span>

      <div className="flex items-center gap-3">
        <span className="flex items-center gap-1.5 text-xs text-gray-400 dark:text-gray-500">
          <WsIndicator status={wsStatus} />
          {wsStatus}
        </span>

        <button
          onClick={toggle}
          aria-label="Basculer thème"
          className="p-1.5 rounded text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
        >
          {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>

        <button
          onClick={handleLogout}
          aria-label="Déconnexion"
          className="flex items-center gap-1.5 text-xs text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
        >
          <LogOut className="w-3.5 h-3.5" />
          Déconnexion
        </button>
      </div>
    </header>
  )
}
