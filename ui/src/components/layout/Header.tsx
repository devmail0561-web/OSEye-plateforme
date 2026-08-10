import { useAuthStore } from '@/stores/authStore'
import { useWSStore } from '@/stores/wsStore'
import { useTheme } from '@/hooks/useTheme'
import { useNavigate } from 'react-router-dom'

const wsColors: Record<string, string> = {
  connected: 'bg-green-400',
  connecting: 'bg-yellow-400 animate-pulse',
  disconnected: 'bg-gray-500',
  error: 'bg-red-500',
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
    <header className="h-14 flex items-center justify-between px-4 border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-900">
      <span className="font-semibold text-gray-900 dark:text-white tracking-tight select-none">OSEye</span>

      <div className="flex items-center gap-3">
        <span className="flex items-center gap-1.5 text-xs text-gray-400 dark:text-gray-400">
          <span className={`inline-block w-2 h-2 rounded-full ${wsColors[wsStatus]}`} />
          {wsStatus}
        </span>

        <button
          onClick={toggle}
          aria-label="Basculer thème"
          className="p-1.5 rounded text-gray-400 dark:text-gray-400 hover:text-gray-900 dark:text-white hover:bg-gray-100 dark:bg-gray-800 transition-colors"
        >
          {isDark ? '☀️' : '🌙'}
        </button>

        <button
          onClick={handleLogout}
          className="text-xs text-gray-400 dark:text-gray-400 hover:text-gray-900 dark:text-white transition-colors"
        >
          Déconnexion
        </button>
      </div>
    </header>
  )
}
