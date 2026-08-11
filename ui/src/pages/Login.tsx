import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/authStore'
import { Input, Button } from '@/components/ui'

export default function Login() {
  const navigate = useNavigate()
  const login = useAuthStore((s) => s.login)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      await login(username, password)
      navigate('/dashboard', { replace: true })
    } catch {
      setError('Identifiants invalides')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-white dark:bg-gray-950">
      <div className="w-full max-w-sm space-y-6">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white tracking-tight">OSEye</h1>
          <p className="mt-1 text-sm text-gray-400">Security Operations Dashboard</p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-6 space-y-4"
        >
          <div className="space-y-1">
            <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Utilisateur
            </label>
            <Input
              id="username"
              type="text"
              aria-label="username"
              autoComplete="username"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Mot de passe
            </label>
            <Input
              id="password"
              type="password"
              aria-label="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full"
            />
          </div>

          {error && (
            <p role="alert" className="text-sm text-red-400">{error}</p>
          )}

          <Button type="submit" variant="primary" disabled={loading} className="w-full justify-center py-2">
            {loading ? 'Connexion…' : 'Se connecter'}
          </Button>
        </form>
      </div>
    </div>
  )
}
