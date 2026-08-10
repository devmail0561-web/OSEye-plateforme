import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import Header from './Header'

export default function AppShell() {
  return (
    <div className="flex flex-col h-screen bg-white dark:bg-gray-950 text-gray-800 dark:text-gray-100">
      <Header />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto p-4 pb-16 md:pb-4">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
