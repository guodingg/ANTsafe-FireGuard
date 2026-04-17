import { Routes, Route, Navigate } from 'react-router-dom'
import MainLayout from './layouts/MainLayout'
import Login from './pages/Login/Login'
import Dashboard from './pages/Dashboard/Dashboard'
import TaskList from './pages/Scan/TaskList'
import TaskCreate from './pages/Scan/TaskCreate'
import TaskDetail from './pages/Scan/TaskDetail'
import AssetList from './pages/Asset/AssetList'
import VulnList from './pages/Vuln/VulnList'
import POCList from './pages/POC/POCList'
import ReportList from './pages/Report/ReportList'
import LogList from './pages/Log/LogList'
import Settings from './pages/Settings/Settings'
import UserList from './pages/User/UserList'
import { useAuthStore } from './store/authStore'

function App() {
  const { token } = useAuthStore()

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/*"
        element={
          token ? (
            <MainLayout>
              <Routes>
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/scan/tasks" element={<TaskList />} />
                <Route path="/scan/tasks/new" element={<TaskCreate />} />
                <Route path="/scan/tasks/:id" element={<TaskDetail />} />
                <Route path="/assets" element={<AssetList />} />
                <Route path="/vulns" element={<VulnList />} />
                <Route path="/pocs" element={<POCList />} />
                <Route path="/reports" element={<ReportList />} />
                <Route path="/logs" element={<LogList />} />
                <Route path="/settings" element={<Settings />} />
                <Route path="/users" element={<UserList />} />
              </Routes>
            </MainLayout>
          ) : (
            <Navigate to="/login" replace />
          )
        }
      />
    </Routes>
  )
}

export default App
