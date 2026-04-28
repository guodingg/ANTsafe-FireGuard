import { Routes, Route, Navigate } from 'react-router-dom'

import MainLayout from './layouts/MainLayout'
import Login from './pages/Login/Login'
import Dashboard from './pages/Dashboard/Dashboard'
import TaskList from './pages/Scan/TaskList'
import TaskDetail from './pages/Scan/TaskDetail'
import TaskCreate from './pages/Scan/TaskCreate'
import AssetList from './pages/Asset/AssetList'
import VulnList from './pages/Vuln/VulnList'
import POCList from './pages/POC/POCList'
import ReportList from './pages/Report/ReportList'
import LogList from './pages/Log/LogList'
import Settings from './pages/Settings/Settings'
import UserList from './pages/User/UserList'
import Profile from './pages/User/Profile'
import AIAssistant from './pages/AIAssistant/AIAssistant'
import DictManage from './pages/Dict/DictManage'
import VulnIntel from './pages/VulnIntel/VulnIntel'
import AssetFilter from './pages/AssetFilter/AssetFilter'

import useAuthStore from './store/authStore'
import './styles/index.css'

// 路由守卫组件
const PrivateRoute = ({ children }) => {
  const { isAuthenticated } = useAuthStore()
  return isAuthenticated ? children : <Navigate to="/login" replace />
}

// 公共路由组件
const PublicRoute = ({ children }) => {
  const { isAuthenticated } = useAuthStore()
  return isAuthenticated ? <Navigate to="/" replace /> : children
}

function App() {
  return (
    <Routes>
      {/* 登录页 */}
      <Route path="/login" element={
        <PublicRoute>
          <Login />
        </PublicRoute>
      } />

      {/* 受保护的路由 */}
      <Route path="/" element={
        <PrivateRoute>
          <MainLayout />
        </PrivateRoute>
      }>
        <Route index element={<Dashboard />} />
        <Route path="scan/tasks" element={<TaskList />} />
        <Route path="scan/tasks/new" element={<TaskCreate />} />
        <Route path="scan/tasks/:id" element={<TaskDetail />} />
        <Route path="assets" element={<AssetList />} />
        <Route path="vulns" element={<VulnList />} />
        <Route path="pocs" element={<POCList />} />
        <Route path="reports" element={<ReportList />} />
        <Route path="logs" element={<LogList />} />
        <Route path="settings" element={<Settings />} />
        <Route path="users" element={<UserList />} />
        <Route path="profile" element={<Profile />} />
        <Route path="ai-assistant" element={<AIAssistant />} />
        <Route path="dicts" element={<DictManage />} />
        <Route path="vuln-intel" element={<VulnIntel />} />
        <Route path="asset-filter" element={<AssetFilter />} />
      </Route>

      {/* 404 */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default App
