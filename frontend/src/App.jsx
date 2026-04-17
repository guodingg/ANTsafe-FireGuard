import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'

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

// Antd主题配置 - 白+蓝+绿配色
const theme = {
  token: {
    colorPrimary: '#1677FF',
    colorSuccess: '#52C41A',
    colorWarning: '#FF8C00',
    colorError: '#FF4D4F',
    colorBgBase: '#ffffff',
    borderRadius: 6,
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
  }
}

function App() {
  return (
    <ConfigProvider theme={theme} locale={zhCN}>
      <BrowserRouter>
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
          </Route>

          {/* 404 */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </ConfigProvider>
  )
}

export default App
