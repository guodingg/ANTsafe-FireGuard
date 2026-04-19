import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import App from './App'
import './styles/index.css'

// 白+蓝+绿主题配色
const theme = {
  token: {
    colorPrimary: '#1677FF',
    colorSuccess: '#52C41A',
    colorWarning: '#FF8C00',
    colorError: '#FF4D4F',
    colorInfo: '#1677FF',
    colorBgBase: '#ffffff',
    colorTextBase: '#262626',
    borderRadius: 6,
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
  },
  components: {
    Menu: {
      darkItemBg: '#ffffff',
      darkItemSelectedBg: '#e6f4ff',
      darkItemHoverBg: '#f5f5f5'
    },
    Layout: {
      headerBg: '#ffffff',
      bodyBg: '#F5F7FA',
      siderBg: '#ffffff'
    }
  }
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <ConfigProvider locale={zhCN} theme={theme}>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </ConfigProvider>
)
