import { useState } from 'react'
import { Form, Input, Button, Card, message, Space } from 'antd'
import { UserOutlined, LockOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../../store/authStore'
import './Login.css'

const Login = () => {
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const { login } = useAuthStore()

  const onFinish = async (values) => {
    setLoading(true)
    try {
      const result = await login(values.username, values.password)
      if (result.success) {
        message.success('登录成功')
        navigate('/dashboard')
      } else {
        message.error(result.message || '登录失败')
      }
    } catch (error) {
      message.error('登录失败，请稍后重试')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-container">
      <div className="login-bg">
        <div className="login-card-wrapper">
          <Card className="login-card" bordered={false}>
            <div className="login-header">
              <div className="login-logo">蚂蚁</div>
              <h1 className="login-title">蚂蚁安全风险评估系统</h1>
              <p className="login-subtitle">ANTsafe System</p>
            </div>

            <Form
              name="login"
              onFinish={onFinish}
              autoComplete="off"
              layout="vertical"
              requiredMark={false}
            >
              <Form.Item
                name="username"
                rules={[{ required: true, message: '请输入用户名' }]}
              >
                <Input
                  prefix={<UserOutlined style={{ color: '#8C8C8C' }} />}
                  placeholder="用户名"
                  size="large"
                />
              </Form.Item>

              <Form.Item
                name="password"
                rules={[{ required: true, message: '请输入密码' }]}
              >
                <Input.Password
                  prefix={<LockOutlined style={{ color: '#8C8C8C' }} />}
                  placeholder="密码"
                  size="large"
                />
              </Form.Item>

              <Form.Item style={{ marginBottom: 16 }}>
                <Button
                  type="primary"
                  htmlType="submit"
                  size="large"
                  block
                  loading={loading}
                  className="login-button"
                >
                  登 录
                </Button>
              </Form.Item>
            </Form>

            <div className="login-footer">
              <Space split={<span style={{ color: '#E8E8E8' }}>|</span>}>
                <a href="https://www.mayisafe.cn" target="_blank" rel="noopener noreferrer">
                  关于我们
                </a>
                <a href="https://www.mayisafe.cn" target="_blank" rel="noopener noreferrer">
                  帮助中心
                </a>
              </Space>
              <p className="login-copyright">
                © 2024 蚂蚁安全 www.mayisafe.cn 版权所有
              </p>
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}

export default Login
