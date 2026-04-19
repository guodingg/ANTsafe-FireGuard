import { useState, useEffect } from 'react'
import { Card, Form, Input, Button, Avatar, Space, message, Upload } from 'antd'
import { UserOutlined, MailOutlined, LockOutlined, SafetyOutlined, UploadOutlined } from '@ant-design/icons'
import useAuthStore from '../../store/authStore'
import api from '../../services/api'

const Profile = () => {
  const [form] = Form.useForm()
  const { user, setUser } = useAuthStore()
  const [loading, setLoading] = useState(false)
  const [passwordLoading, setPasswordLoading] = useState(false)

  useEffect(() => {
    if (user) {
      form.setFieldsValue({
        username: user.username,
        email: user.email,
        role: user.role === 'admin' ? '管理员' : user.role === 'operator' ? '操作员' : '普通用户'
      })
    }
  }, [user, form])

  const handleUpdateProfile = async (values) => {
    setLoading(true)
    try {
      const updatedUser = await api.updateUser(user.id, {
        email: values.email
      })
      setUser({ ...user, ...updatedUser })
      message.success('个人信息更新成功')
    } catch (error) {
      message.error('更新失败: ' + (error.message || '未知错误'))
    } finally {
      setLoading(false)
    }
  }

  const handleChangePassword = async (values) => {
    if (values.newPassword !== values.confirmPassword) {
      message.error('两次输入的密码不一致')
      return
    }
    setPasswordLoading(true)
    try {
      await api.changePassword(user.id, values.oldPassword, values.newPassword)
      message.success('密码修改成功')
      form.setFieldsValue({
        oldPassword: '',
        newPassword: '',
        confirmPassword: ''
      })
    } catch (error) {
      message.error('密码修改失败: ' + (error.message || '未知错误'))
    } finally {
      setPasswordLoading(false)
    }
  }

  const getRoleColor = (role) => {
    const colors = {
      'admin': 'red',
      'operator': 'blue',
      'user': 'green'
    }
    return colors[role] || 'default'
  }

  return (
    <div style={{ maxWidth: 800, margin: '0 auto' }}>
      {/* 基本信息 */}
      <Card
        title={
          <Space>
            <UserOutlined />
            基本信息
          </Space>
        }
        style={{ marginBottom: 24 }}
      >
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: 24 }}>
          <Avatar size={80} src={user?.avatar} icon={<UserOutlined />} style={{ backgroundColor: '#1677FF' }} />
          <div style={{ marginLeft: 24 }}>
            <h2 style={{ margin: 0 }}>{user?.username}</h2>
            <span style={{ color: '#666' }}>
              角色: <span style={{ color: getRoleColor(user?.role) }}>{user?.role === 'admin' ? '管理员' : user?.role === 'operator' ? '操作员' : '普通用户'}</span>
            </span>
          </div>
        </div>

        <Form
          form={form}
          layout="vertical"
          onFinish={handleUpdateProfile}
          initialValues={{
            username: user?.username,
            email: user?.email
          }}
        >
          <Form.Item
            name="username"
            label="用户名"
          >
            <Input disabled prefix={<UserOutlined />} />
          </Form.Item>

          <Form.Item
            name="email"
            label="邮箱"
            rules={[
              { required: true, message: '请输入邮箱' },
              { type: 'email', message: '请输入有效的邮箱地址' }
            ]}
          >
            <Input prefix={<MailOutlined />} placeholder="请输入邮箱" />
          </Form.Item>

          <Form.Item
            name="role"
            label="角色"
          >
            <Input disabled />
          </Form.Item>

          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading}>
              保存修改
            </Button>
          </Form.Item>
        </Form>
      </Card>

      {/* 修改密码 */}
      <Card
        title={
          <Space>
            <LockOutlined />
            修改密码
          </Space>
        }
      >
        <Form
          layout="vertical"
          onFinish={handleChangePassword}
          style={{ maxWidth: 400 }}
        >
          <Form.Item
            name="oldPassword"
            label="旧密码"
            rules={[{ required: true, message: '请输入旧密码' }]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="请输入旧密码" />
          </Form.Item>

          <Form.Item
            name="newPassword"
            label="新密码"
            rules={[
              { required: true, message: '请输入新密码' },
              { min: 6, message: '密码至少6位' }
            ]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="请输入新密码" />
          </Form.Item>

          <Form.Item
            name="confirmPassword"
            label="确认新密码"
            rules={[{ required: true, message: '请确认新密码' }]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="请再次输入新密码" />
          </Form.Item>

          <Form.Item>
            <Button type="primary" htmlType="submit" loading={passwordLoading}>
              修改密码
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  )
}

export default Profile
