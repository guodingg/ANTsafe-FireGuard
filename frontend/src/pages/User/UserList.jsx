import { Card, Table, Button, Space, Tag, Modal, Form, Input, Select, message } from 'antd'
import { TeamOutlined, PlusOutlined, EditOutlined, DeleteOutlined, UserOutlined } from '@ant-design/icons'
import { useState } from 'react'

const UserList = () => {
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [form] = Form.useForm()

  const data = [
    { id: 1, username: 'admin', email: 'admin@mayisafe.cn', role: 'admin', status: 'active', lastLogin: '2024-04-17 10:00', createTime: '2024-01-01' },
    { id: 2, username: 'operator', email: 'operator@mayisafe.cn', role: 'operator', status: 'active', lastLogin: '2024-04-17 09:30', createTime: '2024-02-15' },
    { id: 3, username: 'auditor', email: 'auditor@mayisafe.cn', role: 'auditor', status: 'active', lastLogin: '2024-04-16 18:00', createTime: '2024-03-01' },
    { id: 4, username: 'testuser', email: 'test@mayisafe.cn', role: 'user', status: 'disabled', lastLogin: '2024-04-10 14:00', createTime: '2024-03-15' },
  ]

  const roleColor = { admin: 'red', operator: 'blue', auditor: 'green', user: 'default' }
  const roleText = { admin: '管理员', operator: '操作员', auditor: '审计员', user: '普通用户' }
  const statusColor = { active: 'success', disabled: 'default' }
  const statusText = { active: '正常', disabled: '已禁用' }

  const columns = [
    { title: '用户名', dataIndex: 'username', key: 'username', render: (t) => <span><UserOutlined style={{ marginRight: 8 }} />{t}</span> },
    { title: '邮箱', dataIndex: 'email', key: 'email' },
    { title: '角色', dataIndex: 'role', key: 'role', render: (r) => <Tag color={roleColor[r]}>{roleText[r]}</Tag> },
    { title: '状态', dataIndex: 'status', key: 'status', render: (s) => <Tag color={statusColor[s]}>{statusText[s]}</Tag> },
    { title: '最后登录', dataIndex: 'lastLogin', key: 'lastLogin' },
    { title: '创建时间', dataIndex: 'createTime', key: 'createTime' },
    {
      title: '操作',
      key: 'action',
      render: () => (
        <Space>
          <Button type="text" size="small" icon={<EditOutlined />}>编辑</Button>
          <Button type="text" size="small" danger icon={<DeleteOutlined />}>删除</Button>
        </Space>
      )
    }
  ]

  const handleAddUser = () => {
    form.validateFields().then(values => {
      message.success('用户创建成功')
      setIsModalOpen(false)
      form.resetFields()
    })
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><TeamOutlined style={{ marginRight: 8 }} />用户管理</h1>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setIsModalOpen(true)}>添加用户</Button>
      </div>
      <Card className="content-card" bordered={false}>
        <Table columns={columns} dataSource={data} rowKey="id" pagination={{ pageSize: 10 }} />
      </Card>

      <Modal
        title="添加用户"
        open={isModalOpen}
        onOk={handleAddUser}
        onCancel={() => setIsModalOpen(false)}
      >
        <Form form={form} layout="vertical">
          <Form.Item label="用户名" name="username" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input placeholder="请输入用户名" />
          </Form.Item>
          <Form.Item label="邮箱" name="email" rules={[{ required: true, message: '请输入邮箱' }]}>
            <Input placeholder="请输入邮箱" />
          </Form.Item>
          <Form.Item label="角色" name="role" rules={[{ required: true, message: '请选择角色' }]}>
            <Select placeholder="请选择角色">
              <Select.Option value="admin">管理员</Select.Option>
              <Select.Option value="operator">操作员</Select.Option>
              <Select.Option value="auditor">审计员</Select.Option>
              <Select.Option value="user">普通用户</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item label="初始密码" name="password">
            <Input.Password placeholder="请输入初始密码" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default UserList
