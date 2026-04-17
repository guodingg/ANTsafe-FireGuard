import { Card, Table, Input, Select, Space, Tag, Button, DatePicker } from 'antd'
import { HistoryOutlined, DownloadOutlined, SearchOutlined } from '@ant-design/icons'

const LogList = () => {
  const data = [
    { id: 1, user: 'admin', action: '登录系统', module: '认证模块', ip: '192.168.1.100', time: '2024-04-17 10:00:00', status: 'success' },
    { id: 2, user: 'admin', action: '创建扫描任务', module: '扫描模块', ip: '192.168.1.100', time: '2024-04-17 10:05:00', status: 'success' },
    { id: 3, user: 'admin', action: '导出报告', module: '报告模块', ip: '192.168.1.100', time: '2024-04-17 10:30:00', status: 'success' },
    { id: 4, user: 'admin', action: '修改用户密码', module: '用户模块', ip: '192.168.1.100', time: '2024-04-17 11:00:00', status: 'success' },
  ]

  const columns = [
    { title: '用户', dataIndex: 'user', key: 'user' },
    { title: '操作', dataIndex: 'action', key: 'action', render: (t) => <span style={{ fontWeight: 500 }}>{t}</span> },
    { title: '模块', dataIndex: 'module', key: 'module' },
    { title: 'IP地址', dataIndex: 'ip', key: 'ip' },
    { title: '时间', dataIndex: 'time', key: 'time' },
    { title: '状态', dataIndex: 'status', key: 'status', render: (s) => <Tag color={s === 'success' ? 'success' : 'error'}>{s === 'success' ? '成功' : '失败'}</Tag> },
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><HistoryOutlined style={{ marginRight: 8 }} />日志审计</h1>
        <Button icon={<DownloadOutlined />}>导出日志</Button>
      </div>
      <Card className="content-card" bordered={false}>
        <Space style={{ marginBottom: 16 }} wrap>
          <Input placeholder="搜索用户/操作" prefix={<SearchOutlined />} style={{ width: 200 }} />
          <Select placeholder="模块" style={{ width: 120 }} allowClear>
            <Select.Option value="auth">认证模块</Select.Option>
            <Select.Option value="scan">扫描模块</Select.Option>
            <Select.Option value="user">用户模块</Select.Option>
          </Select>
          <Select placeholder="状态" style={{ width: 100 }} allowClear>
            <Select.Option value="success">成功</Select.Option>
            <Select.Option value="failed">失败</Select.Option>
          </Select>
        </Space>
        <Table columns={columns} dataSource={data} rowKey="id" pagination={{ pageSize: 10 }} />
      </Card>
    </div>
  )
}

export default LogList
