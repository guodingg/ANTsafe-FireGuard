import { Table, Card, Button, Space, Input, Select, Tag, Modal, message } from 'antd'
import { PlusOutlined, SearchOutlined, PlayCircleOutlined, PauseCircleOutlined, DeleteOutlined, EyeOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { useState } from 'react'

const TaskList = () => {
  const navigate = useNavigate()
  const [selectedRowKeys, setSelectedRowKeys] = useState([])

  const tasks = [
    { id: 1, name: '内网资产扫描', target: '192.168.1.0/24', type: 'asset', status: 'completed', progress: 100, vulns: 12, startTime: '2024-04-17 10:30', endTime: '2024-04-17 10:45' },
    { id: 2, name: 'Web漏洞检测', target: 'example.com', type: 'vuln', status: 'running', progress: 68, vulns: 5, startTime: '2024-04-17 14:20', endTime: '-' },
    { id: 3, name: '边界扫描', target: '10.0.0.0/8', type: 'full', status: 'pending', progress: 0, vulns: 0, startTime: '2024-04-17 15:00', endTime: '-' },
    { id: 4, name: '数据库审计', target: '192.168.2.10', type: 'custom', status: 'completed', progress: 100, vulns: 3, startTime: '2024-04-16 09:15', endTime: '2024-04-16 09:30' },
  ]

  const columns = [
    { title: '任务名称', dataIndex: 'name', key: 'name' },
    { title: '扫描目标', dataIndex: 'target', key: 'target' },
    { title: '扫描类型', dataIndex: 'type', key: 'type', render: (type) => {
      const map = { asset: '资产发现', vuln: '漏洞扫描', full: '全面扫描', custom: '自定义' }
      return map[type] || type
    }},
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status) => {
        const map = { completed: { color: 'success', text: '已完成' }, running: { color: 'processing', text: '扫描中' }, pending: { color: 'warning', text: '等待中' }, paused: { color: 'default', text: '已暂停' } }
        return <Tag color={map[status]?.color}>{map[status]?.text}</Tag>
      }
    },
    {
      title: '进度',
      dataIndex: 'progress',
      key: 'progress',
      render: (progress, record) => <Progress percent={progress} size="small" status={progress === 100 ? 'success' : record.status === 'paused' ? 'exception' : 'active'} />
    },
    { title: '发现漏洞', dataIndex: 'vulns', key: 'vulns', render: (v) => v > 0 ? <span style={{ color: '#FF4D4F', fontWeight: 500 }}>{v}</span> : v },
    { title: '开始时间', dataIndex: 'startTime', key: 'startTime' },
    { title: '结束时间', dataIndex: 'endTime', key: 'endTime' },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Space>
          <Button type="text" size="small" icon={<EyeOutlined />} onClick={() => navigate(`/scan/tasks/${record.id}`)}>查看</Button>
          {record.status === 'running' && <Button type="text" size="small" icon={<PauseCircleOutlined />}>暂停</Button>}
          {record.status === 'pending' && <Button type="text" size="small" icon={<PlayCircleOutlined />} type="primary">开始</Button>}
          <Button type="text" size="small" danger icon={<DeleteOutlined />}>删除</Button>
        </Space>
      )
    }
  ]

  const rowSelection = {
    selectedRowKeys,
    onChange: setSelectedRowKeys
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">扫描任务</h1>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => navigate('/scan/tasks/new')}>创建任务</Button>
      </div>

      <Card className="content-card" bordered={false}>
        <Space style={{ marginBottom: 16 }} wrap>
          <Input placeholder="搜索任务名称" prefix={<SearchOutlined />} style={{ width: 200 }} />
          <Select placeholder="扫描类型" style={{ width: 120 }} allowClear>
            <Select.Option value="asset">资产发现</Select.Option>
            <Select.Option value="vuln">漏洞扫描</Select.Option>
            <Select.Option value="full">全面扫描</Select.Option>
          </Select>
          <Select placeholder="状态" style={{ width: 100 }} allowClear>
            <Select.Option value="running">扫描中</Select.Option>
            <Select.Option value="completed">已完成</Select.Option>
            <Select.Option value="pending">等待中</Select.Option>
          </Select>
        </Space>

        <Table
          rowSelection={rowSelection}
          columns={columns}
          dataSource={tasks}
          rowKey="id"
          pagination={{ pageSize: 10 }}
        />
      </Card>
    </div>
  )
}

import { Progress } from 'antd'

export default TaskList
