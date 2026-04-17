import { useState, useEffect } from 'react'
import { Table, Card, Button, Space, Input, Select, Tag, Modal, Form, message, Popconfirm } from 'antd'
import { PlusOutlined, SearchOutlined, PlayCircleOutlined, PauseCircleOutlined, DeleteOutlined, EyeOutlined, ReloadOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import api from '../../services/api'

const TaskList = () => {
  const navigate = useNavigate()
  const [tasks, setTasks] = useState([])
  const [loading, setLoading] = useState(false)
  const [pagination, setPagination] = useState({ current: 1, pageSize: 10, total: 0 })
  const [filters, setFilters] = useState({ status: null, scan_type: null })
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [form] = Form.useForm()

  useEffect(() => {
    loadTasks()
  }, [pagination.current, pagination.pageSize, filters])

  const loadTasks = async () => {
    setLoading(true)
    try {
      const params = {
        skip: (pagination.current - 1) * pagination.pageSize,
        limit: pagination.pageSize
      }
      if (filters.status) params.status_filter = filters.status
      if (filters.scan_type) params.scan_type = filters.scan_type
      
      const data = await api.getTasks(params)
      setTasks(Array.isArray(data) ? data : [])
      // 分页信息从响应头或响应体获取
      setPagination(p => ({ ...p, total: Array.isArray(data) ? data.length : 0 }))
    } catch (error) {
      message.error('加载任务列表失败')
    } finally {
      setLoading(false)
    }
  }

  const handleCreateTask = async (values) => {
    try {
      await api.createTask(values)
      message.success('任务创建成功')
      setIsModalOpen(false)
      form.resetFields()
      loadTasks()
    } catch (error) {
      message.error('创建任务失败')
    }
  }

  const handleStartTask = async (id) => {
    try {
      await api.startTask(id)
      message.success('任务已启动')
      loadTasks()
    } catch (error) {
      message.error('启动任务失败')
    }
  }

  const handleDeleteTask = async (id) => {
    try {
      await api.deleteTask(id)
      message.success('任务已删除')
      loadTasks()
    } catch (error) {
      message.error('删除任务失败')
    }
  }

  const columns = [
    { title: '任务名称', dataIndex: 'name', key: 'name', render: (t) => <span style={{ fontWeight: 500 }}>{t}</span> },
    { title: '扫描目标', dataIndex: 'target', key: 'target', ellipsis: true },
    { title: '扫描类型', dataIndex: 'scan_type', key: 'scan_type', render: (t) => {
      const map = { asset: '资产发现', vuln: '漏洞扫描', full: '全面扫描', custom: '自定义' }
      return <Tag color="blue">{map[t] || t}</Tag>
    }},
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status) => {
        const map = {
          completed: { color: 'success', text: '已完成' },
          running: { color: 'processing', text: '扫描中' },
          pending: { color: 'warning', text: '等待中' },
          paused: { color: 'default', text: '已暂停' },
          failed: { color: 'error', text: '失败' }
        }
        const { color, text } = map[status] || { color: 'default', text: status }
        return <Tag color={color}>{text}</Tag>
      }
    },
    {
      title: '进度',
      dataIndex: 'progress',
      key: 'progress',
      render: (progress) => <Progress percent={progress} size="small" status={progress === 100 ? 'success' : 'active'} />
    },
    { title: '发现漏洞', dataIndex: 'found_vulns', key: 'found_vulns', render: (v) => v > 0 ? <span style={{ color: '#FF4D4F', fontWeight: 500 }}>{v}</span> : v },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', render: (t) => t ? new Date(t).toLocaleString() : '-' },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Space>
          <Button type="text" size="small" icon={<EyeOutlined />} onClick={() => navigate(`/scan/tasks/${record.id}`)}>查看</Button>
          {record.status === 'running' && (
            <Button type="text" size="small" icon={<PauseCircleOutlined />} onClick={() => handlePauseTask(record.id)}>暂停</Button>
          )}
          {(record.status === 'pending' || record.status === 'paused') && (
            <Button type="text" size="small" icon={<PlayCircleOutlined />} onClick={() => handleStartTask(record.id)}>启动</Button>
          )}
          <Popconfirm title="确定删除?" onConfirm={() => handleDeleteTask(record.id)}>
            <Button type="text" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      )
    }
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">扫描任务</h1>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setIsModalOpen(true)}>创建任务</Button>
      </div>

      <Card className="content-card" bordered={false}>
        <Space style={{ marginBottom: 16 }} wrap>
          <Input 
            placeholder="搜索任务名称" 
            prefix={<SearchOutlined />} 
            style={{ width: 200 }}
            onSearch={(v) => console.log('search', v)}
          />
          <Select 
            placeholder="扫描类型" 
            style={{ width: 120 }} 
            allowClear
            onChange={(v) => setFilters(f => ({ ...f, scan_type: v }))}
          >
            <Select.Option value="asset">资产发现</Select.Option>
            <Select.Option value="vuln">漏洞扫描</Select.Option>
            <Select.Option value="full">全面扫描</Select.Option>
          </Select>
          <Select 
            placeholder="状态" 
            style={{ width: 100 }} 
            allowClear
            onChange={(v) => setFilters(f => ({ ...f, status: v }))}
          >
            <Select.Option value="running">扫描中</Select.Option>
            <Select.Option value="completed">已完成</Select.Option>
            <Select.Option value="pending">等待中</Select.Option>
          </Select>
          <Button icon={<ReloadOutlined />} onClick={loadTasks}>刷新</Button>
        </Space>

        <Table
          columns={columns}
          dataSource={tasks}
          rowKey="id"
          loading={loading}
          pagination={{
            current: pagination.current,
            pageSize: pagination.pageSize,
            total: pagination.total,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total) => `共 ${total} 条`
          }}
          onChange={(p) => setPagination(p)}
        />
      </Card>

      <Modal
        title="创建扫描任务"
        open={isModalOpen}
        onOk={() => form.submit()}
        onCancel={() => setIsModalOpen(false)}
        destroyOnClose
      >
        <Form form={form} layout="vertical" onFinish={handleCreateTask}>
          <Form.Item label="任务名称" name="name" rules={[{ required: true, message: '请输入任务名称' }]}>
            <Input placeholder="请输入任务名称" />
          </Form.Item>
          <Form.Item label="扫描目标" name="target" rules={[{ required: true, message: '请输入扫描目标' }]}>
            <Input.TextArea placeholder="支持单IP、CIDR、域名，每行一个" rows={4} />
          </Form.Item>
          <Form.Item label="扫描类型" name="scan_type" rules={[{ required: true, message: '请选择扫描类型' }]}>
            <Select placeholder="请选择扫描类型">
              <Select.Option value="asset">资产发现</Select.Option>
              <Select.Option value="vuln">漏洞扫描</Select.Option>
              <Select.Option value="full">全面扫描</Select.Option>
              <Select.Option value="custom">自定义</Select.Option>
            </Select>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

import { Progress } from 'antd'

export default TaskList
