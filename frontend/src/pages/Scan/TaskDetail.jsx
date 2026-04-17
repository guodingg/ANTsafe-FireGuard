import { useState, useEffect } from 'react'
import { Card, Descriptions, Tag, Button, Space, Progress, Table, message, Spin } from 'antd'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeftOutlined, PlayCircleOutlined, PauseCircleOutlined, DeleteOutlined, FileTextOutlined } from '@ant-design/icons'
import api from '../../services/api'

const TaskDetail = () => {
  const { id } = useParams()
  const navigate = useNavigate()
  const [task, setTask] = useState(null)
  const [assets, setAssets] = useState([])
  const [vulns, setVulns] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadTaskDetail()
  }, [id])

  const loadTaskDetail = async () => {
    setLoading(true)
    try {
      const [taskData, assetsData, vulnsData] = await Promise.all([
        api.getTask(id),
        api.getAssets({ task_id: id }),
        api.getVulns({ task_id: id })
      ])
      setTask(taskData)
      setAssets(Array.isArray(assetsData) ? assetsData : [])
      setVulns(Array.isArray(vulnsData) ? vulnsData : [])
    } catch (error) {
      message.error('加载任务详情失败')
    } finally {
      setLoading(false)
    }
  }

  const handleStartTask = async () => {
    try {
      await api.startTask(id)
      message.success('任务已启动')
      loadTaskDetail()
    } catch (error) {
      message.error('启动任务失败')
    }
  }

  const handleGenerateReport = async () => {
    try {
      await api.generateReport(id)
      message.success('报告生成中')
    } catch (error) {
      message.error('生成报告失败')
    }
  }

  if (loading) {
    return <Spin tip="加载中..." style={{ display: 'flex', justifyContent: 'center', marginTop: 100 }} />
  }

  if (!task) {
    return <Card>任务不存在</Card>
  }

  const statusMap = {
    completed: { color: 'success', text: '已完成' },
    running: { color: 'processing', text: '扫描中' },
    pending: { color: 'warning', text: '等待中' },
    paused: { color: 'default', text: '已暂停' },
    failed: { color: 'error', text: '失败' }
  }
  const { color, text } = statusMap[task.status] || { color: 'default', text: task.status }

  const assetColumns = [
    { title: 'IP地址', dataIndex: 'ip', key: 'ip' },
    { title: '端口', dataIndex: 'port', key: 'port', render: (p) => <Tag>{p}</Tag> },
    { title: '服务', dataIndex: 'service', key: 'service' },
    { title: '产品', dataIndex: 'product', key: 'product' },
    { title: '版本', dataIndex: 'version', key: 'version' },
    { title: '状态', dataIndex: 'status', key: 'status', render: (s) => <Tag color={s === 'alive' ? 'success' : 'error'}>{s}</Tag> }
  ]

  const vulnColumns = [
    { title: '漏洞名称', dataIndex: 'name', key: 'name', render: (t) => <span style={{ fontWeight: 500 }}>{t}</span> },
    { title: 'CVE', dataIndex: 'cve', key: 'cve' },
    { title: '严重性', dataIndex: 'severity', key: 'severity', render: (s) => {
      const color = { critical: 'red', high: 'orange', medium: 'gold', low: 'green', info: 'blue' }
      return <Tag color={color[s]}>{s?.toUpperCase()}</Tag>
    }},
    { title: '状态', dataIndex: 'status', key: 'status', render: (s) => <Tag>{s}</Tag> }
  ]

  return (
    <div>
      <div className="page-header">
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/scan/tasks')}>返回</Button>
        <Space>
          {(task.status === 'pending' || task.status === 'paused') && (
            <Button type="primary" icon={<PlayCircleOutlined />} onClick={handleStartTask}>启动</Button>
          )}
          {task.status === 'completed' && (
            <Button icon={<FileTextOutlined />} onClick={handleGenerateReport}>生成报告</Button>
          )}
        </Space>
      </div>

      <Card className="content-card" bordered={false}>
        <Descriptions title="任务信息" column={2}>
          <Descriptions.Item label="任务名称">{task.name}</Descriptions.Item>
          <Descriptions.Item label="状态"><Tag color={color}>{text}</Tag></Descriptions.Item>
          <Descriptions.Item label="扫描类型">{task.scan_type}</Descriptions.Item>
          <Descriptions.Item label="扫描目标">{task.target}</Descriptions.Item>
          <Descriptions.Item label="创建时间">{new Date(task.created_at).toLocaleString()}</Descriptions.Item>
          <Descriptions.Item label="完成时间">{task.finished_at ? new Date(task.finished_at).toLocaleString() : '-'}</Descriptions.Item>
        </Descriptions>
        
        <div style={{ marginTop: 24 }}>
          <span>扫描进度：</span>
          <Progress percent={task.progress} status={task.progress === 100 ? 'success' : 'active'} style={{ marginTop: 8 }} />
          <div style={{ marginTop: 8 }}>
            <span>主机进度：{task.scanned_hosts || 0} / {task.total_hosts || 0}</span>
            <span style={{ marginLeft: 24 }}>发现漏洞：{task.found_vulns || 0}</span>
          </div>
        </div>
      </Card>

      <Card className="content-card" bordered={false} title="资产列表">
        <Table columns={assetColumns} dataSource={assets} rowKey="id" pagination={{ pageSize: 10 }} />
      </Card>

      <Card className="content-card" bordered={false} title="漏洞列表">
        <Table columns={vulnColumns} dataSource={vulns} rowKey="id" pagination={{ pageSize: 10 }} />
      </Card>
    </div>
  )
}

export default TaskDetail
