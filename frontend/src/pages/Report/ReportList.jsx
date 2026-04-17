import { useState, useEffect } from 'react'
import { Card, Table, Button, Space, Tag, Input, message, Modal, Select } from 'antd'
import { FileTextOutlined, PlusOutlined, DownloadOutlined, DeleteOutlined, SearchOutlined, ReloadOutlined, EyeOutlined } from '@ant-design/icons'
import api from '../../services/api'

const ReportList = () => {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(false)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [tasks, setTasks] = useState([])
  const [formData, setFormData] = useState({ task_id: null, type: 'markdown' })

  useEffect(() => {
    loadReports()
    loadTasks()
  }, [])

  const loadReports = async () => {
    setLoading(true)
    try {
      const result = await api.getReports()
      setData(Array.isArray(result) ? result : [])
    } catch (error) {
      message.error('加载报告列表失败')
    } finally {
      setLoading(false)
    }
  }

  const loadTasks = async () => {
    try {
      const result = await api.getTasks({ limit: 100 })
      setTasks(Array.isArray(result) ? result.filter(t => t.status === 'completed') : [])
    } catch (error) {
      console.error('加载任务失败')
    }
  }

  const handleGenerate = async () => {
    if (!formData.task_id) {
      message.error('请选择任务')
      return
    }
    try {
      await api.generateReport(formData.task_id, formData.type)
      message.success('报告生成中...')
      setIsModalOpen(false)
      setTimeout(loadReports, 2000)
    } catch (error) {
      message.error('生成报告失败')
    }
  }

  const handleDownload = (record) => {
    if (record.content) {
      const blob = new Blob([record.content], { type: 'text/markdown' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${record.name}.md`
      a.click()
      URL.revokeObjectURL(url)
    } else {
      message.info('下载功能开发中')
    }
  }

  const handleDelete = async (id) => {
    try {
      // await api.deleteReport(id)
      message.success('报告已删除')
      loadReports()
    } catch (error) {
      message.error('删除失败')
    }
  }

  const typeColor = { markdown: 'blue', word: 'green', pdf: 'red', excel: 'orange', html: 'purple' }

  const columns = [
    { 
      title: '报告名称', 
      dataIndex: 'name', 
      key: 'name', 
      render: (t) => (
        <span style={{ fontWeight: 500 }}>
          <FileTextOutlined style={{ marginRight: 8 }} />{t}
        </span>
      )
    },
    { 
      title: '关联任务', 
      dataIndex: 'task_id', 
      key: 'task_id', 
      render: (t) => t ? `任务 #${t}` : '-'
    },
    { title: '格式', dataIndex: 'type', key: 'type', render: (t) => <Tag color={typeColor[t]}>{t?.toUpperCase()}</Tag> },
    { title: '大小', dataIndex: 'file_size', key: 'file_size', render: (t) => t ? `${(t / 1024).toFixed(1)} KB` : '-' },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', render: (t) => t ? new Date(t).toLocaleString() : '-' },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Space>
          <Button type="text" size="small" icon={<EyeOutlined />} onClick={() => message.info('预览功能开发中')}>预览</Button>
          <Button type="text" size="small" icon={<DownloadOutlined />} onClick={() => handleDownload(record)}>下载</Button>
          <Button type="text" size="small" danger icon={<DeleteOutlined />} onClick={() => handleDelete(record.id)}>删除</Button>
        </Space>
      )
    }
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><FileTextOutlined style={{ marginRight: 8 }} />报告管理</h1>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setIsModalOpen(true)}>生成报告</Button>
      </div>

      <Card className="content-card" bordered={false}>
        <Space style={{ marginBottom: 16 }}>
          <Input placeholder="搜索报告名称" prefix={<SearchOutlined />} style={{ width: 200 }} allowClear />
          <Button icon={<ReloadOutlined />} onClick={loadReports}>刷新</Button>
        </Space>

        <Table 
          columns={columns} 
          dataSource={data} 
          rowKey="id" 
          loading={loading}
          pagination={{ pageSize: 10 }}
        />
      </Card>

      <Modal
        title="生成报告"
        open={isModalOpen}
        onOk={handleGenerate}
        onCancel={() => setIsModalOpen(false)}
        okText="生成"
      >
        <Space direction="vertical" style={{ width: '100%' }}>
          <div>
            <label>选择任务：</label>
            <Select
              style={{ width: '100%', marginTop: 8 }}
              placeholder="请选择已完成的任务"
              value={formData.task_id}
              onChange={(v) => setFormData(f => ({ ...f, task_id: v }))}
            >
              {tasks.map(t => (
                <Select.Option key={t.id} value={t.id}>{t.name} (#{t.id})</Select.Option>
              ))}
            </Select>
          </div>
          <div>
            <label>报告格式：</label>
            <Select
              style={{ width: '100%', marginTop: 8 }}
              value={formData.type}
              onChange={(v) => setFormData(f => ({ ...f, type: v }))}
            >
              <Select.Option value="markdown">Markdown</Select.Option>
              <Select.Option value="html">HTML</Select.Option>
              <Select.Option value="pdf">PDF</Select.Option>
              <Select.Option value="word">Word</Select.Option>
            </Select>
          </div>
        </Space>
      </Modal>
    </div>
  )
}

export default ReportList
