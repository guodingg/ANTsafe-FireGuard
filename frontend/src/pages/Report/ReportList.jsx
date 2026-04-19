import { useState, useEffect } from 'react'
import { Card, Table, Button, Space, Tag, Input, message, Modal, Select, Spin, Typography } from 'antd'
import { FileTextOutlined, PlusOutlined, DownloadOutlined, DeleteOutlined, SearchOutlined, ReloadOutlined, EyeOutlined, FileOutlined, FolderOutlined } from '@ant-design/icons'
import api from '../../services/api'

const { Text, Title } = Typography

const ReportList = () => {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(false)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [isPreviewModalOpen, setIsPreviewModalOpen] = useState(false)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [previewContent, setPreviewContent] = useState('')
  const [previewTitle, setPreviewTitle] = useState('')
  const [previewType, setPreviewType] = useState('')
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

  // 预览报告
  const handlePreview = async (record) => {
    setPreviewLoading(true)
    setIsPreviewModalOpen(true)
    setPreviewTitle(record.name)
    setPreviewType(record.type)

    try {
      const report = await api.getReport(record.id)

      if (report.content) {
        if (record.type === 'markdown') {
          setPreviewContent(report.content)
        } else if (record.type === 'html') {
          // HTML直接显示
          setPreviewContent(report.content)
        } else if (record.type === 'pdf') {
          // PDF显示为二进制提示
          setPreviewContent('【PDF文件】\n\n此报告为PDF格式，请点击下载按钮查看完整内容。')
        } else if (record.type === 'word' || record.type === 'excel') {
          setPreviewContent('【Word/Excel文件】\n\n此报告为Office格式，请点击下载按钮查看完整内容。')
        } else {
          setPreviewContent(report.content)
        }
      } else {
        setPreviewContent('报告内容为空')
      }
    } catch (error) {
      message.error('加载报告失败')
      setPreviewContent('加载失败，请重试')
    } finally {
      setPreviewLoading(false)
    }
  }

  // 下载报告
  const handleDownload = async (record) => {
    try {
      message.loading({ content: '正在准备下载...', key: 'download' })

      const blob = await api.downloadReport(record.id)

      // 根据类型设置文件名
      const extensions = {
        markdown: '.md',
        html: '.html',
        pdf: '.pdf',
        word: '.docx',
        excel: '.xlsx'
      }
      const ext = extensions[record.type] || '.txt'
      const filename = `${record.name}${ext}`

      // 创建下载链接
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      message.success({ content: '下载完成', key: 'download' })
    } catch (error) {
      message.error({ content: '下载失败: ' + (error.message || '未知错误'), key: 'download' })
    }
  }

  // 删除报告
  const handleDelete = async (record) => {
    try {
      await api.deleteReport(record.id)
      message.success('报告已删除')
      loadReports()
    } catch (error) {
      message.error('删除失败')
    }
  }

  const getTypeIcon = (type) => {
    const icons = {
      markdown: <FileOutlined />,
      html: <FolderOutlined />,
      pdf: <FileTextOutlined />,
      word: <FileTextOutlined />,
      excel: <FileTextOutlined />
    }
    return icons[type] || <FileTextOutlined />
  }

  const typeColor = { markdown: 'blue', word: 'green', pdf: 'red', excel: 'orange', html: 'purple' }

  const columns = [
    {
      title: '报告名称',
      dataIndex: 'name',
      key: 'name',
      render: (t, r) => (
        <Space>
          <span style={{ fontWeight: 500 }}>{getTypeIcon(r.type)}</span>
          <span style={{ fontWeight: 500 }}>{t}</span>
        </Space>
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
          <Button type="text" size="small" icon={<EyeOutlined />} onClick={() => handlePreview(record)}>
            预览
          </Button>
          <Button type="text" size="small" icon={<DownloadOutlined />} onClick={() => handleDownload(record)}>
            下载
          </Button>
          <Button type="text" size="small" danger icon={<DeleteOutlined />} onClick={() => handleDelete(record)}>
            删除
          </Button>
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

      {/* 生成报告弹窗 */}
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

      {/* 预览报告弹窗 */}
      <Modal
        title={
          <Space>
            {getTypeIcon(previewType)}
            <span>{previewTitle}</span>
            <Tag color={typeColor[previewType]}>{previewType?.toUpperCase()}</Tag>
          </Space>
        }
        open={isPreviewModalOpen}
        onCancel={() => setIsPreviewModalOpen(false)}
        width={800}
        footer={
          <Space>
            <Button onClick={() => setIsPreviewModalOpen(false)}>关闭</Button>
            {previewType === 'markdown' && (
              <Button type="primary" icon={<DownloadOutlined />} onClick={() => {
                // 找到对应的记录并下载
                const record = data.find(r => r.name === previewTitle)
                if (record) handleDownload(record)
              }}>
                下载
              </Button>
            )}
          </Space>
        }
      >
        {previewLoading ? (
          <div style={{ textAlign: 'center', padding: 50 }}>
            <Spin size="large" />
            <Text type="secondary" style={{ display: 'block', marginTop: 16 }}>正在加载报告内容...</Text>
          </div>
        ) : (
          <div
            style={{
              maxHeight: 500,
              overflow: 'auto',
              background: '#f5f5f5',
              padding: 16,
              borderRadius: 4,
              fontFamily: previewType === 'markdown' ? 'monospace' : 'inherit',
              fontSize: previewType === 'markdown' ? 13 : 14,
              whiteSpace: previewType === 'markdown' ? 'pre-wrap' : 'normal',
              wordBreak: 'break-word',
              lineHeight: 1.8
            }}
          >
            {/* Markdown渲染简易处理 */}
            {previewType === 'markdown' ? (
              <div
                dangerouslySetInnerHTML={{
                  __html: previewContent
                    .replace(/^# (.*$)/gm, '<h1 style="font-size:24px;border-bottom:1px solid #eee;padding-bottom:8px;margin:16px 0;">$1</h1>')
                    .replace(/^## (.*$)/gm, '<h2 style="font-size:20px;border-bottom:1px solid #eee;padding-bottom:6px;margin:14px 0;">$1</h2>')
                    .replace(/^### (.*$)/gm, '<h3 style="font-size:16px;margin:12px 0;">$1</h3>')
                    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                    .replace(/\*(.*?)\*/g, '<em>$1</em>')
                    .replace(/`(.*?)`/g, '<code style="background:#eee;padding:2px 6px;border-radius:3px;">$1</code>')
                    .replace(/^- (.*$)/gm, '<li style="margin:4px 0;">$1</li>')
                    .replace(/\n\n/g, '</p><p style="margin:8px 0;">')
                }}
              />
            ) : (
              previewContent
            )}
          </div>
        )}
      </Modal>
    </div>
  )
}

export default ReportList
