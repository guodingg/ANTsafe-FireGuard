import { useState, useEffect } from 'react'
import { Card, Table, Input, Select, Space, Tag, Button, DatePicker, message } from 'antd'
import { HistoryOutlined, DownloadOutlined, SearchOutlined, ReloadOutlined } from '@ant-design/icons'
import api from '../../services/api'
import dayjs from 'dayjs'

const { RangePicker } = DatePicker

const LogList = () => {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(false)
  const [filters, setFilters] = useState({ module: null, action: null })
  const [pagination, setPagination] = useState({ current: 1, pageSize: 20, total: 0 })

  useEffect(() => {
    loadLogs()
  }, [pagination.current, filters])

  const loadLogs = async () => {
    setLoading(true)
    try {
      const params = {
        skip: (pagination.current - 1) * pagination.pageSize,
        limit: pagination.pageSize
      }
      if (filters.module) params.module = filters.module
      if (filters.action) params.action = filters.action

      const result = await api.getLogs(params)
      setData(Array.isArray(result) ? result : [])
    } catch (error) {
      message.error('加载日志列表失败')
    } finally {
      setLoading(false)
    }
  }

  const handleExport = () => {
    message.info('导出功能开发中')
  }

  const columns = [
    { title: '用户', dataIndex: 'user_id', key: 'user_id', render: (t) => t || '-' },
    { title: '操作', dataIndex: 'action', key: 'action', render: (t) => <span style={{ fontWeight: 500 }}>{t}</span> },
    { title: '模块', dataIndex: 'module', key: 'module', render: (t) => <Tag color="blue">{t}</Tag> },
    { title: '资源', dataIndex: 'resource', key: 'resource', ellipsis: true, render: (t) => t || '-' },
    { title: 'IP地址', dataIndex: 'ip', key: 'ip', render: (t) => <span style={{ fontFamily: 'monospace' }}>{t}</span> },
    { 
      title: '方法', 
      dataIndex: 'method', 
      key: 'method', 
      render: (t) => {
        const color = { GET: 'green', POST: 'blue', PUT: 'orange', DELETE: 'red' }
        return <Tag color={color[t]}>{t}</Tag>
      }
    },
    { 
      title: '状态', 
      dataIndex: 'status_code', 
      key: 'status_code', 
      render: (t) => {
        if (!t) return '-'
        const color = t < 400 ? 'success' : t < 500 ? 'warning' : 'error'
        return <Tag color={color}>{t}</Tag>
      }
    },
    { title: '耗时', dataIndex: 'duration', key: 'duration', render: (t) => t ? `${t}ms` : '-' },
    { title: '时间', dataIndex: 'created_at', key: 'created_at', render: (t) => t ? new Date(t).toLocaleString() : '-' }
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><HistoryOutlined style={{ marginRight: 8 }} />日志审计</h1>
        <Button icon={<DownloadOutlined />} onClick={handleExport}>导出日志</Button>
      </div>

      <Card className="content-card" bordered={false}>
        <Space style={{ marginBottom: 16 }} wrap>
          <Input placeholder="搜索操作" prefix={<SearchOutlined />} style={{ width: 160 }} allowClear />
          <Select 
            placeholder="模块" 
            style={{ width: 120 }} 
            allowClear
            onChange={(v) => setFilters(f => ({ ...f, module: v }))}
          >
            <Select.Option value="auth">认证模块</Select.Option>
            <Select.Option value="scan">扫描模块</Select.Option>
            <Select.Option value="user">用户模块</Select.Option>
            <Select.Option value="asset">资产模块</Select.Option>
            <Select.Option value="vuln">漏洞模块</Select.Option>
            <Select.Option value="report">报告模块</Select.Option>
          </Select>
          <Select 
            placeholder="状态" 
            style={{ width: 100 }} 
            allowClear
            onChange={(v) => setFilters(f => ({ ...f, status: v }))}
          >
            <Select.Option value="success">成功</Select.Option>
            <Select.Option value="failed">失败</Select.Option>
          </Select>
          <Button icon={<ReloadOutlined />} onClick={loadLogs}>刷新</Button>
        </Space>

        <Table 
          columns={columns} 
          dataSource={data} 
          rowKey="id" 
          loading={loading}
          pagination={{
            current: pagination.current,
            pageSize: pagination.pageSize,
            total: pagination.total,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 条`
          }}
          onChange={(p) => setPagination(p)}
        />
      </Card>
    </div>
  )
}

export default LogList
