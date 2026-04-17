import { useState, useEffect } from 'react'
import { Card, Table, Input, Select, Space, Tag, Button, message, Spin } from 'antd'
import { SearchOutlined, SafetyOutlined, ReloadOutlined } from '@ant-design/icons'
import api from '../../services/api'

const AssetList = () => {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(false)
  const [stats, setStats] = useState({ total: 0, alive: 0, services: [] })
  const [filters, setFilters] = useState({ service: null, status: null })
  const [pagination, setPagination] = useState({ current: 1, pageSize: 10, total: 0 })

  useEffect(() => {
    loadAssets()
    loadStats()
  }, [pagination.current, filters])

  const loadAssets = async () => {
    setLoading(true)
    try {
      const params = {
        skip: (pagination.current - 1) * pagination.pageSize,
        limit: pagination.pageSize
      }
      if (filters.service) params.service = filters.service
      if (filters.status) params.status = filters.status

      const result = await api.getAssets(params)
      setData(Array.isArray(result) ? result : [])
    } catch (error) {
      message.error('加载资产列表失败')
    } finally {
      setLoading(false)
    }
  }

  const loadStats = async () => {
    try {
      const result = await api.getAssetStats()
      setStats(result)
    } catch (error) {
      console.error('加载统计失败')
    }
  }

  const columns = [
    { title: 'IP地址', dataIndex: 'ip', key: 'ip', render: (t) => <span style={{ fontFamily: 'monospace' }}>{t}</span> },
    { title: '主机名', dataIndex: 'hostname', key: 'hostname', ellipsis: true },
    { title: '端口', dataIndex: 'port', key: 'port', render: (p) => <Tag>{p}</Tag> },
    { title: '协议', dataIndex: 'protocol', key: 'protocol' },
    { title: '服务', dataIndex: 'service', key: 'service', render: (s) => <Tag color="blue">{s}</Tag> },
    { title: '产品', dataIndex: 'product', key: 'product' },
    { title: '版本', dataIndex: 'version', key: 'version' },
    { 
      title: '操作系统', 
      dataIndex: 'os', 
      key: 'os',
      render: (t) => t ? <Tag>{t}</Tag> : <span style={{ color: '#999' }}>-</span>
    },
    { 
      title: '状态', 
      dataIndex: 'status', 
      key: 'status', 
      render: (s) => <Tag color={s === 'alive' ? 'success' : 'error'}>{s === 'alive' ? '存活' : '离线'}</Tag> 
    },
    { 
      title: '漏洞', 
      dataIndex: 'vulns', 
      key: 'vulns', 
      render: (v) => v > 0 ? <Tag color="red">{v}</Tag> : <Tag color="green">0</Tag> 
    }
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><SafetyOutlined style={{ marginRight: 8 }} />资产管理</h1>
        <Space>
          <Tag>存活: {stats.alive}</Tag>
          <Tag>总计: {stats.total}</Tag>
          <Button icon={<ReloadOutlined />} onClick={() => { loadAssets(); loadStats(); }}>刷新</Button>
        </Space>
      </div>

      <Card className="content-card" bordered={false}>
        <Space style={{ marginBottom: 16 }} wrap>
          <Input 
            placeholder="搜索IP/主机名" 
            prefix={<SearchOutlined />} 
            style={{ width: 200 }}
            allowClear
          />
          <Select 
            placeholder="服务类型" 
            style={{ width: 120 }} 
            allowClear
            onChange={(v) => setFilters(f => ({ ...f, service: v }))}
          >
            {stats.services?.map(s => (
              <Select.Option key={s.name} value={s.name}>{s.name} ({s.count})</Select.Option>
            ))}
          </Select>
          <Select 
            placeholder="状态" 
            style={{ width: 100 }} 
            allowClear
            onChange={(v) => setFilters(f => ({ ...f, status: v }))}
          >
            <Select.Option value="alive">存活</Select.Option>
            <Select.Option value="down">离线</Select.Option>
          </Select>
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

export default AssetList
