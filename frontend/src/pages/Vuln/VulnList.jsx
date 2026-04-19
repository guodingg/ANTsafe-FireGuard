import { useState, useEffect, useCallback } from 'react'
import { Card, Table, Input, Select, Space, Tag, Button, message, Popconfirm, Modal, Descriptions, Divider, Typography } from 'antd'
import { SearchOutlined, SafetyOutlined, ReloadOutlined, CheckCircleOutlined, ToolOutlined, LinkOutlined } from '@ant-design/icons'
import api from '../../services/api'
import useDataCache, { cacheKeys } from '../../store/dataCache'

const { Text, Paragraph } = Typography

const VulnList = () => {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(false)
  const [filters, setFilters] = useState({ severity: null, status: null })
  const [pagination, setPagination] = useState({ current: 1, pageSize: 10, total: 0 })
  const [refreshKey, setRefreshKey] = useState(0)
  const [detailModal, setDetailModal] = useState({ visible: false, data: null })

  const getCache = useDataCache((s) => s.getCache)
  const setCache = useDataCache((s) => s.setCache)

  // 刷新（清除缓存）
  const handleRefresh = useCallback(() => {
    useDataCache.getState().clearCache()  // 清除所有缓存
    setRefreshKey(k => k + 1)
  }, [])

  useEffect(() => {
    loadVulns()
  }, [pagination.current, filters, refreshKey])

  const loadVulns = async () => {
    // 缓存key包含分页和过滤条件
    const cacheKey = `vulns_page_${pagination.current}_${filters.severity || 'all'}_${filters.status || 'all'}`
    const cached = getCache(cacheKey)
    
    if (cached && pagination.current === 1 && !filters.severity && !filters.status) {
      setData(cached)
      return
    }

    setLoading(true)
    try {
      const params = {
        skip: (pagination.current - 1) * pagination.pageSize,
        limit: pagination.pageSize
      }
      if (filters.severity) params.severity = filters.severity
      if (filters.status) params.status = filters.status

      const result = await api.getVulns(params)
      const list = Array.isArray(result) ? result : []
      setData(list)
      setPagination(p => ({ ...p, total: list.length > 0 ? 100 : 0 })) // TODO: get total from API
      
      // 只缓存第一页的无过滤数据
      if (pagination.current === 1 && !filters.severity && !filters.status) {
        setCache(cacheKeys.vulns(), list)
        setCache(cacheKey, list)
      }
    } catch (error) {
      message.error('加载漏洞列表失败')
    } finally {
      setLoading(false)
    }
  }

  const handleVerify = async (id) => {
    try {
      await api.verifyVuln(id)
      message.success('漏洞已验证')
      useDataCache.getState().clearCache()
      loadVulns()
    } catch (error) {
      message.error('操作失败')
    }
  }

  const handleFix = async (id) => {
    try {
      await api.fixVuln(id)
      message.success('已标记为已修复')
      useDataCache.getState().clearCache()
      loadVulns()
    } catch (error) {
      message.error('操作失败')
    }
  }

  const handleFalsePositive = async (id) => {
    try {
      await api.markFalsePositive(id)
      message.success('已标记为误报')
      useDataCache.getState().clearCache()
      loadVulns()
    } catch (error) {
      message.error('操作失败')
    }
  }

  const showDetail = (record) => {
    setDetailModal({ visible: true, data: record })
  }

  const severityColor = { critical: 'red', high: 'orange', medium: 'gold', low: 'green', info: 'blue' }
  const statusColor = { verified: 'success', unverified: 'warning', fixed: 'processing', false_positive: 'default' }
  const statusText = { verified: '已验证', unverified: '待验证', fixed: '已修复', false_positive: '误报' }

  const columns = [
    { 
      title: '漏洞名称', 
      dataIndex: 'name', 
      key: 'name', 
      render: (t, record) => (
        <a onClick={() => showDetail(record)} style={{ fontWeight: 500, color: '#1890ff' }}>
          {t}
        </a>
      )
    },
    { title: 'CVE编号', dataIndex: 'cve', key: 'cve', render: (t) => t || '-' },
    { 
      title: '严重性', 
      dataIndex: 'severity', 
      key: 'severity', 
      render: (s) => <Tag color={severityColor[s]}>{s?.toUpperCase()}</Tag> 
    },
    { title: '目标', dataIndex: 'target', key: 'target', ellipsis: true },
    { 
      title: '漏洞路径', 
      dataIndex: 'path', 
      key: 'path', 
      width: 150,
      ellipsis: true,
      render: (t) => t ? (
        <Text copyable={{ text: t }} style={{ fontFamily: 'monospace', fontSize: 12 }}>
          {t}
        </Text>
      ) : '-'
    },
    { 
      title: '状态', 
      dataIndex: 'status', 
      key: 'status', 
      render: (s) => <Tag color={statusColor[s]}>{statusText[s] || s}</Tag> 
    },
    { title: '发现时间', dataIndex: 'created_at', key: 'created_at', render: (t) => t ? new Date(t).toLocaleDateString() : '-' },
    {
      title: '操作',
      key: 'action',
      width: 180,
      render: (_, record) => (
        <Space size="small">
          {record.status !== 'verified' && (
            <Button type="text" size="small" icon={<CheckCircleOutlined />} onClick={() => handleVerify(record.id)} />
          )}
          {record.status !== 'fixed' && (
            <Button type="text" size="small" icon={<ToolOutlined />} onClick={() => handleFix(record.id)} />
          )}
          <Popconfirm title="误报?" onConfirm={() => handleFalsePositive(record.id)}>
            <Button type="text" size="small" danger>误报</Button>
          </Popconfirm>
        </Space>
      )
    }
  ]

  const renderRemediation = (text) => {
    if (!text) return '-'
    const lines = text.split('\n').filter(l => l.trim())
    return (
      <ul style={{ margin: 0, paddingLeft: 20 }}>
        {lines.map((line, i) => (
          <li key={i} style={{ marginBottom: 4 }}>
            {line.replace(/^\d+\.\s*/, '')} {/* 去掉开头的数字编号 */}
          </li>
        ))}
      </ul>
    )
  }

  const renderDescription = (text) => {
    if (!text) return '-'
    return <Paragraph>{text}</Paragraph>
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><SafetyOutlined style={{ marginRight: 8 }} />漏洞管理</h1>
        <Button icon={<ReloadOutlined />} onClick={loadVulns}>刷新</Button>
      </div>

      <Card className="content-card" bordered={false}>
        <Space style={{ marginBottom: 16 }} wrap>
          <Input placeholder="搜索漏洞名称/CVE" prefix={<SearchOutlined />} style={{ width: 200 }} allowClear />
          <Select 
            placeholder="严重性" 
            style={{ width: 100 }} 
            allowClear
            onChange={(v) => setFilters(f => ({ ...f, severity: v }))}
          >
            <Select.Option value="critical">严重</Select.Option>
            <Select.Option value="high">高危</Select.Option>
            <Select.Option value="medium">中危</Select.Option>
            <Select.Option value="low">低危</Select.Option>
          </Select>
          <Select 
            placeholder="状态" 
            style={{ width: 100 }} 
            allowClear
            onChange={(v) => setFilters(f => ({ ...f, status: v }))}
          >
            <Select.Option value="verified">已验证</Select.Option>
            <Select.Option value="unverified">待验证</Select.Option>
            <Select.Option value="fixed">已修复</Select.Option>
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

      {/* 漏洞详情弹窗 */}
      <Modal
        title={
          <Space>
            <SafetyOutlined />
            <span>{detailModal.data?.name}</span>
          </Space>
        }
        open={detailModal.visible}
        onCancel={() => setDetailModal({ visible: false, data: null })}
        footer={[
          <Button key="close" onClick={() => setDetailModal({ visible: false, data: null })}>
            关闭
          </Button>
        ]}
        width={700}
      >
        {detailModal.data && (
          <div>
            <Descriptions bordered column={2} size="small">
              <Descriptions.Item label="CVE编号" span={2}>
                <Tag color={detailModal.data.cve ? 'red' : 'default'}>
                  {detailModal.data.cve || '未分配'}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="严重性">
                <Tag color={severityColor[detailModal.data.severity]}>
                  {detailModal.data.severity?.toUpperCase()}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={statusColor[detailModal.data.status]}>
                  {statusText[detailModal.data.status] || detailModal.data.status}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="关联资产">
                {detailModal.data.target}
              </Descriptions.Item>
              <Descriptions.Item label="影响产品">
                {detailModal.data.product || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="漏洞路径" span={2}>
                <Text copyable style={{ fontFamily: 'monospace', color: '#1890ff' }}>
                  {detailModal.data.path || '/'}
                </Text>
              </Descriptions.Item>
            </Descriptions>

            <Divider orientation="left">漏洞描述</Divider>
            <Card size="small">
              {renderDescription(detailModal.data.description)}
            </Card>

            <Divider orientation="left">修复建议</Divider>
            <Card size="small">
              {renderRemediation(detailModal.data.remediation)}
            </Card>

            {detailModal.data.payload && (
              <>
                <Divider orientation="left">测试Payload</Divider>
                <Card size="small">
                  <Text copyable style={{ fontFamily: 'monospace', fontSize: 12 }}>
                    {detailModal.data.payload}
                  </Text>
                </Card>
              </>
            )}

            {detailModal.data.request && (
              <>
                <Divider orientation="left">HTTP请求</Divider>
                <Card size="small">
                  <pre style={{ fontFamily: 'monospace', fontSize: 11, overflow: 'auto', maxHeight: 200 }}>
                    {detailModal.data.request}
                  </pre>
                </Card>
              </>
            )}
          </div>
        )}
      </Modal>
    </div>
  )
}

export default VulnList
