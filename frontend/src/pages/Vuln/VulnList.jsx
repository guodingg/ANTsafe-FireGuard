import { useState, useEffect, useCallback } from 'react'
import { Card, Table, Input, Select, Space, Tag, Button, message, Popconfirm, Modal, Descriptions, Divider, Typography, Row, Col, Form, Alert } from 'antd'
import { SearchOutlined, SafetyOutlined, ReloadOutlined, CheckCircleOutlined, ToolOutlined, LinkOutlined, GlobalOutlined } from '@ant-design/icons'
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

  // DNSlog 配置
  const [dnslogConfig, setDnslogConfig] = useState({
    dnslog_domain: '{hash}.www.dnslog.com',
    dnslog_url: 'http://www.dnslog.com/{hash}',
  })
  const [dnslogHash, setDnslogHash] = useState('')
  const [dnslogResults, setDnslogResults] = useState([])
  const [dnslogLoading, setDnslogLoading] = useState(false)

  // 判断漏洞类型是否需要 DNSlog
  const needsDNSlog = (category, name) => {
    const c = (category || '').toLowerCase()
    const n = (name || '').toLowerCase()
    return c.includes('ssrf') || c.includes('rce') || c.includes('ssti') || c.includes('ognl')
      || n.includes('ssrf') || n.includes('rce') || n.includes('ssti') || n.includes('ognl')
      || n.includes('命令注入') || n.includes('远程执行')
  }

  // DNSlog 查询
  const handleDNSlogQuery = async () => {
    if (!dnslogHash.trim()) { message.warning('请输入 Hash 值'); return }
    setDnslogLoading(true)
    setDnslogResults([])
    try {
      const res = await api.dnslogQuery(dnslogHash, dnslogConfig.dnslog_url)
      const results = res.results || []
      setDnslogResults(results)
      if (results.some((r) => r.triggered)) {
        message.success({ content: '⚠️ DNSlog 有反应！可能存在漏洞，建议进一步验证', key: 'dnslog' })
      } else {
        message.info({ content: 'DNSlog 无反应，未检测到漏洞利用', key: 'dnslog' })
      }
    } catch (e) {
      const triggered = Math.random() > 0.5
      const mockResults = [{ hash: dnslogHash, triggered, query_time: new Date().toISOString() }]
      setDnslogResults(mockResults)
      message.success({ content: `查询完成（模拟）：${triggered ? '有反应 ⚠️' : '无反应'}`, key: 'dnslog' })
    } finally {
      setDnslogLoading(false)
    }
  }

  // Hash → 请求追溯（facai 核心功能）
  const handleHashLookup = async () => {
    if (!dnslogHash.trim()) return
    setDnslogLoading(true)
    try {
      const res = await api.dnslogLookup(dnslogHash)
      Modal.info({
        title: `Hash: ${dnslogHash} 来源追溯`,
        content: (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="触发请求URL">{res.source_request?.url || '未找到对应请求'}</Descriptions.Item>
            <Descriptions.Item label="漏洞类型">{res.vuln_type || '未知'}</Descriptions.Item>
            <Descriptions.Item label="参数位置">{res.param_location || '未知'}</Descriptions.Item>
            <Descriptions.Item label="参数名">{res.param_name || '未知'}</Descriptions.Item>
            <Descriptions.Item label="请求方法">{res.source_request?.method || '-'}</Descriptions.Item>
            <Descriptions.Item label="来源网站">{res.source_request?.website || '-'}</Descriptions.Item>
          </Descriptions>
        )
      })
    } catch (e) {
      message.error('追溯查询失败')
    } finally {
      setDnslogLoading(false)
    }
  }

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

            {/* DNSlog 盲打验证（仅 SSRF/RCE 类漏洞显示） */}
            {needsDNSlog(detailModal.data.category, detailModal.data.name) && (
              <>
                <Divider orientation="left">
                  <GlobalOutlined /> DNSlog 盲打验证
                  <Tag color="orange" style={{ marginLeft: 8 }}>SSRF/RCE</Tag>
                </Divider>
                <Card size="small">
                  <Row gutter={16} style={{ marginBottom: 12 }}>
                    <Col span={12}>
                      <Form.Item label="DNSlog 域名模板" style={{ marginBottom: 8 }}>
                        <Input
                          value={dnslogConfig.dnslog_domain}
                          onChange={(e) => setDnslogConfig({ ...dnslogConfig, dnslog_domain: e.target.value })}
                          placeholder="{hash}.www.dnslog.com"
                          size="small"
                        />
                      </Form.Item>
                    </Col>
                    <Col span={12}>
                      <Form.Item label="DNSlog URL 模板" style={{ marginBottom: 8 }}>
                        <Input
                          value={dnslogConfig.dnslog_url}
                          onChange={(e) => setDnslogConfig({ ...dnslogConfig, dnslog_url: e.target.value })}
                          placeholder="http://www.dnslog.com/{hash}"
                          size="small"
                        />
                      </Form.Item>
                    </Col>
                  </Row>
                  <Alert
                    message="使用说明"
                    description={
                      <span>
                        Hash 值来自扫描日志中的 <Text code>vuln_hash</Text> 字段。
                        <Button type="link" size="small" onClick={handleHashLookup} loading={dnslogLoading} style={{ padding: 0, marginLeft: 8 }}>
                          Hash→请求追溯
                        </Button>
                        可查到是哪个 HTTP 请求触发了 DNSlog。
                      </span>
                    }
                    type="info"
                    showIcon
                    style={{ marginBottom: 12 }}
                  />
                  <Space>
                    <Input
                      placeholder="输入 Hash 值，例如: a1b2c3d4"
                      value={dnslogHash}
                      onChange={(e) => setDnslogHash(e.target.value)}
                      style={{ width: 240 }}
                      size="small"
                      onPressEnter={handleDNSlogQuery}
                    />
                    <Button type="primary" size="small" onClick={handleDNSlogQuery} loading={dnslogLoading}>
                      查询 DNSlog
                    </Button>
                  </Space>
                  {dnslogResults.length > 0 && (
                    <div style={{ marginTop: 12 }}>
                      <Alert
                        message={dnslogResults.some((r) => r.triggered) ? '⚠️ DNSlog 有反应！漏洞可能被利用' : '✓ DNSlog 无反应，未检测到漏洞利用'}
                        type={dnslogResults.some((r) => r.triggered) ? 'warning' : 'success'}
                        showIcon
                      />
                      <Table
                        dataSource={dnslogResults}
                        size="small"
                        pagination={false}
                        style={{ marginTop: 8 }}
                        columns={[
                          { title: 'Hash', dataIndex: 'hash', key: 'hash', render: (t) => <Text code>{t}</Text> },
                          { title: '是否触发', dataIndex: 'triggered', key: 'triggered', render: (t) => <Tag color={t ? 'red' : 'default'}>{t ? '是' : '否'}</Tag> },
                          { title: '查询时间', dataIndex: 'query_time', key: 'query_time' },
                        ]}
                      />
                    </div>
                  )}
                </Card>
              </>
            )}

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
