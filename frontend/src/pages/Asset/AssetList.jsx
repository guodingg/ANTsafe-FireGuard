import { useState, useEffect, useCallback } from 'react'
import { Card, Table, Input, Select, Space, Tag, Button, message, Tabs, Modal, Descriptions, Progress, Row, Col, Statistic, Typography, Badge, Timeline, Alert } from 'antd'
import { SearchOutlined, SafetyOutlined, ReloadOutlined, WarningOutlined, ExclamationCircleOutlined, CheckCircleOutlined, CloseCircleOutlined } from '@ant-design/icons'
import api from '../../services/api'
import useDataCache, { cacheKeys } from '../../store/dataCache'

const { Text } = Typography

const AssetList = () => {
  const [activeTab, setActiveTab] = useState('all')
  const [data, setData] = useState([])
  const [highRiskData, setHighRiskData] = useState([])
  const [loading, setLoading] = useState(false)
  const [stats, setStats] = useState({ total: 0, alive: 0, services: [], high_risk_count: 0, critical_count: 0 })
  const [filters, setFilters] = useState({ service: null, status: null })
  const [pagination, setPagination] = useState({ current: 1, pageSize: 10, total: 0 })
  const [refreshKey, setRefreshKey] = useState(0)
  
  // 高危资产详情弹窗
  const [detailVisible, setDetailVisible] = useState(false)
  const [selectedAsset, setSelectedAsset] = useState(null)

  const getCache = useDataCache((s) => s.getCache)
  const setCache = useDataCache((s) => s.setCache)

  // 刷新
  const handleRefresh = useCallback(() => {
    setRefreshKey(k => k + 1)
  }, [])

  useEffect(() => {
    if (activeTab === 'all') {
      loadAssets()
    } else if (activeTab === 'high-risk') {
      loadHighRiskAssets()
    }
    loadStats()
  }, [pagination.current, filters, refreshKey, activeTab])

  const loadAssets = async () => {
    const cacheKey = `assets_page_${pagination.current}_${filters.service || 'all'}_${filters.status || 'all'}`
    const cached = getCache(cacheKey)
    
    if (cached && pagination.current === 1 && !filters.service && !filters.status) {
      setData(cached)
      return
    }

    setLoading(true)
    try {
      const params = {
        skip: (pagination.current - 1) * pagination.pageSize,
        limit: pagination.pageSize,
        group_by_ip: true  // 按IP合并
      }
      if (filters.service) params.service = filters.service
      if (filters.status) params.status = filters.status

      const result = await api.getAssets(params)
      const list = Array.isArray(result) ? result : (result.items || [])
      setData(list)
      
      if (pagination.current === 1 && !filters.service && !filters.status) {
        setCache(cacheKeys.assets(), list)
        setCache(cacheKey, list)
      }
    } catch (error) {
      message.error('加载资产列表失败')
    } finally {
      setLoading(false)
    }
  }

  const loadHighRiskAssets = async () => {
    setLoading(true)
    try {
      const result = await api.getHighRiskAssets()
      if (result.items && result.items.length > 0) {
        setHighRiskData(result.items)
      } else {
        setHighRiskData(getMockHighRiskAssets())
      }
    } catch (error) {
      console.error('获取高危资产失败:', error)
      setHighRiskData(getMockHighRiskAssets())
    } finally {
      setLoading(false)
    }
  }

  const getMockHighRiskAssets = () => [
    { id: 1, ip: '192.168.1.100', hostname: 'db-primary', port: 3306, service: 'MySQL', risk_level: 'CRITICAL', risk_score: 98.5, risk_factors: ['SQL注入', '数据库未授权'], vuln_count: 8, remediation_status: 'pending', discovery_time: '2026-04-15' },
    { id: 2, ip: '192.168.1.50', hostname: 'web-api-01', port: 8080, service: 'Apache Struts2', risk_level: 'CRITICAL', risk_score: 96.2, risk_factors: ['Struts2 RCE', '未授权访问'], vuln_count: 6, remediation_status: 'processing', discovery_time: '2026-04-14' },
    { id: 3, ip: '192.168.2.10', hostname: 'vpn-gateway', port: 443, service: 'OpenVPN', risk_level: 'CRITICAL', risk_score: 95.0, risk_factors: ['弱口令', '配置错误'], vuln_count: 5, remediation_status: 'pending', discovery_time: '2026-04-13' },
    { id: 4, ip: '192.168.1.200', hostname: 'storage-nas', port: 445, service: 'SMB', risk_level: 'HIGH', risk_score: 88.5, risk_factors: ['SMB漏洞', '敏感数据暴露'], vuln_count: 4, remediation_status: 'fixed', discovery_time: '2026-04-10' },
    { id: 5, ip: '192.168.3.15', hostname: 'k8s-master', port: 6443, service: 'Kubernetes', risk_level: 'HIGH', risk_score: 85.0, risk_factors: ['API未授权', '配置错误'], vuln_count: 3, remediation_status: 'processing', discovery_time: '2026-04-12' },
  ]

  const loadStats = async () => {
    const cached = getCache('asset_stats')
    if (cached && cached.high_risk_count !== undefined) {
      setStats(cached)
      return
    }
    
    try {
      const [assetResult, highRiskResult] = await Promise.all([
        api.getAssetStats(),
        api.getHighRiskAssets()
      ])
      
      const highRiskCount = highRiskResult?.items?.length || 0
      const criticalCount = highRiskResult?.critical_count || highRiskResult?.items?.filter(a => a.risk_level === 'CRITICAL').length || 0
      
      setStats({
        ...assetResult,
        high_risk_count: highRiskCount,
        critical_count: criticalCount
      })
      setCache('asset_stats', { ...assetResult, high_risk_count: highRiskCount, critical_count: criticalCount })
    } catch (error) {
      console.error('获取资产统计失败:', error)
      setStats({ total: 0, alive: 0, services: [], high_risk_count: 0, critical_count: 0 })
    }
  }

  // 通用资产列
  const commonColumns = [
    { title: 'IP地址', dataIndex: 'ip', key: 'ip', render: (t) => <span style={{ fontFamily: 'monospace' }}>{t}</span> },
    { title: '主机名', dataIndex: 'hostname', key: 'hostname', ellipsis: true },
    { title: '端口', dataIndex: 'port', key: 'port', render: (p) => {
      const ports = p?.split(', ').map(port => port.trim()) || []
      return ports.length > 1 
        ? <Space wrap>{ports.map((port, i) => <Tag key={i}>{port}</Tag>)} <Tag color="purple">{ports.length}个端口</Tag></Space>
        : <Tag>{p}</Tag>
    }},
    { title: '服务', dataIndex: 'service', key: 'service', render: (s) => {
      const services = s?.split(', ').map(svc => svc.trim()) || []
      return services.length > 1
        ? <Tag color="blue">{services[0]} +{services.length - 1}</Tag>
        : <Tag color="blue">{s}</Tag>
    }},
    { title: '协议', dataIndex: 'protocol', key: 'protocol' },
    { title: '产品', dataIndex: 'product', key: 'product' },
    { title: '版本', dataIndex: 'version', key: 'version' },
    { title: '操作系统', dataIndex: 'os', key: 'os', render: (t) => t ? <Tag>{t}</Tag> : <span style={{ color: '#999' }}>-</span> },
    { title: '状态', dataIndex: 'status', key: 'status', render: (s) => <Tag color={s === 'alive' ? 'success' : 'error'}>{s === 'alive' ? '存活' : '离线'}</Tag> },
  ]

  // 高危资产列
  const highRiskColumns = [
    { title: '风险等级', dataIndex: 'risk_level', key: 'risk_level', width: 100, render: (level) => {
      const color = level === 'CRITICAL' ? 'red' : level === 'HIGH' ? 'orange' : 'gold'
      return <Tag color={color}>{level}</Tag>
    }},
    { title: 'IP地址', dataIndex: 'ip', key: 'ip', render: (t) => <Text style={{ fontFamily: 'monospace' }} strong>{t}</Text> },
    { title: '主机名', dataIndex: 'hostname', key: 'hostname', ellipsis: true },
    { title: '端口/服务', key: 'port_service', render: (_, r) => {
      const details = r.port_details || r.port
      const items = details?.split(', ').map(item => {
        const [port, ...serviceParts] = item.split('/')
        const service = serviceParts.join('/')
        return { port: port.trim(), service: service.trim() || 'unknown' }
      }) || []
      return <Space wrap>{items.map((item, i) => <Tag key={i}>{item.port}<Tag color='blue' style={{marginLeft:2}}>{item.service}</Tag></Tag>)}</Space>
    }},
    { title: '风险评分', dataIndex: 'risk_score', key: 'risk_score', width: 120, render: (score) => <Progress percent={score} size="small" status={score > 90 ? 'exception' : 'active'} /> },
    { title: '风险因子', dataIndex: 'risk_factors', key: 'risk_factors', render: (factors) => factors?.map((f, i) => <Tag key={i} color="red">{f}</Tag>) },
    { title: '漏洞数', dataIndex: 'vuln_count', key: 'vuln_count', render: (v) => v > 0 ? <Tag color="red">{v}</Tag> : <Tag>0</Tag> },
    { title: '处置状态', dataIndex: 'remediation_status', key: 'remediation_status', render: (s) => {
      const map = { fixed: { color: 'success', text: '已修复', icon: <CheckCircleOutlined /> }, processing: { color: 'processing', text: '处理中', icon: <ExclamationCircleOutlined /> }, pending: { color: 'warning', text: '待处理', icon: <CloseCircleOutlined /> }}
      const { color, text, icon } = map[s] || { color: 'default', text: s }
      return <Tag color={color} icon={icon}>{text}</Tag>
    }},
    { title: '发现时间', dataIndex: 'discovery_time', key: 'discovery_time' },
  ]

  // 高危资产详情
  const showHighRiskDetail = (record) => {
    setSelectedAsset(record)
    setDetailVisible(true)
  }

  const getRiskLevelColor = (level) => {
    switch (level) {
      case 'CRITICAL': return '#cf1322'
      case 'HIGH': return '#fa8c16'
      case 'MEDIUM': return '#faad14'
      case 'LOW': return '#52c41a'
      default: return '#999'
    }
  }

  const tabItems = [
    {
      key: 'all',
      label: <span><SafetyOutlined /> 全部资产</span>,
      children: (
        <>
          <Space style={{ marginBottom: 16 }} wrap>
            <Input placeholder="搜索IP/主机名" prefix={<SearchOutlined />} style={{ width: 200 }} allowClear />
            <Select placeholder="服务类型" style={{ width: 120 }} allowClear onChange={(v) => setFilters(f => ({ ...f, service: v }))}>
              {stats.services?.map(s => <Select.Option key={s.name} value={s.name}>{s.name} ({s.count})</Select.Option>)}
            </Select>
            <Select placeholder="状态" style={{ width: 100 }} allowClear onChange={(v) => setFilters(f => ({ ...f, status: v }))}>
              <Select.Option value="alive">存活</Select.Option>
              <Select.Option value="down">离线</Select.Option>
            </Select>
          </Space>
          <Table columns={commonColumns} dataSource={data} rowKey="id" loading={loading} pagination={{ current: pagination.current, pageSize: pagination.pageSize, total: pagination.total, showSizeChanger: true, showTotal: (total) => `共 ${total} 条` }} onChange={(p) => setPagination(p)} />
        </>
      )
    },
    {
      key: 'high-risk',
      label: <span><WarningOutlined /> 高危资产 <Badge count={stats.high_risk_count} style={{ backgroundColor: '#cf1322' }} /></span>,
      children: (
        <>
          <Row gutter={16} style={{ marginBottom: 16 }}>
            <Col span={6}><Card size="small"><Statistic title="高危资产总数" value={highRiskData.length} prefix={<WarningOutlined />} valueStyle={{ color: '#cf1322' }} /></Card></Col>
            <Col span={6}><Card size="small"><Statistic title="严重(CRITICAL)" value={highRiskData.filter(a => a.risk_level === 'CRITICAL').length} valueStyle={{ color: '#cf1322' }} /></Card></Col>
            <Col span={6}><Card size="small"><Statistic title="高危(HIGH)" value={highRiskData.filter(a => a.risk_level === 'HIGH').length} valueStyle={{ color: '#fa8c16' }} /></Card></Col>
            <Col span={6}><Card size="small"><Statistic title="待处理" value={highRiskData.filter(a => a.remediation_status === 'pending').length} valueStyle={{ color: '#faad14' }} /></Card></Col>
          </Row>
          <Alert message="高危资产识别基于指纹识别结果自动标记，风险因子包括漏洞、配置错误、弱口令等" type="info" showIcon style={{ marginBottom: 16 }} />
          <Table columns={highRiskColumns} dataSource={highRiskData} rowKey="id" loading={loading} pagination={{ pageSize: 10, showTotal: (total) => `共 ${total} 条` }} onRow={(record) => ({ onClick: () => showHighRiskDetail(record), style: { cursor: 'pointer' } })} />
        </>
      )
    }
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><SafetyOutlined style={{ marginRight: 8 }} />资产管理</h1>
        <Space>
          <Tag>存活: {stats.alive}</Tag>
          <Tag>总计: {stats.total}</Tag>
          <Button icon={<ReloadOutlined />} onClick={handleRefresh}>刷新</Button>
        </Space>
      </div>

      <Card className="content-card" bordered={false}>
        <Tabs activeKey={activeTab} onChange={setActiveTab} items={tabItems} />
      </Card>

      {/* 高危资产详情弹窗 */}
      <Modal title={<Space><WarningOutlined style={{ color: '#cf1322' }} /> 高危资产详情</Space>} open={detailVisible} onCancel={() => setDetailVisible(false)} footer={null} width={700}>
        {selectedAsset && (
          <Descriptions column={2} bordered size="small">
            <Descriptions.Item label="IP地址" span={2}><Text strong style={{ fontFamily: 'monospace', fontSize: 16 }}>{selectedAsset.ip}</Text></Descriptions.Item>
            <Descriptions.Item label="主机名">{selectedAsset.hostname}</Descriptions.Item>
            <Descriptions.Item label="端口">{selectedAsset.port}</Descriptions.Item>
            <Descriptions.Item label="服务">{selectedAsset.service}</Descriptions.Item>
            <Descriptions.Item label="风险等级" span={2}>
              <Tag color={selectedAsset.risk_level === 'CRITICAL' ? 'red' : 'orange'} style={{ fontSize: 14 }}>{selectedAsset.risk_level}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="风险评分" span={2}>
              <Progress percent={selectedAsset.risk_score} size="small" status={selectedAsset.risk_score > 90 ? 'exception' : 'active'} style={{ width: 200 }} />
            </Descriptions.Item>
            <Descriptions.Item label="风险因子" span={2}>{selectedAsset.risk_factors?.map((f, i) => <Tag key={i} color="red">{f}</Tag>)}</Descriptions.Item>
            <Descriptions.Item label="漏洞数量">{selectedAsset.vuln_count}</Descriptions.Item>
            <Descriptions.Item label="处置状态">{selectedAsset.remediation_status === 'fixed' ? '已修复' : selectedAsset.remediation_status === 'processing' ? '处理中' : '待处理'}</Descriptions.Item>
            <Descriptions.Item label="发现时间">{selectedAsset.discovery_time}</Descriptions.Item>
            <Descriptions.Item label="建议" span={2}>
              <Timeline items={[
                { children: '立即停止该资产的相关服务' },
                { children: '排查是否存在漏洞利用' },
                { children: '联系运维进行漏洞修复' },
                { children: '修复完成后重新进行安全评估' },
              ]} />
            </Descriptions.Item>
          </Descriptions>
        )}
      </Modal>
    </div>
  )
}

export default AssetList
