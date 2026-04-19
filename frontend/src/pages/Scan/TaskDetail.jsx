import { useState, useEffect } from 'react'
import { Card, Descriptions, Tag, Button, Space, Progress, Table, message, Spin, Collapse, Modal } from 'antd'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeftOutlined, PlayCircleOutlined, FileTextOutlined, EyeOutlined, SafetyOutlined, ExclamationCircleOutlined } from '@ant-design/icons'
import api from '../../services/api'

const { Panel } = Collapse

const TaskDetail = () => {
  const { id } = useParams()
  const navigate = useNavigate()
  const [task, setTask] = useState(null)
  const [assets, setAssets] = useState([])
  const [vulns, setVulns] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedVuln, setSelectedVuln] = useState(null)
  const [vulnModalVisible, setVulnModalVisible] = useState(false)

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

  const showVulnDetail = (vuln) => {
    setSelectedVuln(vuln)
    setVulnModalVisible(true)
  }

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'red',
      high: 'orange',
      medium: 'gold',
      low: 'green',
      info: 'blue'
    }
    return colors[severity] || 'default'
  }

  const getSeverityText = (severity) => {
    const texts = {
      critical: '严重',
      high: '高危',
      medium: '中危',
      low: '低危',
      info: '信息'
    }
    return texts[severity] || severity
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
    { title: 'IP地址', dataIndex: 'ip', key: 'ip', render: (ip) => <Tag color="blue">{ip}</Tag> },
    { title: '端口', dataIndex: 'port', key: 'port', render: (p) => <Tag>{p}</Tag> },
    { title: '协议', dataIndex: 'protocol', key: 'protocol' },
    { title: '服务', dataIndex: 'service', key: 'service' },
    { title: '产品', dataIndex: 'product', key: 'product', render: (p) => p || '-' },
    { title: '版本', dataIndex: 'version', key: 'version', render: (v) => v || '-' },
    { title: '状态', dataIndex: 'status', key: 'status', render: (s) => <Tag color={s === 'alive' ? 'success' : 'error'}>{s === 'alive' ? '存活' : '离线'}</Tag> }
  ]

  const vulnColumns = [
    { title: '漏洞名称', dataIndex: 'name', key: 'name', render: (t, record) => (
      <a onClick={() => showVulnDetail(record)} style={{ fontWeight: 500 }}>{t}</a>
    )},
    { title: 'CVE', dataIndex: 'cve', key: 'cve', render: (c) => c ? <Tag color="red">{c}</Tag> : '-' },
    { title: '严重性', dataIndex: 'severity', key: 'severity', render: (s) => (
      <Tag color={getSeverityColor(s)}>{getSeverityText(s)}</Tag>
    )},
    { title: '关联资产', dataIndex: 'asset_id', key: 'asset_id', render: (_, record) => {
      const asset = assets.find(a => a.id === record.asset_id)
      return asset ? <Tag>{asset.ip}:{asset.port}</Tag> : '-'
    }},
    { title: '状态', dataIndex: 'status', key: 'status', render: (s) => {
      const statusMap = {
        unverified: '未验证',
        verified: '已验证',
        false_positive: '误报',
        fixed: '已修复'
      }
      return <Tag>{statusMap[s] || s}</Tag>
    }},
    { title: '操作', key: 'action', render: (_, record) => (
      <Button type="link" icon={<EyeOutlined />} onClick={() => showVulnDetail(record)}>详情</Button>
    )}
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
          <Descriptions.Item label="扫描类型">
            {task.scan_type === 'asset' ? '资产发现' : 
             task.scan_type === 'vuln' ? '漏洞扫描' : 
             task.scan_type === 'full' ? '全面扫描' : 
             task.scan_type === 'nuclei' ? 'Nuclei扫描' : task.scan_type}
          </Descriptions.Item>
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

      <Card className="content-card" bordered={false} title={`资产列表 (${assets.length})`}>
        <Table columns={assetColumns} dataSource={assets} rowKey="id" pagination={{ pageSize: 10 }} size="small" />
      </Card>

      <Card className="content-card" bordered={false} title={`漏洞列表 (${vulns.length})`}>
        <Table columns={vulnColumns} dataSource={vulns} rowKey="id" pagination={{ pageSize: 10 }} size="small" />
      </Card>

      {/* 漏洞详情弹窗 */}
      <Modal
        title={
          <Space>
            <SafetyOutlined style={{ color: selectedVuln ? getSeverityColor(selectedVuln.severity) : '#666' }} />
            {selectedVuln?.name}
          </Space>
        }
        open={vulnModalVisible}
        onCancel={() => setVulnModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setVulnModalVisible(false)}>关闭</Button>
        ]}
        width={700}
      >
        {selectedVuln && (
          <div>
            <Descriptions column={2} bordered size="small">
              <Descriptions.Item label="CVE">
                {selectedVuln.cve ? <Tag color="red">{selectedVuln.cve}</Tag> : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="严重性">
                <Tag color={getSeverityColor(selectedVuln.severity)}>{getSeverityText(selectedVuln.severity)}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="关联资产">
                {(() => {
                  const asset = assets.find(a => a.id === selectedVuln.asset_id)
                  return asset ? <Tag>{asset.ip}:{asset.port}</Tag> : '-'
                })()}
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                {selectedVuln.status === 'unverified' ? '未验证' :
                 selectedVuln.status === 'verified' ? '已验证' :
                 selectedVuln.status === 'false_positive' ? '误报' :
                 selectedVuln.status === 'fixed' ? '已修复' : selectedVuln.status}
              </Descriptions.Item>
            </Descriptions>

            <Collapse defaultActiveKey={['description']} style={{ marginTop: 16 }}>
              <Panel header="漏洞描述" key="description">
                <div style={{ whiteSpace: 'pre-wrap', fontSize: 14, lineHeight: 1.8 }}>
                  {selectedVuln.description || '暂无描述'}
                </div>
              </Panel>
              
              {selectedVuln.payload && (
                <Panel header="漏洞Payload" key="payload">
                  <div style={{ background: '#f5f5f5', padding: 12, borderRadius: 4, fontFamily: 'monospace', fontSize: 13 }}>
                    <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{selectedVuln.payload}</pre>
                  </div>
                </Panel>
              )}

              {selectedVuln.remediation && (
                <Panel header="修复建议" key="remediation">
                  <div style={{ whiteSpace: 'pre-wrap', fontSize: 14, lineHeight: 1.8, color: '#52c41a' }}>
                    {selectedVuln.remediation}
                  </div>
                </Panel>
              )}

              {selectedVuln.impact && (
                <Panel header="安全影响" key="impact">
                  <div style={{ whiteSpace: 'pre-wrap', fontSize: 14, lineHeight: 1.8 }}>
                    <Space>
                      <ExclamationCircleOutlined style={{ color: getSeverityColor(selectedVuln.severity) }} />
                      {selectedVuln.impact}
                    </Space>
                  </div>
                </Panel>
              )}
            </Collapse>
          </div>
        )}
      </Modal>
    </div>
  )
}

export default TaskDetail
