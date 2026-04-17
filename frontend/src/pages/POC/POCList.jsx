import { useState, useEffect } from 'react'
import { Card, Table, Input, Select, Space, Tag, Button, message, Modal, Form } from 'antd'
import { BugOutlined, PlusOutlined, SearchOutlined, ReloadOutlined, RocketOutlined } from '@ant-design/icons'
import api from '../../services/api'

const POCList = () => {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(false)
  const [filters, setFilters] = useState({ source: null, severity: null })
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [form] = Form.useForm()

  useEffect(() => {
    loadPOCs()
  }, [filters])

  const loadPOCs = async () => {
    setLoading(true)
    try {
      const params = {}
      if (filters.source) params.source = filters.source
      if (filters.severity) params.severity = filters.severity

      const result = await api.getPOCs(params)
      setData(Array.isArray(result) ? result : [])
    } catch (error) {
      message.error('加载POC列表失败')
    } finally {
      setLoading(false)
    }
  }

  const handleGeneratePOC = () => {
    setIsModalOpen(true)
  }

  const handleTestPOC = async (poc) => {
    message.info('POC测试功能开发中')
  }

  const severityColor = { critical: 'red', high: 'orange', medium: 'gold', low: 'green' }
  const sourceColor = { Nuclei: 'blue', Goby: 'purple', Xray: 'cyan', custom: 'green', default: 'default' }

  const columns = [
    { 
      title: 'POC名称', 
      dataIndex: 'name', 
      key: 'name', 
      render: (t, r) => (
        <span>
          <span style={{ fontWeight: 500 }}>{t}</span>
          {r.ai_generated && <Tag color="purple" style={{ marginLeft: 8 }}>AI</Tag>}
        </span>
      )
    },
    { title: '来源', dataIndex: 'source', key: 'source', render: (s) => <Tag color={sourceColor[s] || 'default'}>{s}</Tag> },
    { title: 'CVE', dataIndex: 'cve', key: 'cve', render: (t) => t || '-' },
    { title: '分类', dataIndex: 'category', key: 'category', render: (t) => t || '-' },
    { title: '协议', dataIndex: 'protocol', key: 'protocol' },
    { title: '使用次数', dataIndex: 'use_count', key: 'use_count' },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Button type="text" size="small" icon={<RocketOutlined />} onClick={() => handleTestPOC(record)}>测试</Button>
      )
    }
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><BugOutlined style={{ marginRight: 8 }} />POC管理</h1>
        <Space>
          <Button icon={<PlusOutlined />} onClick={() => message.info('导入功能开发中')}>导入POC</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleGeneratePOC}>AI生成</Button>
        </Space>
      </div>

      <Card className="content-card" bordered={false}>
        <Space style={{ marginBottom: 16 }} wrap>
          <Input placeholder="搜索POC名称" prefix={<SearchOutlined />} style={{ width: 200 }} allowClear />
          <Select 
            placeholder="来源" 
            style={{ width: 120 }} 
            allowClear
            onChange={(v) => setFilters(f => ({ ...f, source: v }))}
          >
            <Select.Option value="Nuclei">Nuclei</Select.Option>
            <Select.Option value="Goby">Goby</Select.Option>
            <Select.Option value="Xray">Xray</Select.Option>
            <Select.Option value="custom">自定义</Select.Option>
          </Select>
          <Select 
            placeholder="严重性" 
            style={{ width: 100 }} 
            allowClear
            onChange={(v) => setFilters(f => ({ ...f, severity: v }))}
          >
            <Select.Option value="critical">严重</Select.Option>
            <Select.Option value="high">高危</Select.Option>
          </Select>
          <Button icon={<ReloadOutlined />} onClick={loadPOCs}>刷新</Button>
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
        title="AI生成POC"
        open={isModalOpen}
        onCancel={() => setIsModalOpen(false)}
        footer={null}
      >
        <Form form={form} layout="vertical">
          <Form.Item label="漏洞描述" name="description" rules={[{ required: true, message: '请输入漏洞描述' }]}>
            <Input.TextArea placeholder="描述漏洞信息，如：Apache Struts2 RCE漏洞" rows={4} />
          </Form.Item>
          <Form.Item label="目标" name="target" rules={[{ required: true, message: '请输入目标' }]}>
            <Input placeholder="目标URL或IP地址" />
          </Form.Item>
          <Form.Item>
            <Button type="primary" block onClick={() => message.info('POC生成功能开发中')}>
              生成POC
            </Button>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default POCList
