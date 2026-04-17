import { Card, Table, Input, Select, Space, Tag, Button } from 'antd'
import { BugOutlined, PlusOutlined, SearchOutlined } from '@ant-design/icons'

const POCList = () => {
  const data = [
    { id: 1, name: 'MySQL弱口令', source: 'Nuclei', severity: 'medium', protocol: 'tcp', cve: '-', useCount: 25, aiGen: false },
    { id: 2, name: 'Apache Shiro反序列化', source: 'Goby', severity: 'critical', protocol: 'http', cve: 'CVE-2020-1957', useCount: 12, aiGen: false },
    { id: 3, name: 'ThinkPHP RCE', source: 'Xray', severity: 'critical', protocol: 'http', cve: 'CVE-2019-9082', useCount: 18, aiGen: false },
    { id: 4, name: '自定义POC-1', source: '自定义', severity: 'high', protocol: 'tcp', cve: '-', useCount: 3, aiGen: true },
  ]

  const severityColor = { critical: 'red', high: 'orange', medium: 'gold', low: 'green' }
  const sourceColor = { Nuclei: 'blue', Goby: 'purple', Xray: 'cyan', '自定义': 'green' }

  const columns = [
    { title: 'POC名称', dataIndex: 'name', key: 'name', render: (t, r) => <span><span style={{ fontWeight: 500 }}>{t}</span> {r.aiGen && <Tag color="purple" style={{ marginLeft: 8 }}>AI</Tag>}</span> },
    { title: '来源', dataIndex: 'source', key: 'source', render: (s) => <Tag color={sourceColor[s]}>{s}</Tag> },
    { title: '严重性', dataIndex: 'severity', key: 'severity', render: (s) => <Tag color={severityColor[s]}>{s}</Tag> },
    { title: '协议', dataIndex: 'protocol', key: 'protocol' },
    { title: 'CVE', dataIndex: 'cve', key: 'cve' },
    { title: '使用次数', dataIndex: 'useCount', key: 'useCount' },
    { title: '操作', key: 'action', render: () => <Button type="link" size="small">测试</Button> }
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><BugOutlined style={{ marginRight: 8 }} />POC管理</h1>
        <Space>
          <Button icon={<PlusOutlined />}>导入POC</Button>
          <Button type="primary" icon={<PlusOutlined />}>AI生成</Button>
        </Space>
      </div>
      <Card className="content-card" bordered={false}>
        <Space style={{ marginBottom: 16 }} wrap>
          <Input placeholder="搜索POC名称" prefix={<SearchOutlined />} style={{ width: 200 }} />
          <Select placeholder="来源" style={{ width: 120 }} allowClear>
            <Select.Option value="nuclei">Nuclei</Select.Option>
            <Select.Option value="goby">Goby</Select.Option>
            <Select.Option value="xray">Xray</Select.Option>
          </Select>
        </Space>
        <Table columns={columns} dataSource={data} rowKey="id" pagination={{ pageSize: 10 }} />
      </Card>
    </div>
  )
}

export default POCList
