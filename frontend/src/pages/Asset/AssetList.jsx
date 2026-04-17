import { Card, Table, Input, Select, Space, Tag, Button } from 'antd'
import { SearchOutlined, SafetyOutlined } from '@ant-design/icons'
import { useState } from 'react'

const AssetList = () => {
  const [data] = useState([
    { id: 1, ip: '192.168.1.1', hostname: 'router.example.com', port: 80, service: 'HTTP', product: 'Apache', version: '2.4.41', os: 'Linux', status: 'alive', vulns: 2 },
    { id: 2, ip: '192.168.1.10', hostname: 'web.example.com', port: 443, service: 'HTTPS', product: 'Nginx', version: '1.18.0', os: 'Ubuntu', status: 'alive', vulns: 0 },
    { id: 3, ip: '192.168.1.20', hostname: 'db.example.com', port: 3306, service: 'MySQL', product: 'MySQL', version: '5.7.30', os: 'Linux', status: 'alive', vulns: 1 },
  ])

  const columns = [
    { title: 'IP地址', dataIndex: 'ip', key: 'ip' },
    { title: '主机名', dataIndex: 'hostname', key: 'hostname' },
    { title: '端口', dataIndex: 'port', key: 'port', render: (p) => <Tag>{p}</Tag> },
    { title: '服务', dataIndex: 'service', key: 'service' },
    { title: '产品', dataIndex: 'product', key: 'product' },
    { title: '版本', dataIndex: 'version', key: 'version' },
    { title: '操作系统', dataIndex: 'os', key: 'os' },
    { title: '状态', dataIndex: 'status', key: 'status', render: (s) => <Tag color={s === 'alive' ? 'success' : 'error'}>{s === 'alive' ? '存活' : '离线'}</Tag> },
    { title: '漏洞', dataIndex: 'vulns', key: 'vulns', render: (v) => v > 0 ? <Tag color="red">{v}</Tag> : <Tag color="green">{v}</Tag> },
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><SafetyOutlined style={{ marginRight: 8 }} />资产管理</h1>
      </div>
      <Card className="content-card" bordered={false}>
        <Space style={{ marginBottom: 16 }} wrap>
          <Input placeholder="搜索IP/主机名" prefix={<SearchOutlined />} style={{ width: 200 }} />
          <Select placeholder="服务类型" style={{ width: 120 }} allowClear>
            <Select.Option value="http">HTTP</Select.Option>
            <Select.Option value="ssh">SSH</Select.Option>
            <Select.Option value="mysql">MySQL</Select.Option>
          </Select>
        </Space>
        <Table columns={columns} dataSource={data} rowKey="id" pagination={{ pageSize: 10 }} />
      </Card>
    </div>
  )
}

export default AssetList
