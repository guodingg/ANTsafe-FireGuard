import { Card, Table, Input, Select, Space, Tag, Button } from 'antd'
import { SearchOutlined, SafetyOutlined } from '@ant-design/icons'
import { useState } from 'react'

const VulnList = () => {
  const [data] = useState([
    { id: 1, name: 'SQL注入', cve: 'CVE-2024-1234', severity: 'critical', target: '192.168.1.20:3306', product: 'MySQL 5.7.30', status: 'verified', time: '2024-04-17' },
    { id: 2, name: 'XSS跨站脚本', cve: 'CVE-2024-5678', severity: 'high', target: '192.168.1.1:80', product: 'Apache 2.4.41', status: 'verified', time: '2024-04-17' },
    { id: 3, name: '弱口令', cve: '-', severity: 'medium', target: '192.168.1.10:22', product: 'SSH', status: 'unverified', time: '2024-04-16' },
    { id: 4, name: '信息泄露', cve: '-', severity: 'low', target: '192.168.1.1:443', product: 'Nginx', status: 'fixed', time: '2024-04-15' },
  ])

  const severityColor = { critical: 'red', high: 'orange', medium: 'gold', low: 'green', info: 'blue' }
  const severityText = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
  const statusColor = { verified: 'success', unverified: 'warning', fixed: 'processing', false_positive: 'default' }
  const statusText = { verified: '已验证', unverified: '待验证', fixed: '已修复', false_positive: '误报' }

  const columns = [
    { title: '漏洞名称', dataIndex: 'name', key: 'name', render: (t) => <span style={{ fontWeight: 500 }}>{t}</span> },
    { title: 'CVE编号', dataIndex: 'cve', key: 'cve' },
    { title: '严重性', dataIndex: 'severity', key: 'severity', render: (s) => <Tag color={severityColor[s]}>{severityText[s]}</Tag> },
    { title: '目标', dataIndex: 'target', key: 'target' },
    { title: '影响产品', dataIndex: 'product', key: 'product' },
    { title: '状态', dataIndex: 'status', key: 'status', render: (s) => <Tag color={statusColor[s]}>{statusText[s]}</Tag> },
    { title: '发现时间', dataIndex: 'time', key: 'time' },
    { title: '操作', key: 'action', render: () => <Button type="link" size="small">详情</Button> }
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><SafetyOutlined style={{ marginRight: 8 }} />漏洞管理</h1>
      </div>
      <Card className="content-card" bordered={false}>
        <Space style={{ marginBottom: 16 }} wrap>
          <Input placeholder="搜索漏洞名称/CVE" prefix={<SearchOutlined />} style={{ width: 200 }} />
          <Select placeholder="严重性" style={{ width: 100 }} allowClear>
            <Select.Option value="critical">严重</Select.Option>
            <Select.Option value="high">高危</Select.Option>
            <Select.Option value="medium">中危</Select.Option>
            <Select.Option value="low">低危</Select.Option>
          </Select>
          <Select placeholder="状态" style={{ width: 100 }} allowClear>
            <Select.Option value="verified">已验证</Select.Option>
            <Select.Option value="unverified">待验证</Select.Option>
            <Select.Option value="fixed">已修复</Select.Option>
          </Select>
        </Space>
        <Table columns={columns} dataSource={data} rowKey="id" pagination={{ pageSize: 10 }} />
      </Card>
    </div>
  )
}

export default VulnList
