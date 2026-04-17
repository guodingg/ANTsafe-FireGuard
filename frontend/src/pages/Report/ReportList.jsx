import { Card, Table, Button, Space, Tag, Input } from 'antd'
import { FileTextOutlined, PlusOutlined, DownloadOutlined, DeleteOutlined, SearchOutlined } from '@ant-design/icons'

const ReportList = () => {
  const data = [
    { id: 1, name: '内网资产扫描报告', taskName: '内网资产扫描', type: 'word', size: '2.5MB', createTime: '2024-04-17 10:50', creator: 'admin' },
    { id: 2, name: 'Web漏洞检测报告', taskName: 'Web漏洞检测', type: 'pdf', size: '1.8MB', createTime: '2024-04-17 15:30', creator: 'admin' },
    { id: 3, name: '月度安全评估报告', taskName: '-', type: 'excel', size: '856KB', createTime: '2024-04-15 09:00', creator: 'admin' },
  ]

  const typeColor = { word: 'blue', pdf: 'red', excel: 'green', html: 'orange' }

  const columns = [
    { title: '报告名称', dataIndex: 'name', key: 'name', render: (t) => <span style={{ fontWeight: 500 }}><FileTextOutlined style={{ marginRight: 8 }} />{t}</span> },
    { title: '关联任务', dataIndex: 'taskName', key: 'taskName' },
    { title: '格式', dataIndex: 'type', key: 'type', render: (t) => <Tag color={typeColor[t]}>{t.toUpperCase()}</Tag> },
    { title: '大小', dataIndex: 'size', key: 'size' },
    { title: '创建时间', dataIndex: 'createTime', key: 'createTime' },
    { title: '创建人', dataIndex: 'creator', key: 'creator' },
    {
      title: '操作',
      key: 'action',
      render: () => (
        <Space>
          <Button type="text" size="small" icon={<DownloadOutlined />}>下载</Button>
          <Button type="text" size="small" danger icon={<DeleteOutlined />}>删除</Button>
        </Space>
      )
    }
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><FileTextOutlined style={{ marginRight: 8 }} />报告管理</h1>
        <Button type="primary" icon={<PlusOutlined />}>生成报告</Button>
      </div>
      <Card className="content-card" bordered={false}>
        <Space style={{ marginBottom: 16 }}>
          <Input placeholder="搜索报告名称" prefix={<SearchOutlined />} style={{ width: 200 }} />
        </Space>
        <Table columns={columns} dataSource={data} rowKey="id" pagination={{ pageSize: 10 }} />
      </Card>
    </div>
  )
}

export default ReportList
