import { useState, useEffect } from 'react'
import { Card, Table, Input, Select, Space, Tag, Button, message, Modal, Form, Popconfirm, Switch, Row, Col, Statistic, Typography, Alert, Divider, Tooltip } from 'antd'
import { SafetyOutlined, PlusOutlined, DeleteOutlined, ReloadOutlined, WarningOutlined, CheckCircleOutlined, InfoCircleOutlined, FilterOutlined } from '@ant-design/icons'
import api from '../../services/api'

const { Text, Paragraph } = Typography

const AssetFilter = () => {
  const [whitelist, setWhitelist] = useState([])
  const [filterRules, setFilterRules] = useState([])
  const [loading, setLoading] = useState(false)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [form] = Form.useForm()
  const [enabled, setEnabled] = useState(true)

  useEffect(() => {
    loadWhitelist()
    loadFilterRules()
  }, [])

  const loadWhitelist = async () => {
    setLoading(true)
    try {
      const result = await api.getWhitelist()
      setWhitelist(result.items || [])
    } catch (error) {
      console.error('获取白名单失败:', error)
      setWhitelist([])
    } finally {
      setLoading(false)
    }
  }

  const getMockWhitelist = () => [
    { id: 1, type: 'ip', value: '192.168.1.1', reason: '网关设备', created_by: 'admin', created_at: '2026-04-10' },
    { id: 2, type: 'ip', value: '10.0.0.1', reason: 'DNS服务器', created_by: 'admin', created_at: '2026-04-10' },
    { id: 3, type: 'cidr', value: '192.168.100.0/24', reason: '办公网络', created_by: 'admin', created_at: '2026-04-11' },
    { id: 4, type: 'domain', value: '*.example.com', reason: '测试域名', created_by: 'admin', created_at: '2026-04-12' },
    { id: 5, type: 'keyword', value: 'localhost', reason: '本地回环', created_by: 'admin', created_at: '2026-04-13' },
  ]

  const loadFilterRules = async () => {
    try {
      const result = await api.getFilterRules()
      setFilterRules(result.items || [])
    } catch (error) {
      console.error('获取过滤规则失败:', error)
      setFilterRules(getMockFilterRules())
    }
  }

  const getMockFilterRules = () => [
    { id: 1, name: '内网保留地址', pattern: '^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)', type: 'regex', enabled: true },
    { id: 2, name: '本地回环', pattern: '^127\\.', type: 'regex', enabled: true },
    { id: 3, name: '多播地址', pattern: '^(224\\.|239\\.)', type: 'regex', enabled: true },
  ]

  const handleAddWhitelist = async (values) => {
    try {
      const result = await api.addWhitelist({
        entry_type: values.type,
        value: values.value,
        description: values.reason || ''
      })
      setWhitelist([...whitelist, result])
      message.success('添加成功')
    } catch (error) {
      message.error('添加失败')
    }
    setIsModalOpen(false)
    form.resetFields()
  }

  const handleDeleteWhitelist = async (id) => {
    try {
      await api.deleteWhitelist(id)
      setWhitelist(whitelist.filter(item => item.id !== id))
      message.success('删除成功')
    } catch (error) {
      message.error('删除失败')
    }
  }

  const handleToggleRule = async (id) => {
    const rule = filterRules.find(r => r.id === id)
    if (!rule) return
    try {
      await api.updateFilterRule(id, { enabled: !rule.enabled })
      setFilterRules(filterRules.map(r =>
        r.id === id ? { ...r, enabled: !r.enabled } : r
      ))
      message.success('规则状态已更新')
    } catch (error) {
      message.error('更新失败')
    }
  }

  const whitelistColumns = [
    { title: '类型', dataIndex: 'type', key: 'type', width: 110, render: (type, record) => {
      const isWildcard = record.is_wildcard || (record.value && record.value.startsWith('*.'))
      if (isWildcard || type === 'wildcard') {
        return <Tag color="orange">泛解析</Tag>
      }
      const map = { ip: 'IP', cidr: 'CIDR', domain: '域名', keyword: '关键字', regex: '正则' }
      const color = { ip: 'blue', cidr: 'purple', domain: 'cyan', keyword: 'orange', regex: 'magenta' }
      return <Tag color={color[type]}>{map[type] || type}</Tag>
    }},
    { title: '值', dataIndex: 'value', key: 'value', render: (v, r) => {
      const isWildcard = r.is_wildcard || (r.value && r.value.startsWith('*.'))
      return (
        <Space>
          <Text code={r.type !== 'keyword'}>{v}</Text>
          {isWildcard && <Tag color="orange" style={{ fontSize: 10 }}>泛解析</Tag>}
        </Space>
      )
    }},
    { title: '说明', dataIndex: 'reason', key: 'reason', ellipsis: true },
    { title: '添加人', dataIndex: 'created_by', key: 'created_by' },
    { title: '添加时间', dataIndex: 'created_at', key: 'created_at' },
    { title: '操作', key: 'action', width: 100, render: (_, record) => (
      <Popconfirm title="确定删除?" onConfirm={() => handleDeleteWhitelist(record.id)}>
        <Button type="text" danger size="small" icon={<DeleteOutlined />} />
      </Popconfirm>
    )}
  ]

  const ruleColumns = [
    { title: '规则名称', dataIndex: 'name', key: 'name' },
    { title: '匹配模式', dataIndex: 'pattern', key: 'pattern', render: (p) => <Text code>{p}</Text> },
    { title: '类型', dataIndex: 'type', key: 'type' },
    { title: '状态', dataIndex: 'enabled', key: 'enabled', render: (enabled, record) => <Switch checked={enabled} onChange={() => handleToggleRule(record.id)} /> },
  ]

  return (
    <div style={{ padding: 24 }}>
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        {/* 标题 */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Space>
            <FilterOutlined style={{ fontSize: 24, color: '#1890ff' }} />
            <h2 style={{ margin: 0 }}>资产过滤配置</h2>
          </Space>
          <Space>
            <Text>全局过滤：</Text>
            <Switch checked={enabled} onChange={setEnabled} checkedChildren="开启" unCheckedChildren="关闭" />
          </Space>
        </div>

        {/* 说明 */}
        <Alert
          message="资产过滤说明"
          description={
            <Paragraph style={{ margin: 0 }}>
              资产过滤用于在扫描前排除不需要扫描的资产，避免误扫生产环境或敏感设备。
              <ul style={{ margin: '8px 0 0 0' }}>
                <li><b>白名单</b>：明确允许扫描的资产（与过滤规则配合使用）</li>
                <li><b>过滤规则</b>：自动排除匹配规则的资产，如内网保留地址、本地回环等</li>
                <li><b>泛解析去重</b>：当添加 <Text code>*.example.com</Text> 类型的泛解析白名单时，系统会智能保留有意义的前缀（如 admin、login、www），自动过滤随机字符组成的泛解析（如 <Text code>a3b7.example.com</Text>），大幅减少重复资产。</li>
              </ul>
            </Paragraph>
          }
          type="info"
          showIcon
          icon={<InfoCircleOutlined />}
        />

        {/* 统计 */}
        <Row gutter={16}>
          <Col span={6}>
            <Card size="small">
              <Statistic title="白名单条目" value={whitelist.length} prefix={<CheckCircleOutlined />} valueStyle={{ color: '#52c41a' }} />
            </Card>
          </Col>
          <Col span={6}>
            <Card size="small">
              <Statistic title="过滤规则" value={filterRules.length} prefix={<FilterOutlined />} valueStyle={{ color: '#1890ff' }} />
            </Card>
          </Col>
          <Col span={6}>
            <Card size="small">
              <Statistic title="生效规则" value={filterRules.filter(r => r.enabled).length} suffix={`/ ${filterRules.length}`} valueStyle={{ color: '#52c41a' }} />
            </Card>
          </Col>
          <Col span={6}>
            <Card size="small">
              <Statistic title="状态" value={enabled ? '过滤已启用' : '过滤已禁用'} valueStyle={{ color: enabled ? '#52c41a' : '#999' }} />
            </Card>
          </Col>
        </Row>

        {/* 白名单管理 */}
        <Card
          title={<Space><SafetyOutlined /> 白名单管理</Space>}
          extra={<Button type="primary" icon={<PlusOutlined />} onClick={() => setIsModalOpen(true)}>添加白名单</Button>}
        >
          <Table columns={whitelistColumns} dataSource={whitelist} rowKey="id" loading={loading} pagination={{ pageSize: 10 }} />
        </Card>

        {/* 过滤规则 */}
        <Card title={<Space><FilterOutlined /> 过滤规则</Space>}>
          <Paragraph type="secondary" style={{ marginBottom: 16 }}>
            过滤规则用于自动排除不符合条件的资产，支持正则表达式匹配。默认规则包括内网地址、本地回环、多播地址等特殊用途IP段。
          </Paragraph>
          <Table columns={ruleColumns} dataSource={filterRules} rowKey="id" pagination={false} />
        </Card>

        {/* 常见过滤示例 */}
        <Card title={<Space><InfoCircleOutlined /> 常见过滤示例</Space>} size="small">
          <Row gutter={[16, 16]}>
            <Col span={8}>
              <Text strong>内网保留地址：</Text>
              <Text code>10.0.0.0/8</Text>
              <Text type="secondary">、</Text>
              <Text code>172.16.0.0/12</Text>
              <Text type="secondary">、</Text>
              <Text code>192.168.0.0/16</Text>
            </Col>
            <Col span={8}>
              <Text strong>本地回环：</Text>
              <Text code>127.0.0.1</Text>
            </Col>
            <Col span={8}>
              <Text strong>广播/多播：</Text>
              <Text code>224.0.0.0/4</Text>
            </Col>
            <Col span={8}>
              <Text strong>测试域名：</Text>
              <Text code>*.test.com</Text>
            </Col>
            <Col span={8}>
              <Text strong>localhost：</Text>
              <Text code>localhost</Text>
            </Col>
            <Col span={8}>
              <Text strong>内部系统：</Text>
              <Text code>*.local</Text>
            </Col>
            <Col span={8}>
              <Text strong>泛解析（去重）：</Text>
              <Text code>*.qzone.cc.com</Text>
              <Text type="secondary" style={{ fontSize: 11, display: 'block' }}>保留 admin/login，剔除随机字符</Text>
            </Col>
          </Row>
        </Card>
      </Space>

      {/* 添加白名单弹窗 */}
      <Modal title="添加白名单" open={isModalOpen} onCancel={() => setIsModalOpen(false)} onOk={() => form.submit()} destroyOnClose>
        <Form form={form} layout="vertical" onFinish={handleAddWhitelist}>
          <Form.Item label="类型" name="type" rules={[{ required: true, message: '请选择类型' }]}>
            <Select placeholder="请选择类型">
              <Select.Option value="ip">IP地址</Select.Option>
              <Select.Option value="cidr">CIDR网段</Select.Option>
              <Select.Option value="domain">域名</Select.Option>
              <Select.Option value="keyword">关键字</Select.Option>
              <Select.Option value="regex">正则表达式</Select.Option>
              <Select.Option value="wildcard">泛解析（如 *.example.com）</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item label="值" name="value" rules={[{ required: true, message: '请输入值' }]}>
            <Input placeholder="例如: 192.168.1.1 或 192.168.1.0/24" />
          </Form.Item>
          <Form.Item label="说明" name="reason" rules={[{ required: true, message: '请输入说明' }]}>
            <Input placeholder="输入该白名单的原因或用途" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default AssetFilter
