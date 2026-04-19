import { useState, useEffect, useRef } from 'react'
import { Card, Table, Input, Select, Space, Tag, Button, message, Modal, Form, Upload, Popconfirm, Divider, Alert } from 'antd'
import { BugOutlined, PlusOutlined, SearchOutlined, ReloadOutlined, RocketOutlined, UploadOutlined, FileTextOutlined, DeleteOutlined, PlayCircleOutlined } from '@ant-design/icons'
import api from '../../services/api'
import useDataCache, { cacheKeys } from '../../store/dataCache'

const { Dragger } = Upload

const POCList = () => {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(false)
  const [filters, setFilters] = useState({ source: null, severity: null })
  const [pagination, setPagination] = useState({ current: 1, pageSize: 10, total: 0 })
  const [isImportModalOpen, setIsImportModalOpen] = useState(false)
  const [isAIGenerateModalOpen, setIsAIGenerateModalOpen] = useState(false)
  const [isTestModalOpen, setIsTestModalOpen] = useState(false)
  const [importType, setImportType] = useState('yaml')  // yaml | zip
  const [aiLoading, setAILoading] = useState(false)
  const [generatedPOC, setGeneratedPOC] = useState(null)
  const [testTarget, setTestTarget] = useState('')
  const [testingPOC, setTestingPOC] = useState(null)
  const [aiForm] = Form.useForm()
  const [testForm] = Form.useForm()
  const [refreshKey, setRefreshKey] = useState(0)

  const getCache = useDataCache((s) => s.getCache)
  const setCache = useDataCache((s) => s.setCache)
  const clearCache = useDataCache((s) => s.clearCache)

  useEffect(() => {
    loadPOCs()
  }, [filters, refreshKey])

  const loadPOCs = async () => {
    const cacheKey = `pocs_${filters.source || 'all'}_${filters.severity || 'all'}`
    const cached = getCache(cacheKey)

    if (cached) {
      setData(cached)
      return
    }

    setLoading(true)
    try {
      const params = {}
      if (filters.source) params.source = filters.source
      if (filters.severity) params.severity = filters.severity

      const result = await api.getPOCs(params)
      const list = Array.isArray(result) ? result : []
      setData(list)
      setPagination(p => ({ ...p, total: list.length }))
      setCache(cacheKey, list)
    } catch (error) {
      message.error('加载POC列表失败')
    } finally {
      setLoading(false)
    }
  }

  const handleRefresh = () => {
    clearCache(cacheKeys.vulns())
    setRefreshKey(k => k + 1)
  }

  // 导入POC
  const handleImport = async (file) => {
    try {
      const isYaml = file.name.endsWith('.yaml') || file.name.endsWith('.yml')
      const isZip = file.name.endsWith('.zip')

      if (!isYaml && !isZip) {
        message.error('只支持 YAML 或 ZIP 格式文件')
        return false
      }

      setLoading(true)
      let result

      if (isYaml) {
        result = await api.importPOCYaml(file)
      } else {
        result = await api.importPOCZip(file)
      }

      if (result.message.includes('成功') || result.imported > 0) {
        message.success(result.message || '导入成功')
        handleRefresh()
        setIsImportModalOpen(false)
      } else {
        message.warning(result.message || '导入完成，请查看详情')
      }
    } catch (error) {
      message.error(error.message || '导入失败')
    } finally {
      setLoading(false)
    }
    return false
  }

  // AI生成POC
  const handleAIGenerate = async (values) => {
    setAILoading(true)
    try {
      message.loading({ content: '正在生成POC，请稍候...', key: 'ai_poc' })

      const result = await api.aiGeneratePOC(values.description, values.target)

      if (result.reply) {
        // 提取生成的POC内容
        const pocContent = extractPOCFromResponse(result.reply)
        setGeneratedPOC(pocContent)
        message.success({ content: 'POC生成成功！', key: 'ai_poc' })
      } else {
        message.error({ content: '生成失败，请重试', key: 'ai_poc' })
      }
    } catch (error) {
      message.error({ content: error.message || 'AI生成失败', key: 'ai_poc' })
    } finally {
      setAILoading(false)
    }
  }

  // 从AI回复中提取POC
  const extractPOCFromResponse = (text) => {
    // 尝试提取 ```yaml ... ``` 包裹的内容
    const yamlMatch = text.match(/```(?:yaml)?\n([\s\S]*?)```/)
    if (yamlMatch) {
      return yamlMatch[1].trim()
    }
    // 尝试提取 ``` ... ```
    const codeMatch = text.match(/```\n([\s\S]*?)```/)
    if (codeMatch) {
      return codeMatch[1].trim()
    }
    return text.trim()
  }

  // 保存AI生成的POC
  const handleSaveGeneratedPOC = async () => {
    if (!generatedPOC) return

    try {
      // 创建临时文件
      const blob = new Blob([generatedPOC], { type: 'text/yaml' })
      const file = new File([blob], 'ai_generated_poc.yaml', { type: 'text/yaml' })

      const result = await api.importPOCYaml(file)

      if (result.id) {
        message.success('POC保存成功')
        setGeneratedPOC(null)
        setIsAIGenerateModalOpen(false)
        aiForm.resetFields()
        handleRefresh()
      }
    } catch (error) {
      message.error(error.message || '保存失败')
    }
  }

  // 测试POC
  const handleTestPOC = async (poc) => {
    setTestingPOC(poc)
    testForm.setFieldsValue({ target: '' })
    setIsTestModalOpen(true)
  }

  const handleRunTest = async (values) => {
    if (!testingPOC) return

    setLoading(true)
    try {
      message.loading({ content: '正在测试POC...', key: 'test_poc' })

      const result = await api.testPOC(testingPOC.id, values.target)

      if (result.success) {
        message.success({ content: `测试成功！发现漏洞: ${result.vuln_name || testingPOC.name}`, key: 'test_poc' })
      } else if (result.error) {
        message.error({ content: `测试失败: ${result.error}`, key: 'test_poc' })
      } else {
        message.warning({ content: result.message || '测试完成，未发现漏洞', key: 'test_poc' })
      }

      setIsTestModalOpen(false)
    } catch (error) {
      message.error({ content: error.message || '测试失败', key: 'test_poc' })
    } finally {
      setLoading(false)
    }
  }

  // 删除POC
  const handleDeletePOC = async (poc) => {
    try {
      await api.deletePOC(poc.id)
      message.success('POC已删除')
      handleRefresh()
    } catch (error) {
      message.error(error.message || '删除失败')
    }
  }

  const severityColor = { critical: 'red', high: 'orange', medium: 'gold', low: 'green' }
  const sourceColor = { Nuclei: 'blue', Goby: 'purple', Xray: 'cyan', custom: 'green', ai: 'magenta', default: 'default' }

  const columns = [
    {
      title: 'POC名称',
      dataIndex: 'name',
      key: 'name',
      render: (t, r) => (
        <Space>
          <span style={{ fontWeight: 500 }}>{t}</span>
          {r.ai_generated && <Tag color="purple">AI</Tag>}
        </Space>
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
      width: 200,
      render: (_, record) => (
        <Space size="small">
          <Button type="text" size="small" icon={<PlayCircleOutlined />} onClick={() => handleTestPOC(record)}>
            测试
          </Button>
          {record.source === 'custom' || record.source === 'ai' ? (
            <Popconfirm title="确认删除此POC？" onConfirm={() => handleDeletePOC(record)}>
              <Button type="text" size="small" danger icon={<DeleteOutlined />}>
                删除
              </Button>
            </Popconfirm>
          ) : null}
        </Space>
      )
    }
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><BugOutlined style={{ marginRight: 8 }} />POC管理</h1>
        <Space>
          <Button icon={<UploadOutlined />} onClick={() => { setImportType('yaml'); setIsImportModalOpen(true); }}>
            导入POC
          </Button>
          <Button type="primary" icon={<RocketOutlined />} onClick={() => setIsAIGenerateModalOpen(true)}>
            AI生成
          </Button>
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
            <Select.Option value="ai">AI生成</Select.Option>
          </Select>
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
          <Button icon={<ReloadOutlined />} onClick={handleRefresh}>刷新</Button>
        </Space>

        <Table
          columns={columns}
          dataSource={data}
          rowKey="id"
          loading={loading}
          pagination={{ pageSize: 10, total: pagination.total }}
          onChange={(p) => setPagination(pp => ({ ...pp, current: p.current }))}
        />
      </Card>

      {/* 导入POC弹窗 */}
      <Modal
        title="导入POC"
        open={isImportModalOpen}
        onCancel={() => setIsImportModalOpen(false)}
        footer={null}
        width={500}
      >
        <Space style={{ marginBottom: 16 }}>
          <Button
            type={importType === 'yaml' ? 'primary' : 'default'}
            onClick={() => setImportType('yaml')}
          >
            单个YAML
          </Button>
          <Button
            type={importType === 'zip' ? 'primary' : 'default'}
            onClick={() => setImportType('zip')}
          >
            批量ZIP
          </Button>
        </Space>

        <Divider style={{ margin: '12px 0' }} />

        <Dragger
          accept={importType === 'yaml' ? '.yaml,.yml' : '.zip'}
          showUploadList={false}
          beforeUpload={handleImport}
        >
          <p className="ant-upload-drag-icon">
            <UploadOutlined style={{ fontSize: 48, color: '#1890ff' }} />
          </p>
          <p className="ant-upload-text">点击或拖拽{importType === 'yaml' ? 'YAML' : 'ZIP'}文件上传</p>
          <p className="ant-upload-hint">
            {importType === 'yaml'
              ? '支持Nuclei标准的YAML格式POC'
              : '支持包含多个YAML POC文件的ZIP压缩包'}
          </p>
        </Dragger>

        <Alert
          message="支持格式"
          description={
            importType === 'yaml'
              ? 'Nuclei YAML模板格式 (.yaml, .yml)'
              : '包含多个YAML POC的ZIP压缩包'
          }
          type="info"
          showIcon
          style={{ marginTop: 16 }}
        />
      </Modal>

      {/* AI生成POC弹窗 */}
      <Modal
        title={<Space><RocketOutlined style={{ color: '#722ed1' }} />AI生成POC</Space>}
        open={isAIGenerateModalOpen}
        onCancel={() => {
          setIsAIGenerateModalOpen(false)
          setGeneratedPOC(null)
          aiForm.resetFields()
        }}
        width={700}
        footer={generatedPOC ? [
          <Button key="cancel" onClick={() => setGeneratedPOC(null)}>
            重新生成
          </Button>,
          <Button key="save" type="primary" onClick={handleSaveGeneratedPOC}>
            保存POC
          </Button>
        ] : null}
      >
        {!generatedPOC ? (
          <Form form={aiForm} layout="vertical" onFinish={handleAIGenerate}>
            <Alert
              message="AI POC生成器"
              description="输入漏洞描述，AI将为您生成Nuclei YAML格式的POC检测脚本"
              type="info"
              showIcon
              style={{ marginBottom: 16 }}
            />

            <Form.Item
              label="漏洞描述"
              name="description"
              rules={[{ required: true, message: '请输入漏洞描述' }]}
              extra="描述漏洞信息，如：Apache Struts2远程代码执行漏洞(CVE-2017-5638)"
            >
              <Input.TextArea
                placeholder="例如：ThinkPHP 5.0.23 远程代码执行漏洞，攻击者可通过构造恶意请求执行任意PHP代码"
                rows={4}
              />
            </Form.Item>

            <Form.Item
              label="目标地址"
              name="target"
              rules={[{ required: true, message: '请输入测试目标' }]}
              extra="输入目标URL或IP地址，生成的POC将针对此目标"
            >
              <Input placeholder="例如：http://192.168.1.1:8080 或 https://example.com" />
            </Form.Item>

            <Form.Item>
              <Button type="primary" htmlType="submit" block icon={<RocketOutlined />} loading={aiLoading}>
                生成POC
              </Button>
            </Form.Item>
          </Form>
        ) : (
          <div>
            <Alert
              message="POC生成成功！"
              description="以下是AI生成的POC内容，确认无误后可点击保存"
              type="success"
              showIcon
              style={{ marginBottom: 16 }}
            />
            <div style={{
              background: '#f5f5f5',
              padding: 16,
              borderRadius: 4,
              maxHeight: 400,
              overflow: 'auto',
              fontFamily: 'monospace',
              fontSize: 12,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all'
            }}>
              {generatedPOC}
            </div>
          </div>
        )}
      </Modal>

      {/* 测试POC弹窗 */}
      <Modal
        title={<Space><PlayCircleOutlined style={{ color: '#52c41a' }} />测试POC - {testingPOC?.name}</Space>}
        open={isTestModalOpen}
        onCancel={() => setIsTestModalOpen(false)}
        footer={null}
      >
        <Form form={testForm} layout="vertical" onFinish={handleRunTest}>
          <Form.Item
            label="测试目标"
            name="target"
            rules={[{ required: true, message: '请输入测试目标' }]}
          >
            <Input placeholder="输入目标URL或IP地址" />
          </Form.Item>

          <Form.Item style={{ marginBottom: 0 }}>
            <Space>
              <Button type="primary" htmlType="submit" icon={<PlayCircleOutlined />} loading={loading}>
                开始测试
              </Button>
              <Button onClick={() => setIsTestModalOpen(false)}>
                取消
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default POCList
