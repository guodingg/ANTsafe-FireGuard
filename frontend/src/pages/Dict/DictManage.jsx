import { useState, useEffect } from 'react'
import { Card, Table, Button, Space, Tag, Modal, Form, Input, Select, Upload, message, Popconfirm, Divider, List } from 'antd'
import { PlusOutlined, UploadOutlined, DeleteOutlined, EditOutlined, DownloadOutlined, ReloadOutlined, FileTextOutlined } from '@ant-design/icons'
import api from '../../services/api'

const { TextArea } = Input

const DictManage = () => {
  const [dicts, setDicts] = useState([])
  const [loading, setLoading] = useState(false)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [editingDict, setEditingDict] = useState(null)
  const [form] = Form.useForm()
  const [viewDict, setViewDict] = useState(null)

  useEffect(() => {
    loadDicts()
  }, [])

  const loadDicts = async () => {
    setLoading(true)
    try {
      const data = await api.getDicts()
      setDicts(data)
    } catch (error) {
      message.error('加载字典失败')
    } finally {
      setLoading(false)
    }
  }

  const handleCreate = () => {
    setEditingDict(null)
    form.resetFields()
    setIsModalOpen(true)
  }

  const handleEdit = (record) => {
    setEditingDict(record)
    form.setFieldsValue({
      name: record.name,
      type: record.type,
      content: record.content,
      description: record.description,
      is_default: record.is_default
    })
    setIsModalOpen(true)
  }

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields()
      
      if (editingDict) {
        await api.updateDict(editingDict.id, values)
        message.success('字典更新成功')
      } else {
        await api.createDict(values)
        message.success('字典创建成功')
      }
      
      setIsModalOpen(false)
      loadDicts()
    } catch (error) {
      message.error(editingDict ? '更新失败' : '创建失败')
    }
  }

  const handleDelete = async (id) => {
    try {
      await api.deleteDict(id)
      message.success('字典已删除')
      loadDicts()
    } catch (error) {
      message.error('删除失败')
    }
  }

  const handleImportTxt = async (file) => {
    try {
      const result = await api.importDictTxt(file, 'custom')
      message.success(result.message || '导入成功')
      loadDicts()
    } catch (error) {
      message.error('导入失败')
    }
    return false
  }

  const handleViewWords = async (record) => {
    try {
      const data = await api.request(`/dicts/${record.id}/words?limit=50`)
      setViewDict({ ...record, words: data.words })
    } catch (error) {
      message.error('获取词条失败')
    }
  }

  const typeColor = {
    subdomain: 'blue',
    port: 'green',
    path: 'orange',
    user_agent: 'purple',
    custom: 'default'
  }

  const typeText = {
    subdomain: '子域名典',
    port: '端口字典',
    path: '路径字典',
    user_agent: 'UA字典',
    custom: '自定义'
  }

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name', render: (t, r) => (
      <span>
        <FileTextOutlined style={{ marginRight: 8 }} />
        {t}
        {r.is_default && <Tag color="blue" style={{ marginLeft: 8 }}>默认</Tag>}
      </span>
    )},
    { title: '类型', dataIndex: 'type', key: 'type', render: (t) => <Tag color={typeColor[t]}>{typeText[t]}</Tag> },
    { title: '词条数', dataIndex: 'count', key: 'count' },
    { title: '来源', dataIndex: 'source', key: 'source', render: (s) => s === 'system' ? <Tag>系统</Tag> : <Tag color="green">自定义</Tag> },
    { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Space>
          <Button type="text" size="small" onClick={() => handleViewWords(record)}>查看词条</Button>
          {record.source !== 'system' && (
            <>
              <Button type="text" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>编辑</Button>
              <Popconfirm title="确定删除?" onConfirm={() => handleDelete(record.id)}>
                <Button type="text" size="small" danger icon={<DeleteOutlined />}>删除</Button>
              </Popconfirm>
            </>
          )}
        </Space>
      )
    }
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><FileTextOutlined style={{ marginRight: 8 }} />自定义字典</h1>
        <Space>
          <Upload accept=".txt" beforeUpload={handleImportTxt} showUploadList={false}>
            <Button icon={<UploadOutlined />}>导入TXT</Button>
          </Upload>
          <Button icon={<PlusOutlined />} type="primary" onClick={handleCreate}>创建字典</Button>
        </Space>
      </div>

      <Card className="content-card" bordered={false}>
        <Table
          columns={columns}
          dataSource={dicts}
          rowKey="id"
          loading={loading}
          pagination={{ pageSize: 10 }}
        />
      </Card>

      <Modal
        title={editingDict ? '编辑字典' : '创建字典'}
        open={isModalOpen}
        onOk={handleSubmit}
        onCancel={() => setIsModalOpen(false)}
        width={600}
        destroyOnClose
      >
        <Form form={form} layout="vertical">
          <Form.Item label="字典名称" name="name" rules={[{ required: true, message: '请输入字典名称' }]}>
            <Input placeholder="如：常用子域名" />
          </Form.Item>
          <Form.Item label="字典类型" name="type" rules={[{ required: true, message: '请选择类型' }]}>
            <Select placeholder="选择字典类型">
              <Select.Option value="subdomain">子域名典</Select.Option>
              <Select.Option value="port">端口字典</Select.Option>
              <Select.Option value="path">路径字典</Select.Option>
              <Select.Option value="user_agent">UA字典</Select.Option>
              <Select.Option value="custom">自定义</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item label="字典内容" name="content" rules={[{ required: true, message: '请输入字典内容' }]}>
            <TextArea rows={6} placeholder="每行一个词条，或用逗号分隔" />
          </Form.Item>
          <Form.Item label="描述" name="description">
            <Input.TextArea rows={2} placeholder="字典描述（可选）" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={`${viewDict?.name} - 词条列表`}
        open={!!viewDict}
        onCancel={() => setViewDict(null)}
        footer={null}
        width={500}
      >
        {viewDict && (
          <div>
            <p>共 {viewDict.words?.length || 0} 个词条</p>
            <div className="word-list">
              {(viewDict.words || []).map((word, i) => (
                <Tag key={i}>{word}</Tag>
              ))}
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}

export default DictManage
