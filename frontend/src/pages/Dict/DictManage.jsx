import { useState, useEffect } from 'react'
import { Card, Table, Button, Space, Tag, Modal, Form, Input, Select, Upload, message, Popconfirm, Divider, List, Alert } from 'antd'
import { PlusOutlined, UploadOutlined, DeleteOutlined, EditOutlined, DownloadOutlined, ReloadOutlined, FileTextOutlined, DatabaseOutlined, SafetyOutlined } from '@ant-design/icons'
import api from '../../services/api'

const { TextArea } = Input

// 预设字典数据
const PRESET_DICTS = [
  {
    name: '常用子域名',
    type: 'subdomain',
    description: '常见子域名字典，包含 www, mail, ftp, admin, api 等',
    content: 'www,mail,ftp,admin,blog,dev,test,api,backup,staging,shop,crm,erp,oa,wiki,git,jenkins,docker,k8s,kubernetes,mobile,app,dashboard,smtp,pop,imap,webmail,owa,portal,cdn,static,assets,img,images,css,js,html,xml,json,api,rest,soap,v2,v3,old,new,staging,prod,production,dev,development,test,qa'
  },
  {
    name: '常见端口',
    type: 'port',
    description: '常见服务端口字典，包含 HTTP, HTTPS, SSH, FTP, 数据库等端口',
    content: '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1025,1433,1521,1723,3306,3389,5432,5900,5901,6379,8080,8443,8888,9090,9200,9300,10000,27017,27018,50000'
  },
  {
    name: 'Web敏感路径',
    type: 'path',
    description: 'Web应用敏感路径字典，用于目录扫描',
    content: 'admin,login,wp-admin,wp-login,administrator,phpmyadmin,admin.php,login.php,backup,backup.zip,backup.tar,backup.tar.gz,.git/config,.git/HEAD,.gitignore,.env,.env.bak,.htaccess,.htpasswd,swagger,swagger-ui,api-docs,api/swagger.json,console,manager,manage,management,editor,upload,uploads,files,images,docs,documentation,api,rest,graphql,v1,v2,v3,old,new,staging,prod,test,debug,trace,error'
  },
  {
    name: 'HTTP请求头',
    type: 'custom',
    description: '常用HTTP请求头字典',
    content: 'User-Agent,Accept,Accept-Language,Accept-Encoding,Connection,Host,Referer,Cookie,Authorization,X-Requested-With,X-Forwarded-For,X-Remote-IP,X-Remote-Addr'
  },
  {
    name: '常见Banner信息',
    type: 'custom',
    description: '常见服务Banner特征字典',
    content: 'SSH-2.0-OpenSSH,SSH-1.99-OpenSSH,FTP,banner,Apache,Nginx,Tomcat,JBoss,WebLogic,IIS,Microsoft-HTTPAPI,MySQL,PostgreSQL,MongoDB,Redis'
  }
]

const DictManage = () => {
  const [dicts, setDicts] = useState([])
  const [loading, setLoading] = useState(false)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [isPresetModalOpen, setIsPresetModalOpen] = useState(false)
  const [editingDict, setEditingDict] = useState(null)
  const [form] = Form.useForm()
  const [viewDict, setViewDict] = useState(null)
  const [presetLoading, setPresetLoading] = useState(false)

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

  // 加载预设字典
  const handleLoadPresets = async () => {
    setPresetLoading(true)
    try {
      // 直接在前端创建预设字典
      for (const preset of PRESET_DICTS) {
        try {
          await api.createDict({
            name: preset.name,
            type: preset.type,
            content: preset.content,
            description: preset.description,
            is_default: true
          })
        } catch (e) {
          // 忽略已存在的错误
          console.log(`${preset.name} 已存在或创建失败`)
        }
      }
      message.success('预设字典加载成功')
      setIsPresetModalOpen(false)
      loadDicts()
    } catch (error) {
      message.error('加载预设字典失败')
    } finally {
      setPresetLoading(false)
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
    { title: '来源', dataIndex: 'source', key: 'source', render: (s) => s === 'system' ? <Tag color="cyan">系统</Tag> : <Tag color="green">自定义</Tag> },
    { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
    {
      title: '操作',
      key: 'action',
      width: 180,
      render: (_, record) => (
        <Space size="small">
          <Button type="text" size="small" onClick={() => handleViewWords(record)}>查看</Button>
          {record.source !== 'system' && (
            <>
              <Button type="text" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)} />
              <Popconfirm title="确定删除?" onConfirm={() => handleDelete(record.id)}>
                <Button type="text" size="small" danger icon={<DeleteOutlined />} />
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
          <Button icon={<DatabaseOutlined />} onClick={() => setIsPresetModalOpen(true)}>
            预设字典
          </Button>
          <Upload accept=".txt" beforeUpload={handleImportTxt} showUploadList={false}>
            <Button icon={<UploadOutlined />}>导入TXT</Button>
          </Upload>
          <Button icon={<PlusOutlined />} type="primary" onClick={handleCreate}>创建字典</Button>
        </Space>
      </div>

      {/* 提示信息 */}
      {dicts.length === 0 && !loading && (
        <Alert
          message="暂无字典"
          description="您可以加载预设字典（系统内置常用字典）或创建自定义字典"
          type="info"
          showIcon
          icon={<SafetyOutlined />}
          style={{ marginBottom: 16 }}
          action={
            <Button size="small" type="primary" onClick={() => setIsPresetModalOpen(true)}>
              加载预设字典
            </Button>
          }
        />
      )}

      <Card className="content-card" bordered={false}>
        <Table
          columns={columns}
          dataSource={dicts}
          rowKey="id"
          loading={loading}
          pagination={{ pageSize: 10 }}
        />
      </Card>

      {/* 预设字典弹窗 */}
      <Modal
        title={<Space><DatabaseOutlined />选择预设字典</Space>}
        open={isPresetModalOpen}
        onCancel={() => setIsPresetModalOpen(false)}
        footer={
          <Space>
            <Button onClick={() => setIsPresetModalOpen(false)}>取消</Button>
            <Button type="primary" icon={<SafetyOutlined />} onClick={handleLoadPresets} loading={presetLoading}>
              一键加载所有预设字典
            </Button>
          </Space>
        }
        width={600}
      >
        <Alert
          message="预设字典说明"
          description="以下是系统预置的常用字典，点击「一键加载」将所有预设字典导入到您的账户中"
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
        />
        
        <div style={{ maxHeight: 400, overflow: 'auto' }}>
          {PRESET_DICTS.map((preset, index) => (
            <Card size="small" key={index} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <strong>{preset.name}</strong>
                  <Tag color={typeColor[preset.type]} style={{ marginLeft: 8 }}>{typeText[preset.type]}</Tag>
                  <div style={{ fontSize: 12, color: '#666', marginTop: 4 }}>
                    {preset.description}
                  </div>
                </div>
                <Tag>{preset.content.split(',').length} 词条</Tag>
              </div>
            </Card>
          ))}
        </div>
      </Modal>

      {/* 创建/编辑字典弹窗 */}
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

      {/* 查看词条弹窗 */}
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
            <div style={{ maxHeight: 300, overflow: 'auto' }}>
              {(viewDict.words || []).map((word, i) => (
                <Tag key={i} style={{ margin: 4 }}>{word}</Tag>
              ))}
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}

export default DictManage
