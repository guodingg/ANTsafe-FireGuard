import { Card, Tabs, Form, Input, Button, Switch, Space, message, InputNumber, Select } from 'antd'
import { SettingOutlined, RobotOutlined, SyncOutlined, SafetyOutlined } from '@ant-design/icons'
import api from '../../services/api'

const Settings = () => {
  const [aiForm] = Form.useForm()
  const [systemForm] = Form.useForm()
  const [rulesLoading, setRulesLoading] = useState(false)

  const onAIFinish = async (values) => {
    try {
      message.success('AI配置已保存')
    } catch (error) {
      message.error('保存失败')
    }
  }

  const onSystemFinish = async (values) => {
    try {
      message.success('系统配置已保存')
    } catch (error) {
      message.error('保存失败')
    }
  }

  const handleRulesUpdate = async () => {
    setRulesLoading(true)
    try {
      await new Promise(resolve => setTimeout(resolve, 2000))
      message.success('规则更新完成')
    } catch (error) {
      message.error('更新失败')
    } finally {
      setRulesLoading(false)
    }
  }

  const items = [
    {
      key: 'ai',
      label: <span><RobotOutlined /> AI配置</span>,
      children: (
        <Form form={aiForm} layout="vertical" onFinish={onAIFinish} initialValues={{ provider: 'kimi', timeout: 30 }}>
          <Form.Item label="AI服务提供商" name="provider">
            <Select>
              <Select.Option value="kimi">Kimi (月之暗面)</Select.Option>
              <Select.Option value="minimax">MiniMax</Select.Option>
              <Select.Option value="deepseek">DeepSeek</Select.Option>
              <Select.Option value="qwen">通义千问</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item label="API Key" name="apiKey">
            <Input.Password placeholder="请输入API Key" />
          </Form.Item>
          <Form.Item label="模型" name="model">
            <Input placeholder="如: moonshot-v1-8k" />
          </Form.Item>
          <Form.Item label="请求超时(秒)" name="timeout">
            <InputNumber min={10} max={120} />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit">保存配置</Button>
          </Form.Item>
        </Form>
      )
    },
    {
      key: 'rules',
      label: <span><SyncOutlined /> 规则更新</span>,
      children: (
        <Form layout="vertical">
          <Form.Item label="自动更新">
            <Switch defaultChecked />
          </Form.Item>
          <Form.Item label="更新频率">
            <Select defaultValue="daily">
              <Select.Option value="hourly">每小时</Select.Option>
              <Select.Option value="daily">每天</Select.Option>
              <Select.Option value="weekly">每周</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item label="规则数据源">
            <Space direction="vertical" style={{ width: '100%' }}>
              <div><Switch defaultChecked disabled /> <span>Nuclei Templates</span></div>
              <div><Switch defaultChecked disabled /> <span>MSF模块</span></div>
              <div><Switch defaultChecked disabled /> <span>Goby POC</span></div>
              <div><Switch defaultChecked /> <span>自定义规则</span></div>
            </Space>
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" onClick={handleRulesUpdate} loading={rulesLoading}>立即更新</Button>
              <Button>检查更新</Button>
            </Space>
          </Form.Item>
        </Form>
      )
    },
    {
      key: 'system',
      label: <span><SafetyOutlined /> 安全设置</span>,
      children: (
        <Form layout="vertical" onFinish={onSystemFinish} initialValues={{ port: 8000, maxTask: 10, timeout: 30 }}>
          <Form.Item label="服务端口" name="port">
            <InputNumber min={1024} max={65535} />
          </Form.Item>
          <Form.Item label="最大并发任务数" name="maxTask">
            <InputNumber min={1} max={100} />
          </Form.Item>
          <Form.Item label="会话超时(分钟)" name="timeout">
            <InputNumber min={5} max={1440} />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit">保存配置</Button>
          </Form.Item>
        </Form>
      )
    }
  ]

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><SettingOutlined style={{ marginRight: 8 }} />系统设置</h1>
      </div>
      <Card className="content-card" bordered={false}>
        <Tabs items={items} />
      </Card>
    </div>
  )
}

import { useState } from 'react'

export default Settings
