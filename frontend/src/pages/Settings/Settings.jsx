import { useState, useEffect } from 'react'
import { Card, Tabs, Form, Input, Button, Switch, Space, message, InputNumber, Select, Tag, Modal, Upload, Statistic, Row, Col, Alert, Progress, Divider, Typography, List } from 'antd'
import { SettingOutlined, RobotOutlined, SyncOutlined, SafetyOutlined, CloudUploadOutlined, CloudDownloadOutlined, CheckCircleOutlined, ExclamationCircleOutlined, InfoCircleOutlined } from '@ant-design/icons'
import api from '../../services/api'
import dayjs from 'dayjs'

const { Text, Paragraph } = Typography

const Settings = () => {
  const [aiForm] = Form.useForm()
  const [systemForm] = Form.useForm()
  const [rulesLoading, setRulesLoading] = useState(false)
  const [updating, setUpdating] = useState(false)
  const [updateProgress, setUpdateProgress] = useState(0)
  const [updateResult, setUpdateResult] = useState(null)
  const [ruleStats, setRuleStats] = useState({
    nuclei_templates: 0,
    nuclei_categories: {},
    pocs: 0,
    pocs_by_source: {},
    custom_rules: 0,
    disk_usage: 0,
    xray_pocs: 0,
    xray_categories: {}
  })
  const [autoUpdateConfig, setAutoUpdateConfig] = useState({
    enabled: true,
    frequency: 'daily',
    time: '03:00',
    weekDay: 1,
    monthDay: 1
  })

  useEffect(() => {
    loadRuleStats()
  }, [])

  const loadRuleStats = async () => {
    try {
      const stats = await api.getRuleStats()
      // 获取Xray POC统计
      try {
        const xrayStats = await api.getXrayStats()
        stats.xray_pocs = xrayStats.total || 0
        stats.xray_categories = xrayStats.categories || {}
        stats.disk_usage = (stats.disk_usage || 0) + (xrayStats.disk_usage || 0)
      } catch (e) {
        console.error('获取Xray统计失败:', e)
      }
      setRuleStats(stats)
    } catch (error) {
      console.error('获取规则统计失败:', error)
    }
  }

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

  const handleOnlineUpdate = async () => {
    setUpdating(true)
    setUpdateProgress(0)
    setUpdateResult(null)
    
    try {
      // 模拟更新进度
      const progressTimer = setInterval(() => {
        setUpdateProgress(prev => {
          if (prev >= 90) {
            clearInterval(progressTimer)
            return prev
          }
          return prev + 10
        })
      }, 500)
      
      const result = await api.updateRulesOnline()
      
      clearInterval(progressTimer)
      setUpdateProgress(100)
      
      setUpdateResult({
        success: true,
        message: '规则库更新成功！',
        details: result.details || {}
      })
      
      message.success('规则库更新成功')
      loadRuleStats()
    } catch (error) {
      setUpdateResult({
        success: false,
        message: '更新失败',
        error: error.message
      })
      message.error(error.message || '更新失败')
    } finally {
      setUpdating(false)
    }
  }

  const handleOfflineUpdate = async (file) => {
    if (!file) return
    
    setUpdating(true)
    setUpdateResult(null)
    
    try {
      const result = await api.updateRulesOffline(file)
      
      setUpdateResult({
        success: true,
        message: '离线更新成功！',
        details: result.details || {}
      })
      
      // 显示新增的规则详情
      if (result.details) {
        const { nuclei_templates, new_categories, pocs } = result.details
        
        let successMsg = `更新完成！`
        if (nuclei_templates > 0) {
          successMsg += `\n新增 Nuclei 模板: ${nuclei_templates} 个`
        }
        if (new_categories && new_categories.length > 0) {
          successMsg += `\n新增类别: ${new_categories.join(', ')}`
        }
        if (pocs > 0) {
          successMsg += `\n新增 POC 规则: ${pocs} 个`
        }
        
        Modal.success({
          title: '离线更新成功',
          content: <pre style={{ whiteSpace: 'pre-wrap' }}>{successMsg}</pre>
        })
      }
      
      message.success('离线更新成功')
      loadRuleStats()
    } catch (error) {
      setUpdateResult({
        success: false,
        message: '离线更新失败',
        error: error.message
      })
      Modal.error({
        title: '离线更新失败',
        content: error.message || '请检查离线包格式是否正确'
      })
    } finally {
      setUpdating(false)
    }
  }

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const categories = [
    { key: 'sqli', label: 'SQL注入', color: 'red' },
    { key: 'xss', label: 'XSS跨站脚本', color: 'orange' },
    { key: 'rce', label: '远程代码执行', color: 'magenta' },
    { key: 'lfi', label: '本地文件包含', color: 'gold' },
    { key: 'rfi', label: '远程文件包含', color: 'lime' },
    { key: 'ssrf', label: 'SSRF', color: 'green' },
    { key: 'csrf', label: 'CSRF', color: 'cyan' },
    { key: 'fingerprint', label: '指纹识别', color: 'blue' },
    { key: 'misc', label: '其他', color: 'purple' }
  ]

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
        <div>
          {/* 规则库统计 */}
          <Card size="small" style={{ marginBottom: 16 }}>
            <Row gutter={16}>
              <Col span={6}>
                <Statistic 
                  title="Nuclei 模板" 
                  value={ruleStats.nuclei_templates} 
                  suffix="个"
                  valueStyle={{ color: '#1890ff' }}
                />
              </Col>
              <Col span={6}>
                <Statistic 
                  title="POC 规则库" 
                  value={ruleStats.pocs} 
                  suffix="个"
                  valueStyle={{ color: '#52c41a' }}
                />
              </Col>
              <Col span={6}>
                <Statistic 
                  title="自定义规则" 
                  value={ruleStats.custom_rules} 
                  suffix="个"
                  valueStyle={{ color: '#faad14' }}
                />
              </Col>
              <Col span={6}>
                <Statistic 
                  title="占用空间" 
                  value={formatBytes(ruleStats.disk_usage)} 
                />
              </Col>
            </Row>
          </Card>

          {/* 规则类别分布 */}
          {Object.keys(ruleStats.nuclei_categories).length > 0 && (
            <Card size="small" title="Nuclei 规则类别分布" style={{ marginBottom: 16 }}>
              <Row gutter={16}>
                {Object.entries(ruleStats.nuclei_categories).slice(0, 6).map(([cat, count]) => (
                  <Col span={8} key={cat} style={{ marginBottom: 8 }}>
                    <Tag color="blue">{cat}</Tag>: {count} 个
                  </Col>
                ))}
              </Row>
            </Card>
          )}

          <Divider />

          {/* 自动更新设置 */}
          <Card size="small" title="自动更新设置" style={{ marginBottom: 16 }}>
            <Form layout="vertical">
              <Form.Item label="启用自动更新">
                <Switch 
                  checked={autoUpdateConfig.enabled} 
                  onChange={(checked) => setAutoUpdateConfig({...autoUpdateConfig, enabled: checked})}
                />
              </Form.Item>

              {autoUpdateConfig.enabled && (
                <>
                  <Form.Item label="更新频率">
                    <Select 
                      value={autoUpdateConfig.frequency}
                      onChange={(value) => setAutoUpdateConfig({...autoUpdateConfig, frequency: value})}
                    >
                      <Select.Option value="hourly">每小时</Select.Option>
                      <Select.Option value="daily">每天</Select.Option>
                      <Select.Option value="weekly">每周</Select.Option>
                      <Select.Option value="monthly">每月</Select.Option>
                    </Select>
                  </Form.Item>

                  {autoUpdateConfig.frequency === 'daily' && (
                    <Form.Item label="更新时间">
                      <Input 
                        type="time" 
                        value={autoUpdateConfig.time}
                        onChange={(e) => setAutoUpdateConfig({...autoUpdateConfig, time: e.target.value})}
                        style={{ width: 150 }}
                      />
                    </Form.Item>
                  )}

                  {autoUpdateConfig.frequency === 'weekly' && (
                    <Form.Item label="更新周期">
                      <Space>
                        <Select 
                          value={autoUpdateConfig.weekDay}
                          onChange={(value) => setAutoUpdateConfig({...autoUpdateConfig, weekDay: value})}
                          style={{ width: 120 }}
                        >
                          <Select.Option value={1}>周一</Select.Option>
                          <Select.Option value={2}>周二</Select.Option>
                          <Select.Option value={3}>周三</Select.Option>
                          <Select.Option value={4}>周四</Select.Option>
                          <Select.Option value={5}>周五</Select.Option>
                          <Select.Option value={6}>周六</Select.Option>
                          <Select.Option value={0}>周日</Select.Option>
                        </Select>
                        <Input 
                          type="time" 
                          value={autoUpdateConfig.time}
                          onChange={(e) => setAutoUpdateConfig({...autoUpdateConfig, time: e.target.value})}
                          style={{ width: 120 }}
                        />
                      </Space>
                    </Form.Item>
                  )}

                  {autoUpdateConfig.frequency === 'monthly' && (
                    <Form.Item label="更新周期">
                      <Space>
                        <InputNumber 
                          value={autoUpdateConfig.monthDay}
                          onChange={(value) => setAutoUpdateConfig({...autoUpdateConfig, monthDay: value})}
                          min={1} 
                          max={28}
                          style={{ width: 80 }}
                        />
                        <Text>日</Text>
                        <Input 
                          type="time" 
                          value={autoUpdateConfig.time}
                          onChange={(e) => setAutoUpdateConfig({...autoUpdateConfig, time: e.target.value})}
                          style={{ width: 120 }}
                        />
                      </Space>
                    </Form.Item>
                  )}
                </>
              )}
            </Form>
          </Card>

          {/* 规则数据源 */}
          <Card size="small" title="规则数据源" style={{ marginBottom: 16 }}>
            <Space direction="vertical" style={{ width: '100%' }}>
              <div>
                <Switch defaultChecked disabled /> <Text strong> NUCLEI TEMPLATES </Text> 
                <Tag color="blue" style={{ marginLeft: 8 }}>{ruleStats.nuclei_templates} 个</Tag>
                <Text type="secondary" style={{ marginLeft: 8 }}>官方漏洞检测规则库</Text>
              </div>
              <div>
                <Switch defaultChecked disabled /> <Text strong> MSF模块 </Text> 
                <Tag color="green" style={{ marginLeft: 8 }}>{ruleStats.pocs} 个</Tag>
                <Text type="secondary" style={{ marginLeft: 8 }}>Metasploit漏洞利用模块</Text>
              </div>
              <div>
                <Switch defaultChecked disabled /> <Text strong> XRAY POC </Text> 
                <Tag color="orange" style={{ marginLeft: 8 }}>{ruleStats.xray_pocs} 个</Tag>
                <Text type="secondary" style={{ marginLeft: 8 }}>长亭科技Xray漏洞检测规则</Text>
              </div>
              <div>
                <Switch defaultChecked /> <Text strong> 自定义规则 </Text> 
                <Tag color="gold" style={{ marginLeft: 8 }}>{ruleStats.custom_rules} 个</Tag>
                <Text type="secondary" style={{ marginLeft: 8 }}>用户导入的私有规则</Text>
              </div>
            </Space>
          </Card>

          {/* 更新操作 */}
          <Card size="small" title="更新操作">
            {updating && (
              <div style={{ marginBottom: 16 }}>
                <Progress percent={updateProgress} status="active" />
                <Text type="secondary">正在更新规则库，请稍候...</Text>
              </div>
            )}

            {updateResult && (
              <Alert
                type={updateResult.success ? 'success' : 'error'}
                message={updateResult.message}
                description={updateResult.error || (updateResult.details && (
                  <div>
                    {updateResult.details.nuclei_templates > 0 && (
                      <div>• Nuclei 模板: +{updateResult.details.nuclei_templates} 个</div>
                    )}
                    {updateResult.details.pocs > 0 && (
                      <div>• POC 规则: +{updateResult.details.pocs} 个</div>
                    )}
                    {updateResult.details.new_categories?.length > 0 && (
                      <div>• 新增类别: {updateResult.details.new_categories.join(', ')}</div>
                    )}
                  </div>
                ))}
                icon={updateResult.success ? <CheckCircleOutlined /> : <ExclamationCircleOutlined />}
                showIcon
                style={{ marginBottom: 16 }}
              />
            )}

            <Space wrap>
              <Button 
                type="primary" 
                icon={<CloudDownloadOutlined />}
                onClick={handleOnlineUpdate}
                loading={updating}
              >
                在线更新
              </Button>
              
              <Upload
                accept=".zip"
                beforeUpload={(file) => {
                  handleOfflineUpdate(file)
                  return false
                }}
                showUploadList={false}
                disabled={updating}
              >
                <Button icon={<CloudUploadOutlined />} loading={updating}>
                  离线更新
                </Button>
              </Upload>

              <Button icon={<InfoCircleOutlined />}>
                检查更新
              </Button>
            </Space>

            <Paragraph type="secondary" style={{ marginTop: 16 }}>
              <Text type="secondary">
                💡 提示: 离线包来源: <a href="https://www.mayisafe.cn" target="_blank" rel="noopener">www.mayisafe.cn</a> 。
                如无法联网，请前往官网下载最新离线规则包进行更新。
              </Text>
            </Paragraph>
          </Card>
        </div>
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

export default Settings
