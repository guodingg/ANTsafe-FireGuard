import { useState, useEffect } from 'react'
import { Row, Col, Card, Button, Input, Select, Table, Space, Progress, Tag, message } from 'antd'
import {
  SearchOutlined,
  PlayCircleOutlined,
  CloudServerOutlined,
  SafetyOutlined,
  CheckCircleOutlined,
  WarningOutlined,
  HistoryOutlined,
  RightOutlined,
  SyncOutlined
} from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import ReactECharts from 'echarts-for-react'
import api from '../../services/api'
import useDataCache, { cacheKeys } from '../../store/dataCache'
import './Dashboard.css'

const { Search } = Input

const Dashboard = () => {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [initialized, setInitialized] = useState(false)
  const [stats, setStats] = useState({
    tasks: { total: 0, running: 0, completed: 0 },
    assets: { total: 0, alive: 0 },
    vulnerabilities: { total: 0, critical: 0, high: 0 }
  })
  const [recentTasks, setRecentTasks] = useState([])
  const [taskTrend, setTaskTrend] = useState([])
  const [scanLoading, setScanLoading] = useState(false)
  const [quickScanTarget, setQuickScanTarget] = useState('')
  const [quickScanType, setQuickScanType] = useState('full')
  const [refreshKey, setRefreshKey] = useState(0)

  // 获取缓存
  const getCache = useDataCache((s) => s.getCache)
  const setCache = useDataCache((s) => s.setCache)

  useEffect(() => {
    loadDashboardData()
  }, [refreshKey])

  // 刷新数据（清除缓存）
  const handleRefresh = () => {
    const clearCache = useDataCache.getState().clearCache
    clearCache(cacheKeys.stats())
    setRefreshKey(k => k + 1)
  }

  const loadDashboardData = async () => {
    // 先检查缓存
    const key = cacheKeys.stats()
    const cached = getCache(key)
    
    if (cached) {
      setStats(cached)
      setRecentTasks(cached.recent_tasks || [])
      setTaskTrend(cached.task_trend || [])
      setInitialized(true)
      return
    }
    
    setLoading(true)
    try {
      const data = await api.getDashboardStats()
      setStats(data)
      setRecentTasks(data.recent_tasks || [])
      setTaskTrend(data.task_trend || [])
      setCache(key, data)  // 缓存数据
      setInitialized(true)
    } catch (error) {
      console.error('加载仪表盘数据失败:', error)
    } finally {
      setLoading(false)
    }
  }

  // 统计卡片
  const statCards = [
    {
      title: '总扫描任务',
      value: stats.tasks.total,
      icon: <SearchOutlined />,
      color: 'blue',
      onClick: () => navigate('/scan/tasks')
    },
    {
      title: '安全主机',
      value: stats.assets.alive,
      suffix: `/${stats.assets.total}`,
      icon: <CloudServerOutlined />,
      color: 'green',
      onClick: () => navigate('/assets')
    },
    {
      title: '高危漏洞',
      value: stats.vulnerabilities.critical + stats.vulnerabilities.high,
      icon: <WarningOutlined />,
      color: 'orange',
      onClick: () => navigate('/vulns')
    },
    {
      title: '已完成任务',
      value: stats.tasks.completed,
      icon: <CheckCircleOutlined />,
      color: 'blue',
      onClick: () => navigate('/scan/tasks')
    }
  ]

  // 漏洞分布图表配置
  const vulnChartOption = {
    tooltip: {
      trigger: 'item',
      formatter: '{b}: {c} ({d}%)'
    },
    legend: {
      orient: 'vertical',
      right: '5%',
      top: 'center',
      textStyle: { color: '#8C8C8C' }
    },
    color: ['#FF4D4F', '#FF8C00', '#d4b106', '#52C41A', '#1677FF'],
    series: [
      {
        name: '漏洞分布',
        type: 'pie',
        radius: ['45%', '70%'],
        center: ['35%', '50%'],
        avoidLabelOverlap: false,
        itemStyle: {
          borderRadius: 6,
          borderColor: '#fff',
          borderWidth: 2
        },
        label: { show: false },
        emphasis: {
          label: { show: true, fontSize: 14, fontWeight: 'bold' }
        },
        data: [
          { value: stats.vulnerabilities.critical, name: '严重' },
          { value: stats.vulnerabilities.high, name: '高危' },
          { value: 0, name: '中危' },
          { value: 0, name: '低危' },
          { value: 0, name: '信息' }
        ]
      }
    ]
  }

  // 任务趋势图表配置
  const trendChartOption = {
    tooltip: { trigger: 'axis' },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: taskTrend.map(t => t.date?.slice(5) || ''),
      axisLine: { lineStyle: { color: '#E8E8E8' } },
      axisLabel: { color: '#8C8C8C' }
    },
    yAxis: {
      type: 'value',
      axisLine: { show: false },
      splitLine: { lineStyle: { color: '#F0F0F0' } },
      axisLabel: { color: '#8C8C8C' }
    },
    color: ['#1677FF'],
    series: [
      {
        name: '扫描任务',
        type: 'line',
        smooth: true,
        areaStyle: {
          color: {
            type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(22, 119, 255, 0.3)' },
              { offset: 1, color: 'rgba(22, 119, 255, 0.05)' }
            ]
          }
        },
        data: taskTrend.map(t => t.count || 0)
      }
    ]
  }

  const taskColumns = [
    { title: '任务名称', dataIndex: 'name', key: 'name' },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status) => {
        const map = {
          completed: { color: 'green', text: '已完成' },
          running: { color: 'blue', text: '扫描中' },
          pending: { color: 'orange', text: '等待中' }
        }
        const { color, text } = map[status] || { color: 'default', text: status }
        return <Tag color={color}>{text}</Tag>
      }
    },
    {
      title: '进度',
      dataIndex: 'progress',
      key: 'progress',
      render: (progress) => (
        <Progress percent={progress} size="small" status={progress === 100 ? 'success' : 'active'} />
      )
    },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => navigate(`/scan/tasks/${record.id}`)}>
          查看
        </Button>
      )
    }
  ]

  const handleQuickScan = async () => {
    if (!quickScanTarget.trim()) {
      message.warning('请输入扫描目标')
      return
    }
    
    // 验证目标格式
    const target = quickScanTarget.trim()
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/
    const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$/;
    
    if (!ipv4Regex.test(target) && !domainRegex.test(target) && !cidrRegex.test(target)) {
      message.warning('目标格式不正确，请输入有效的IP地址、域名或CIDR')
      return
    }
    
    setScanLoading(true)
    try {
      // 创建任务
      const taskData = {
        name: `快捷扫描-${target}-${new Date().toLocaleString()}`,
        target: target,
        scan_type: quickScanType
      }
      const task = await api.createTask(taskData)
      
      // 启动任务
      await api.startTask(task.id)
      
      message.success('扫描任务已启动')
      setQuickScanTarget('')
      
      // 刷新数据并跳转到任务列表
      loadDashboardData()
      navigate('/scan/tasks')
    } catch (error) {
      message.error('启动扫描失败: ' + (error.message || '未知错误'))
    } finally {
      setScanLoading(false)
    }
  }

  return (
    <div className="dashboard">
      {/* 统计卡片 */}
      <Row gutter={[16, 16]} className="stat-row">
        {statCards.map((stat, index) => (
          <Col xs={24} sm={12} lg={6} key={index}>
            <Card className={`stat-card stat-card-${stat.color}`} bordered={false} onClick={stat.onClick} hoverable>
              <div className="stat-card-inner">
                <div className={`stat-card-icon ${stat.color}`}>{stat.icon}</div>
                <div className="stat-card-content">
                  <div className="stat-card-value">
                    {loading ? '-' : stat.value}
                    {stat.suffix && <span className="stat-card-suffix">{stat.suffix}</span>}
                  </div>
                  <div className="stat-card-label">{stat.title}</div>
                </div>
              </div>
            </Card>
          </Col>
        ))}
      </Row>

      {/* 快捷扫描 & 漏洞分布 */}
      <Row gutter={[16, 16]} className="main-row">
        <Col xs={24} lg={10}>
          <Card className="content-card quick-scan-card" bordered={false}>
            <div className="content-card-title">
              <SearchOutlined style={{ marginRight: 8, color: '#1677FF' }} />
              快捷漏洞扫描
            </div>
            <div className="quick-scan-form">
              <Input.Group compact style={{ marginBottom: 12, display: 'flex' }}>
                <Select defaultValue="domain" style={{ width: 120 }}>
                  <Select.Option value="domain">域名</Select.Option>
                  <Select.Option value="ip">IP</Select.Option>
                  <Select.Option value="cidr">CIDR</Select.Option>
                </Select>
                <Input style={{ flex: 1 }} placeholder="请输入目标，如: example.com" size="large" value={quickScanTarget} onChange={(e) => setQuickScanTarget(e.target.value)} onPressEnter={handleQuickScan} />
              </Input.Group>
              <Select value={quickScanType} onChange={setQuickScanType} size="large" style={{ marginBottom: 16, width: '100%' }}>
                <Select.Option value="asset">资产发现</Select.Option>
                <Select.Option value="vuln">漏洞扫描</Select.Option>
                <Select.Option value="full">全面扫描</Select.Option>
              </Select>
              <Space style={{ width: '100%' }}>
                <Button type="primary" icon={<PlayCircleOutlined />} size="large" onClick={handleQuickScan} loading={scanLoading} style={{ flex: 1 }}>
                  开始扫描
                </Button>
                <Button icon={<HistoryOutlined />} size="large" onClick={() => navigate('/scan/tasks')}>
                  历史记录
                </Button>
              </Space>
            </div>
          </Card>
        </Col>

        <Col xs={24} lg={14}>
          <Card className="content-card" bordered={false} title={
            <span><SafetyOutlined style={{ marginRight: 8, color: '#FF8C00' }} />漏洞分布统计</span>
          } extra={<Button type="link" icon={<SyncOutlined />} onClick={handleRefresh}>刷新</Button>}>
            {initialized && <ReactECharts option={vulnChartOption} style={{ height: 240 }} notMerge={true} />}
          </Card>
        </Col>
      </Row>

      {/* 最近任务 */}
      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card className="content-card" bordered={false} title={
            <span><HistoryOutlined style={{ marginRight: 8, color: '#1677FF' }} />最近扫描任务</span>
          } extra={
            <Button type="link" onClick={() => navigate('/scan/tasks')}>查看全部 <RightOutlined /></Button>
          }>
            <Table columns={taskColumns} dataSource={recentTasks} rowKey="id" pagination={false} loading={loading} size="middle" />
          </Card>
        </Col>
      </Row>
    </div>
  )
}

export default Dashboard
