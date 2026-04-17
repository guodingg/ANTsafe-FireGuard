import { useState } from 'react'
import { Row, Col, Card, Button, Input, Select, Table, Space, Progress, Tag } from 'antd'
import {
  SearchOutlined,
  PlayCircleOutlined,
  CloudServerOutlined,
  SafetyOutlined,
  CheckCircleOutlined,
  WarningOutlined,
  HistoryOutlined,
  RightOutlined
} from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import ReactECharts from 'echarts-for-react'
import './Dashboard.css'

const { Search } = Input

const Dashboard = () => {
  const navigate = useNavigate()
  const [scanLoading, setScanLoading] = useState(false)

  // 模拟统计数据
  const stats = [
    {
      title: '总扫描任务',
      value: 128,
      icon: <SearchOutlined />,
      color: 'blue',
      key: 'tasks'
    },
    {
      title: '安全主机',
      value: 95,
      icon: <CloudServerOutlined />,
      color: 'green',
      key: 'secure'
    },
    {
      title: '高危漏洞',
      value: 16,
      icon: <WarningOutlined />,
      color: 'orange',
      key: 'critical'
    },
    {
      title: '已修复漏洞',
      value: 86,
      icon: <CheckCircleOutlined />,
      color: 'blue',
      key: 'fixed'
    }
  ]

  // 模拟最近任务
  const recentTasks = [
    { id: 1, name: '内网资产扫描', target: '192.168.1.0/24', status: 'completed', progress: 100, vulns: 12, time: '2024-04-17 10:30' },
    { id: 2, name: 'Web漏洞检测', target: 'example.com', status: 'running', progress: 68, vulns: 5, time: '2024-04-17 14:20' },
    { id: 3, name: '边界扫描', target: '10.0.0.0/8', status: 'pending', progress: 0, vulns: 0, time: '2024-04-17 15:00' },
    { id: 4, name: '数据库审计', target: '192.168.2.10', status: 'completed', progress: 100, vulns: 3, time: '2024-04-16 09:15' }
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
      textStyle: {
        color: '#8C8C8C'
      }
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
        label: {
          show: false
        },
        emphasis: {
          label: {
            show: true,
            fontSize: 14,
            fontWeight: 'bold'
          }
        },
        data: [
          { value: 16, name: '严重' },
          { value: 28, name: '高危' },
          { value: 45, name: '中危' },
          { value: 62, name: '低危' },
          { value: 35, name: '信息' }
        ]
      }
    ]
  }

  // 任务趋势图表配置
  const trendChartOption = {
    tooltip: {
      trigger: 'axis'
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: ['周一', '周二', '周三', '周四', '周五', '周六', '周日'],
      axisLine: {
        lineStyle: { color: '#E8E8E8' }
      },
      axisLabel: {
        color: '#8C8C8C'
      }
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
            type: 'linear',
            x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(22, 119, 255, 0.3)' },
              { offset: 1, color: 'rgba(22, 119, 255, 0.05)' }
            ]
          }
        },
        data: [12, 25, 18, 32, 28, 15, 8]
      }
    ]
  }

  const taskColumns = [
    { title: '任务名称', dataIndex: 'name', key: 'name' },
    { title: '扫描目标', dataIndex: 'target', key: 'target' },
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
      render: (progress, record) => (
        record.status === 'running' ? (
          <Progress percent={progress} size="small" />
        ) : (
          <Progress percent={progress} size="small" status={progress === 100 ? 'success' : 'exception'} />
        )
      )
    },
    { title: '发现漏洞', dataIndex: 'vulns', key: 'vulns', render: (v) => v > 0 ? <span style={{ color: '#FF4D4F' }}>{v}</span> : v },
    { title: '时间', dataIndex: 'time', key: 'time' },
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

  const handleQuickScan = () => {
    setScanLoading(true)
    setTimeout(() => {
      setScanLoading(false)
      message.success('扫描任务已创建')
      navigate('/scan/tasks')
    }, 1500)
  }

  return (
    <div className="dashboard">
      {/* 统计卡片 */}
      <Row gutter={[16, 16]} className="stat-row">
        {stats.map((stat, index) => (
          <Col xs={24} sm={12} lg={6} key={index}>
            <Card className={`stat-card stat-card-${stat.color}`} bordered={false}>
              <div className="stat-card-inner">
                <div className={`stat-card-icon ${stat.color}`}>
                  {stat.icon}
                </div>
                <div className="stat-card-content">
                  <div className="stat-card-value">{stat.value}</div>
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
              <Input.Group compact style={{ marginBottom: 12 }}>
                <Select defaultValue="domain" style={{ width: 100 }}>
                  <Select.Option value="domain">域名</Select.Option>
                  <Select.Option value="ip">IP</Select.Option>
                  <Select.Option value="cidr">CIDR</Select.Option>
                </Select>
                <Input
                  style={{ width: 'calc(100% - 100px)' }}
                  placeholder="请输入目标，如: example.com"
                  size="large"
                />
              </Input.Group>
              <Input.Group compact style={{ marginBottom: 16 }}>
                <Select defaultValue="full" style={{ width: '100%' }}>
                  <Select.Option value="quick">快速扫描</Select.Option>
                  <Select.Option value="full">全面扫描</Select.Option>
                  <Select.Option value="vuln">漏洞扫描</Select.Option>
                  <Select.Option value="custom">自定义</Select.Option>
                </Select>
              </Input.Group>
              <Space style={{ width: '100%' }}>
                <Button
                  type="primary"
                  icon={<PlayCircleOutlined />}
                  size="large"
                  onClick={handleQuickScan}
                  loading={scanLoading}
                  style={{ flex: 1 }}
                >
                  开始扫描
                </Button>
                <Button
                  icon={<HistoryOutlined />}
                  size="large"
                  onClick={() => navigate('/scan/tasks')}
                >
                  历史记录
                </Button>
              </Space>
            </div>
          </Card>
        </Col>

        <Col xs={24} lg={14}>
          <Card className="content-card" bordered={false}>
            <div className="content-card-title">
              <SafetyOutlined style={{ marginRight: 8, color: '#FF8C00' }} />
              漏洞分布统计
            </div>
            <ReactECharts option={vulnChartOption} style={{ height: 240 }} />
          </Card>
        </Col>
      </Row>

      {/* 最近任务 */}
      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card className="content-card" bordered={false}>
            <div className="content-card-title-row">
              <div className="content-card-title">
                <HistoryOutlined style={{ marginRight: 8, color: '#1677FF' }} />
                最近扫描任务
              </div>
              <Button type="link" onClick={() => navigate('/scan/tasks')}>
                查看全部 <RightOutlined />
              </Button>
            </div>
            <Table
              columns={taskColumns}
              dataSource={recentTasks}
              rowKey="id"
              pagination={false}
              size="middle"
            />
          </Card>
        </Col>
      </Row>
    </div>
  )
}

export default Dashboard
