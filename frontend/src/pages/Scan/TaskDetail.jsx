import { Card, Result, Button } from 'antd'
import { useNavigate } from 'react-router-dom'

const TaskDetail = () => {
  const navigate = useNavigate()

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">任务详情</h1>
      </div>
      <Card className="content-card" bordered={false}>
        <Result
          title="功能开发中"
          subTitle="任务详情功能即将上线，敬请期待。"
          extra={<Button type="primary" onClick={() => navigate('/scan/tasks')}>返回列表</Button>}
        />
      </Card>
    </div>
  )
}

export default TaskDetail
