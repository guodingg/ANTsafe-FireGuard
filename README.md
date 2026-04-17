# 蚂蚁安全风险评估系统 (ANTsafe System)

## 产品介绍

蚂蚁安全风险评估系统是一款具备AI能力的综合性网络安全评估平台，融合资产发现、漏洞扫描、威胁情报分析与自动化渗透测试。

## 系统功能

- **首页/数据大屏** - 系统态势总览，快速扫描入口
- **扫描任务** - 创建、管理扫描任务，支持多种扫描类型
- **资产管理** - 主机、端口、服务、产品识别
- **漏洞管理** - 漏洞列表、验证、修复跟踪
- **POC管理** - POC库管理，支持自定义导入和AI生成
- **报告管理** - 报告生成与导出
- **日志审计** - 完整的操作审计
- **系统设置** - AI配置、规则更新、安全设置
- **用户管理** - 用户与权限管理

## 技术栈

### 前端
- React 18 + Vite 5
- Ant Design 5
- ECharts 5
- React Router 6
- Zustand

### 后端
- Python 3.8+ / FastAPI
- PostgreSQL / SQLite
- Redis
- JWT认证

## 快速开始

### 前端运行

```bash
cd frontend
npm install
npm run dev
```

### 后端运行

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

## 版权信息

© 蚂蚁安全 www.mayisafe.cn 版权所有
