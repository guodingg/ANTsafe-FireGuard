"""
AI助手API - 实时对话功能
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

from secscan.models.user import User
from secscan.api.v1.auth import get_current_user
from secscan.ai.manager import AIManager

router = APIRouter(prefix="/ai/assistant", tags=["AI助手"])

class Message(BaseModel):
    """对话消息"""
    role: str  # user / assistant / system
    content: str
    timestamp: Optional[datetime] = None

class ChatRequest(BaseModel):
    """聊天请求"""
    message: str
    context: Optional[Dict[str, Any]] = None  # 可选上下文：任务ID、漏洞ID等

class ChatResponse(BaseModel):
    """聊天响应"""
    reply: str
    suggestions: List[str] = []
    context_used: Optional[Dict[str, Any]] = None

# 对话历史（生产环境应该用Redis存储）
chat_histories: Dict[int, List[Message]] = {}

# 系统提示词
SYSTEM_PROMPT = """你是一个专业的网络安全助手，隶属于蚂蚁安全风险评估系统。

你可以帮助用户：
1. 分析漏洞和CVE
2. 生成漏洞检测POC
3. 解释安全概念和术语
4. 提供修复建议
5. 分析扫描结果
6. 解答安全相关问题

请用中文回答，保持专业但易懂。"""

@router.post("/chat", response_model=ChatResponse)
async def chat(
    data: ChatRequest,
    current_user: User = Depends(get_current_user)
):
    """发送消息并获取AI回复"""
    user_id = current_user.id
    
    # 获取或创建对话历史
    if user_id not in chat_histories:
        chat_histories[user_id] = [
            Message(role="system", content=SYSTEM_PROMPT)
        ]
    
    # 添加用户消息
    chat_histories[user_id].append(
        Message(role="user", content=data.message, timestamp=datetime.utcnow())
    )
    
    # 构建消息列表
    messages = [
        {"role": m.role, "content": m.content}
        for m in chat_histories[user_id][-20:]  # 保留最近20条
    ]
    
    # 添加上下文
    context_info = ""
    if data.context:
        if data.context.get("task_id"):
            context_info += f"\n当前任务ID: {data.context['task_id']}"
        if data.context.get("vuln_id"):
            context_info += f"\n当前漏洞ID: {data.context['vuln_id']}"
        if data.context.get("target"):
            context_info += f"\n扫描目标: {data.context['target']}"
    
    if context_info:
        messages.append({
            "role": "system",
            "content": f"当前上下文信息：{context_info}"
        })
    
    try:
        # 调用AI（使用Kimi）
        from secscan.ai.kimi import KimiProvider
        provider = KimiProvider()
        
        # 构造完整消息
        full_messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        if context_info:
            full_messages.append({"role": "system", "content": f"当前上下文：{context_info}"})
        full_messages.extend(messages[-18:])  # 保留上下文
        
        reply = await provider._call_api(full_messages)
        
        # 添加助手回复
        chat_histories[user_id].append(
            Message(role="assistant", content=reply, timestamp=datetime.utcnow())
        )
        
        # 生成建议
        suggestions = await _generate_suggestions(data.message, reply)
        
        return ChatResponse(
            reply=reply,
            suggestions=suggestions,
            context_used=data.context
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI回复失败: {str(e)}")

@router.get("/history")
async def get_history(
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_user)
):
    """获取对话历史"""
    user_id = current_user.id
    history = chat_histories.get(user_id, [])
    
    return {
        "messages": [
            {
                "role": m.role,
                "content": m.content,
                "timestamp": m.timestamp.isoformat() if m.timestamp else None
            }
            for m in history[-limit:]
        ],
        "total": len(history)
    }

@router.delete("/history")
async def clear_history(current_user: User = Depends(get_current_user)):
    """清除对话历史"""
    user_id = current_user.id
    if user_id in chat_histories:
        # 保留system消息
        chat_histories[user_id] = [
            Message(role="system", content=SYSTEM_PROMPT)
        ]
    return {"message": "对话历史已清除"}

@router.get("/suggestions")
async def get_suggestions(
    type: str = Query("general", regex="^(general|scan|vuln|poc|report)$"),
    current_user: User = Depends(get_current_user)
):
    """获取快速建议"""
    suggestions_map = {
        "general": [
            "帮我分析一下这个漏洞",
            "什么是SQL注入？",
            "如何加强服务器安全？",
            "解释一下XSS攻击"
        ],
        "scan": [
            "如何发现内网资产？",
            "扫描很慢怎么办？",
            "目标发现很多端口，正常吗？",
            "如何提高扫描效率？"
        ],
        "vuln": [
            "高危漏洞如何快速修复？",
            "已验证的漏洞怎么处理？",
            "误报如何标记？",
            "漏洞评级标准是什么？"
        ],
        "poc": [
            "如何编写POC？",
            "Nuclei模板怎么写？",
            "现有POC如何使用？",
            "AI可以帮我生成POC吗？"
        ],
        "report": [
            "如何生成完整报告？",
            "报告包含哪些内容？",
            "PDF和Word报告区别？",
            "报告如何分享给团队？"
        ]
    }
    
    return {"suggestions": suggestions_map.get(type, suggestions_map["general"])}

async def _generate_suggestions(user_message: str, reply: str) -> List[str]:
    """根据对话内容生成建议"""
    suggestions = []
    
    msg_lower = user_message.lower()
    
    if any(k in msg_lower for k in ["漏洞", "vuln", "cve"]):
        suggestions = ["查看漏洞详情", "验证漏洞", "生成修复建议"]
    elif any(k in msg_lower for k in ["扫描", "scan", "目标"]):
        suggestions = ["开始新扫描", "查看扫描进度", "优化扫描策略"]
    elif any(k in msg_lower for k in ["poc", "验证", "检测"]):
        suggestions = ["生成POC", "测试现有POC", "导入自定义POC"]
    elif any(k in msg_lower for k in ["报告", "report", "导出"]):
        suggestions = ["生成报告", "选择报告格式", "下载报告"]
    else:
        suggestions = ["继续提问", "获取安全建议", "分析扫描结果"]
    
    return suggestions[:3]
