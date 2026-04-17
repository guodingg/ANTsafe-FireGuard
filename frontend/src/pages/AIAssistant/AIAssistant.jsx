import { useState, useRef, useEffect } from 'react'
import { Card, Input, Button, List, Avatar, Spin, Space, Tag, Divider } from 'antd'
import { SendOutlined, RobotOutlined, UserOutlined, BulbOutlined, ReloadOutlined, DeleteOutlined } from '@ant-design/icons'
import api from '../../services/api'
import './AIAssistant.css'

const { TextArea } = Input

const AIAssistant = () => {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [suggestions, setSuggestions] = useState([])
  const messagesEndRef = useRef(null)
  const inputRef = useRef(null)

  useEffect(() => {
    loadHistory()
    loadSuggestions()
  }, [])

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const loadHistory = async () => {
    try {
      const data = await api.request('/ai/assistant/history')
      if (data.messages) {
        // 过滤掉system消息显示
        const filtered = data.messages.filter(m => m.role !== 'system')
        setMessages(filtered)
      }
    } catch (error) {
      console.error('加载历史失败')
    }
  }

  const loadSuggestions = async () => {
    try {
      const data = await api.request('/ai/assistant/suggestions?type=general')
      setSuggestions(data.suggestions || [])
    } catch (error) {
      console.error('加载建议失败')
    }
  }

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  const handleSend = async () => {
    if (!input.trim() || loading) return

    const userMessage = { role: 'user', content: input.trim() }
    setMessages(prev => [...prev, userMessage])
    setInput('')
    setLoading(true)

    try {
      const data = await api.request('/ai/assistant/chat', {
        method: 'POST',
        body: JSON.stringify({ message: userMessage.content })
      })

      const assistantMessage = { role: 'assistant', content: data.reply }
      setMessages(prev => [...prev, assistantMessage])

      if (data.suggestions) {
        setSuggestions(data.suggestions)
      }
    } catch (error) {
      const errorMessage = { role: 'assistant', content: '抱歉，AI助手暂时无法回复，请稍后重试。' }
      setMessages(prev => [...prev, errorMessage])
    } finally {
      setLoading(false)
    }
  }

  const handleClearHistory = async () => {
    try {
      await api.request('/ai/assistant/history', { method: 'DELETE' })
      setMessages([])
    } catch (error) {
      console.error('清除历史失败')
    }
  }

  const handleSuggestionClick = (suggestion) => {
    setInput(suggestion)
    inputRef.current?.focus()
  }

  return (
    <div className="ai-assistant">
      <div className="page-header">
        <h1 className="page-title"><RobotOutlined style={{ marginRight: 8 }} />AI安全助手</h1>
        <Button icon={<DeleteOutlined />} onClick={handleClearHistory}>清除对话</Button>
      </div>

      <Card className="chat-card" bordered={false}>
        {/* 消息列表 */}
        <div className="messages-container">
          {messages.length === 0 && (
            <div className="welcome-message">
              <RobotOutlined style={{ fontSize: 48, color: '#1677FF', marginBottom: 16 }} />
              <h2>欢迎使用 AI 安全助手</h2>
              <p>我可以帮助你：</p>
              <ul>
                <li>分析漏洞和CVE</li>
                <li>生成漏洞检测POC</li>
                <li>解释安全概念</li>
                <li>提供修复建议</li>
              </ul>
            </div>
          )}

          {messages.map((msg, index) => (
            <div key={index} className={`message ${msg.role}`}>
              <Avatar 
                icon={msg.role === 'user' ? <UserOutlined /> : <RobotOutlined />} 
                className={`avatar-${msg.role}`}
              />
              <div className="message-content">
                <div className="message-bubble">
                  {msg.content}
                </div>
                <div className="message-time">
                  {new Date().toLocaleTimeString()}
                </div>
              </div>
            </div>
          ))}

          {loading && (
            <div className="message assistant">
              <Avatar icon={<RobotOutlined />} className="avatar-assistant" />
              <div className="message-content">
                <div className="message-bubble loading">
                  <Spin size="small" /> AI正在思考...
                </div>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* 快捷建议 */}
        {messages.length === 0 && suggestions.length > 0 && (
          <div className="suggestions">
            <div className="suggestions-title">
              <BulbOutlined /> 快捷提问
            </div>
            <Space wrap>
              {suggestions.map((s, i) => (
                <Tag 
                  key={i} 
                  className="suggestion-tag"
                  onClick={() => handleSuggestionClick(s)}
                >
                  {s}
                </Tag>
              ))}
            </Space>
          </div>
        )}

        <Divider style={{ margin: '16px 0' }} />

        {/* 输入框 */}
        <div className="input-container">
          <TextArea
            ref={inputRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="输入你的问题，按Enter发送..."
            autoSize={{ minRows: 1, maxRows: 4 }}
            onPressEnter={(e) => {
              if (!e.shiftKey) {
                e.preventDefault()
                handleSend()
              }
            }}
          />
          <Button 
            type="primary" 
            icon={<SendOutlined />} 
            onClick={handleSend}
            loading={loading}
            disabled={!input.trim()}
          >
            发送
          </Button>
        </div>
      </Card>
    </div>
  )
}

export default AIAssistant
