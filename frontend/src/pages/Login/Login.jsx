import React, { useState } from 'react';
import { Form, Input, Button, message, Checkbox } from 'antd';
import { UserOutlined, LockOutlined, SafetyOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import useAuthStore from '../../store/authStore';
import './Login.css';

const Login = () => {
  const [loading, setLoading] = useState(false);
  const [form] = Form.useForm();
  const navigate = useNavigate();
  const login = useAuthStore((state) => state.login);

  const onFinish = async (values) => {
    setLoading(true);
    try {
      await login(values.username, values.password);
      message.success('登录成功');
      navigate('/');
    } catch (error) {
      message.error(error.message || '用户名或密码错误');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-left">
        <div className="login-left-content">
          <div className="login-logo">
            <img src="/logo.svg" alt="ANTsafe" className="logo-icon" />
            <span className="logo-text">蚂蚁安全</span>
          </div>
          <h1 className="login-title">可信IP资产攻击面管理系统</h1>
          <p className="login-subtitle">Trusted IP Asset Attack Surface Management System</p>
          <div className="login-features">
            <div className="feature-item">
              <SafetyOutlined />
              <span>自动化漏洞检测</span>
            </div>
            <div className="feature-item">
              <SafetyOutlined />
              <span>资产清点与分类</span>
            </div>
            <div className="feature-item">
              <SafetyOutlined />
              <span>威胁情报分析</span>
            </div>
            <div className="feature-item">
              <SafetyOutlined />
              <span>安全风险评估</span>
            </div>
          </div>
        </div>
        <div className="login-left-footer">
          <span>© 2024 蚂蚁安全 www.mayisafe.cn</span>
        </div>
      </div>
      
      <div className="login-right">
        <div className="login-form-container">
          <div className="login-form-header">
            <h2>用户登录</h2>
            <p>欢迎回来，请登录您的账户</p>
          </div>
          
          <Form
            form={form}
            name="login"
            onFinish={onFinish}
            autoComplete="off"
            size="large"
            className="login-form"
          >
            <Form.Item
              name="username"
              rules={[{ required: true, message: '请输入用户名' }]}
            >
              <Input 
                prefix={<UserOutlined style={{ color: '#1890ff' }} />} 
                placeholder="请输入用户名"
              />
            </Form.Item>

            <Form.Item
              name="password"
              rules={[{ required: true, message: '请输入密码' }]}
            >
              <Input.Password 
                prefix={<LockOutlined style={{ color: '#1890ff' }} />} 
                placeholder="请输入密码"
              />
            </Form.Item>

            <Form.Item name="remember" valuePropName="checked">
              <div className="login-options">
                <Checkbox>记住密码</Checkbox>
                <a href="#">忘记密码？</a>
              </div>
            </Form.Item>

            <Form.Item>
              <Button type="primary" htmlType="submit" loading={loading} block className="login-button">
                {loading ? '登录中...' : '立即登录'}
              </Button>
            </Form.Item>
          </Form>
        </div>
      </div>
    </div>
  );
};

export default Login;
