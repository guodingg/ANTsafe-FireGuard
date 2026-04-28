/**
 * API 服务 - 连接后端
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

class APIService {
  constructor() {
    this.baseURL = API_BASE_URL
    this.token = localStorage.getItem('token')
  }

  setToken(token) {
    this.token = token
    if (token) {
      localStorage.setItem('token', token)
    } else {
      localStorage.removeItem('token')
    }
  }

  async request(path, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    }

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`
    }

    const response = await fetch(`${this.baseURL}${path}`, {
      ...options,
      headers
    })

    if (response.status === 401) {
      this.setToken(null)
      window.location.href = '/login'
      throw new Error('认证过期')
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: '请求失败' }))
      throw new Error(error.detail || '请求失败')
    }

    return response.json()
  }

  // Auth
  async login(username, password) {
    const formData = new URLSearchParams()
    formData.append('username', username)
    formData.append('password', password)

    const response = await fetch(`${this.baseURL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: formData
    })

    if (!response.ok) {
      throw new Error('用户名或密码错误')
    }

    const data = await response.json()
    this.setToken(data.access_token)
    return data
  }

  async getMe() {
    return this.request('/auth/me')
  }

  async logout() {
    this.setToken(null)
  }

  // AI助手
  async chat(message, context = null) {
    return this.request('/ai/assistant/chat', {
      method: 'POST',
      body: JSON.stringify({ message, context })
    })
  }

  async getAssistantHistory(limit = 50) {
    return this.request(`/ai/assistant/history?limit=${limit}`)
  }

  async clearAssistantHistory() {
    return this.request('/ai/assistant/history', { method: 'DELETE' })
  }

  async getAssistantSuggestions(type = 'general') {
    return this.request(`/ai/assistant/suggestions?type=${type}`)
  }

  // Dashboard
  async getDashboardStats() {
    return this.request('/dashboard/stats')
  }

  async getScanTrend(days = 7) {
    return this.request(`/dashboard/trend?days=${days}`)
  }

  // Tasks
  async getTasks(params = {}) {
    const query = new URLSearchParams(params)
    return this.request(`/scan/tasks/?${query}`)
  }

  async getTask(id) {
    return this.request(`/scan/tasks/${id}`)
  }

  async createTask(data) {
    return this.request('/scan/tasks/', {
      method: 'POST',
      body: JSON.stringify(data)
    })
  }

  async startTask(id) {
    return this.request(`/scan/tasks/${id}/start`, { method: 'POST' })
  }

  async pauseTask(id) {
    return this.request(`/scan/tasks/${id}/pause`, { method: 'POST' })
  }

  async deleteTask(id) {
    return this.request(`/scan/tasks/${id}`, { method: 'DELETE' })
  }

  async getTaskProgress(id) {
    return this.request(`/scan/tasks/${id}/progress`)
  }

  // Assets
  async getAssets(params = {}) {
    const query = new URLSearchParams(params)
    return this.request(`/assets/?${query}`)
  }

  async getAssetStats() {
    return this.request('/assets/stats/summary')
  }

  // Vulns
  async getVulns(params = {}) {
    const query = new URLSearchParams(params)
    return this.request(`/vulns/?${query}`)
  }

  async verifyVuln(id) {
    return this.request(`/vulns/${id}/verify`, { method: 'PUT' })
  }

  async fixVuln(id) {
    return this.request(`/vulns/${id}/fix`, { method: 'PUT' })
  }

  async markFalsePositive(id) {
    return this.request(`/vulns/${id}/false-positive`, { method: 'PUT' })
  }

  // POC
  async getPOCs(params = {}) {
    const query = new URLSearchParams(params)
    return this.request(`/pocs/?${query}`)
  }

  async getPOCDetail(pocId) {
    return this.request(`/pocs/${pocId}`)
  }

  async importPOCYaml(file) {
    const formData = new FormData()
    formData.append('file', file)
    return this.request('/pocs/import/yaml', {
      method: 'POST',
      body: formData
    })
  }

  async importPOCZip(file) {
    const formData = new FormData()
    formData.append('file', file)
    return this.request('/pocs/import/zip', {
      method: 'POST',
      body: formData
    })
  }

  async deletePOC(pocId) {
    return this.request(`/pocs/${pocId}`, { method: 'DELETE' })
  }

  async testPOC(pocId, target) {
    return this.request(`/pocs/test/${pocId}?target=${encodeURIComponent(target)}`, { method: 'POST' })
  }

  async aiGeneratePOC(description, target) {
    return this.request('/ai/assistant/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: `请根据以下漏洞描述生成一个Nuclei YAML格式的POC检测脚本：\n${description}\n\n目标：${target}`,
        type: 'poc'
      })
    })
  }

  // Reports
  async getReports(params = {}) {
    const query = new URLSearchParams(params)
    return this.request(`/reports/?${query}`)
  }

  async getReport(reportId) {
    return this.request(`/reports/${reportId}`)
  }

  async generateReport(taskId, type = 'markdown') {
    return this.request(`/reports/generate?task_id=${taskId}&report_type=${type}`, {
      method: 'POST'
    })
  }

  async deleteReport(reportId) {
    return this.request(`/reports/${reportId}`, { method: 'DELETE' })
  }

  async downloadReport(reportId) {
    const token = localStorage.getItem('token')
    const response = await fetch(`${this.baseURL}/reports/${reportId}/download`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    if (!response.ok) throw new Error('下载失败')
    return response.blob()
  }

  // Logs
  async getLogs(params = {}) {
    const query = new URLSearchParams(params)
    return this.request(`/logs/?${query}`)
  }

  // AI
  async analyzeVulnerability(vulnData) {
    return this.request('/ai/analyze/vulnerability', {
      method: 'POST',
      body: JSON.stringify(vulnData)
    })
  }

  async generatePOC(vulnDescription, target) {
    return this.request('/ai/generate/poc', {
      method: 'POST',
      body: JSON.stringify({ vuln_description: vulnDescription, target })
    })
  }

  // 自定义字典
  async getDicts(params = {}) {
    const query = new URLSearchParams(params)
    return this.request(`/dicts/?${query}`)
  }

  async getDict(dictId) {
    return this.request(`/dicts/${dictId}`)
  }

  async createDict(data) {
    return this.request('/dicts/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
  }

  async updateDict(dictId, data) {
    return this.request(`/dicts/${dictId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
  }

  async deleteDict(dictId) {
    return this.request(`/dicts/${dictId}`, { method: 'DELETE' })
  }

  async importDictTxt(file, dictType = 'custom') {
    const formData = new FormData()
    formData.append('file', file)
    formData.append('dict_type', dictType)
    return this.request('/dicts/import/txt', {
      method: 'POST',
      body: formData
    })
  }

  async loadPresetDicts() {
    return this.request('/dicts/preset', { method: 'POST' })
  }

  async getDict(id) {
    return this.request(`/dicts/${id}`)
  }

  async createDict(data) {
    return this.request('/dicts/', {
      method: 'POST',
      body: JSON.stringify(data)
    })
  }

  async updateDict(id, data) {
    return this.request(`/dicts/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    })
  }

  async deleteDict(id) {
    return this.request(`/dicts/${id}`, { method: 'DELETE' })
  }

  async importDictTxt(file, dictType) {
    const formData = new FormData()
    formData.append('file', file)
    formData.append('dict_type', dictType)
    
    const response = await fetch(`${this.baseURL}/dicts/import/txt`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`
      },
      body: formData
    })
    return response.json()
  }

  // Users
  async getUsers() {
    return this.request('/users/')
  }

  async createUser(data) {
    return this.request('/users/', {
      method: 'POST',
      body: JSON.stringify(data)
    })
  }

  async updateUser(id, data) {
    return this.request(`/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    })
  }

  async deleteUser(id) {
    return this.request(`/users/${id}`, { method: 'DELETE' })
  }

  async changePassword(userId, oldPassword, newPassword) {
    return this.request(`/users/${userId}/password`, {
      method: 'PUT',
      body: JSON.stringify({
        old_password: oldPassword,
        new_password: newPassword
      })
    })
  }

  // 规则库统计
  async getRuleStats() {
    return this.request('/rules/stats')
  }

  // 在线更新规则库
  async updateRulesOnline() {
    return this.request('/rules/update/online', { method: 'POST' })
  }

  // 检查规则更新
  async checkRuleUpdates() {
    return this.request('/rules/check')
  }

  // 离线更新规则库
  async updateRulesOffline(file) {
    const formData = new FormData()
    formData.append('file', file)
    
    const response = await fetch(`${this.baseURL}/rules/update/offline`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`
      },
      body: formData
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: '上传失败' }))
      throw new Error(error.detail || '上传失败')
    }
    
    return response.json()
  }

  // Nuclei模板统计
  async getNucleiStats() {
    return this.request('/nuclei/stats')
  }

  // Nuclei模板在线更新
  async updateNucleiOnline() {
    return this.request('/nuclei/templates/update', { method: 'POST' })
  }

  // Nuclei模板离线更新
  async updateNucleiOffline(file) {
    const formData = new FormData()
    formData.append('file', file)
    
    const response = await fetch(`${this.baseURL}/nuclei/templates/update/offline`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`
      },
      body: formData
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: '上传失败' }))
      throw new Error(error.detail || '上传失败')
    }
    
    return response.json()
  }

  // Xray POC
  async getXrayStats() {
    return this.request('/xray/stats')
  }

  async updateXrayOnline() {
    return this.request('/xray/update', { method: 'POST' })
  }

  async updateXrayOffline(file) {
    const formData = new FormData()
    formData.append('file', file)
    
    const response = await fetch(`${this.baseURL}/xray/update/offline`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`
      },
      body: formData
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: '上传失败' }))
      throw new Error(error.detail || '上传失败')
    }
    
    return response.json()
  }

  // 漏洞情报
  async getVulnIntel(params = {}) {
    return this.request('/vuln-intel/', params)
  }

  async getVulnIntelSources() {
    return this.request('/vuln-intel/sources')
  }

  async getLatestVulns(limit = 10) {
    return this.request('/vuln-intel/latest', { limit })
  }

  // ==================== DNSlog 盲打查询 ====================

  // DNSlog 查询（检查某个 hash 是否触发）
  async dnslogQuery(hash, dnslogUrl) {
    return this.request('/tools/dnslog/query', {
      method: 'POST',
      body: JSON.stringify({ hash, dnslog_url: dnslogUrl })
    })
  }

  // DNSlog Hash → 追溯是哪个 HTTP 请求触发了 DNSlog
  async dnslogLookup(hash) {
    return this.request(`/tools/dnslog/lookup?hash=${encodeURIComponent(hash)}`)
  }
}

export const api = new APIService()
export default api
