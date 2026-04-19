/**
 * 数据缓存管理 - 减少重复请求
 */
import { create } from 'zustand'

// 缓存有效期（5分钟）
const CACHE_TTL = 5 * 60 * 1000

const useDataCache = create((set, get) => ({
  cache: {},
  lastFetch: {},

  // 获取缓存
  getCache: (key) => {
    const item = get().cache[key]
    if (!item) return null
    
    const now = Date.now()
    if (now - item.timestamp > CACHE_TTL) {
      // 缓存过期
      delete get().cache[key]
      return null
    }
    return item.data
  },

  // 设置缓存
  setCache: (key, data) => {
    set((state) => ({
      cache: {
        ...state.cache,
        [key]: {
          data,
          timestamp: Date.now()
        }
      }
    }))
  },

  // 清除缓存
  clearCache: (key) => {
    if (key) {
      delete get().cache[key]
    } else {
      set({ cache: {} })
    }
  },

  // 预加载数据
  preloadData: async (key, fetchFn) => {
    // 如果已有缓存，直接返回
    const cached = get().getCache(key)
    if (cached) return cached
    
    // 否则请求数据
    try {
      const data = await fetchFn()
      get().setCache(key, data)
      return data
    } catch (e) {
      console.error('预加载失败:', e)
      return null
    }
  }
}))

// 缓存key生成器
export const cacheKeys = {
  stats: () => 'dashboard_stats',
  tasks: () => 'scan_tasks',
  assets: () => 'assets_list',
  vulns: () => 'vulns_list',
  taskDetail: (id) => `task_${id}`,
  assetDetail: (id) => `asset_${id}`,
  vulnDetail: (id) => `vuln_${id}`,
  logs: () => 'audit_logs',
  settings: () => 'system_settings',
}

export default useDataCache
