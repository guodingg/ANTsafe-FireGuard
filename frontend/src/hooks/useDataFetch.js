/**
 * 数据获取Hook - 支持缓存和预加载
 */
import { useState, useEffect, useCallback } from 'react'
import useDataCache, { cacheKeys } from '../store/dataCache'

export const useDataFetch = (key, fetchFn, options = {}) => {
  const { skip = false, cacheTime = 5 * 60 * 1000 } = options
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastFetch, setLastFetch] = useState(0)
  
  const getCache = useDataCache((state) => state.getCache)
  const setCache = useDataCache((state) => state.setCache)

  const fetchData = useCallback(async (force = false) => {
    if (skip) return
    
    // 检查缓存
    const cached = getCache(key)
    const now = Date.now()
    
    if (!force && cached && now - lastFetch < cacheTime) {
      setData(cached)
      setLoading(false)
      return
    }
    
    setLoading(true)
    setError(null)
    
    try {
      const result = await fetchFn()
      setData(result)
      setCache(key, result)
      setLastFetch(now)
    } catch (e) {
      setError(e)
      console.error('数据获取失败:', e)
    } finally {
      setLoading(false)
    }
  }, [key, fetchFn, skip, cacheTime, getCache, setCache, lastFetch])

  const refresh = useCallback(() => {
    fetchData(true)
  }, [fetchData])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  return { data, loading, error, refresh }
}

// 预加载所有关键数据
export const preloadAllData = async (api) => {
  const setCache = useDataCache.getState().setCache
  
  try {
    // 并行预加载
    const [stats, tasks, assets, vulns] = await Promise.all([
      api.getStats().catch(() => null),
      api.getTasks().catch(() => null),
      api.getAssets().catch(() => null),
      api.getVulns().catch(() => null),
    ])
    
    if (stats) setCache(cacheKeys.stats(), stats)
    if (tasks) setCache(cacheKeys.tasks(), tasks)
    if (assets) setCache(cacheKeys.assets(), assets)
    if (vulns) setCache(cacheKeys.vulns(), vulns)
    
    console.log('[预加载] 数据已缓存')
  } catch (e) {
    console.error('[预加载] 失败:', e)
  }
}

export default useDataFetch
