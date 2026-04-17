import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export const useAuthStore = create(
  persist(
    (set, get) => ({
      token: null,
      user: null,
      
      login: async (username, password) => {
        // 模拟登录，实际应该调用API
        if (username === 'admin' && password === 'admin123') {
          const user = {
            id: 1,
            username: 'admin',
            email: 'admin@mayisafe.cn',
            role: 'admin',
            avatar: null
          }
          const token = 'mock-jwt-token-' + Date.now()
          
          set({ token, user })
          return { success: true, user }
        }
        
        return { success: false, message: '用户名或密码错误' }
      },
      
      logout: () => {
        set({ token: null, user: null })
      },
      
      updateUser: (userData) => {
        set({ user: { ...get().user, ...userData } })
      }
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({ token: state.token, user: state.user })
    }
  )
)
