import { create } from 'zustand'
import api from '../services/api'

const useAuthStore = create((set, get) => ({
  user: null,
  token: localStorage.getItem('token'),
  isAuthenticated: !!localStorage.getItem('token'),
  loading: false,

  login: async (username, password) => {
    set({ loading: true })
    try {
      await api.login(username, password)
      const user = await api.getMe()
      set({ 
        user, 
        isAuthenticated: true, 
        loading: false,
        token: localStorage.getItem('token')
      })
      return true
    } catch (error) {
      set({ loading: false })
      throw error
    }
  },

  logout: () => {
    api.logout()
    set({ 
      user: null, 
      isAuthenticated: false,
      token: null 
    })
  },

  checkAuth: async () => {
    const token = localStorage.getItem('token')
    if (!token) {
      set({ isAuthenticated: false })
      return false
    }
    
    try {
      const user = await api.getMe()
      set({ user, isAuthenticated: true })
      return true
    } catch (error) {
      get().logout()
      return false
    }
  },

  setUser: (userData) => set({ user: userData })
}))

export default useAuthStore
