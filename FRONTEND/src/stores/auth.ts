import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'

interface LoginCredentials {
  username: string
  password: string
}

interface RegisterData {
  username: string
  email: string
  password: string
}

export const useAuthStore = defineStore('auth', () => {
  const isAuthenticated = ref(false)
  const loading = ref(false)
  const error = ref<string | null>(null)

  const baseURL = '/api'  // 使用Vite代理

  const login = async (credentials: LoginCredentials) => {
    loading.value = true
    error.value = null

    try {
      const response = await axios.post(`${baseURL}/auth/login`, credentials)
      const { user, token } = response.data

      // 存储认证信息到localStorage
      localStorage.setItem('auth_token', token)
      localStorage.setItem('user_data', JSON.stringify(user))

      isAuthenticated.value = true
      return { user, token }
    } catch (err: any) {
      error.value = err.response?.data?.error || err.response?.data?.message || 'Login failed'
      console.error('Login error:', err.response?.data)
      throw err
    } finally {
      loading.value = false
    }
  }

  const register = async (data: RegisterData) => {
    loading.value = true
    error.value = null

    try {
      console.log('Registering user:', data)
      console.log('Request URL:', `${baseURL}/auth/register`)

      const response = await axios.post(`${baseURL}/auth/register`, data)
      console.log('Registration successful:', response.data)
      return response.data
    } catch (err: any) {
      console.error('Registration error:', err)
      console.error('Error response:', err.response)
      console.error('Error data:', err.response?.data)

      error.value = err.response?.data?.error || err.response?.data?.message || 'Registration failed'
      throw err
    } finally {
      loading.value = false
    }
  }

  const logout = async () => {
    try {
      const token = localStorage.getItem('auth_token')
      if (token) {
        await axios.post(`${baseURL}/auth/logout`, {}, {
          headers: { Authorization: `Bearer ${token}` }
        })
      }
    } catch (err) {
      console.error('Logout error:', err)
    } finally {
      isAuthenticated.value = false
      localStorage.removeItem('auth_token')
      localStorage.removeItem('user_data')
    }
  }

  const checkAuth = () => {
    const token = localStorage.getItem('auth_token')
    const userData = localStorage.getItem('user_data')

    if (token && userData) {
      isAuthenticated.value = true
      return true
    }
    return false
  }

  return {
    isAuthenticated,
    loading,
    error,
    login,
    register,
    logout,
    checkAuth
  }
})
