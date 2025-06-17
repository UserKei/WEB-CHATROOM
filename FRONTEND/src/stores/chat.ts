import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { WebSocketManager, type User, type Message } from '@/utils/websocket'
import { useAuthStore } from '@/stores/auth'

export interface AuthUser extends User {
  email: string
  token: string
}

export const useChatStore = defineStore('chat', () => {
  // State
  const currentUser = ref<AuthUser | null>(null)
  const users = ref<User[]>([])
  const messages = ref<Message[]>([])
  const privateMessages = ref<{ [userId: number]: Message[] }>({})
  const blockedUsers = ref<number[]>([])
  const typingUsers = ref<number[]>([])
  const wsManager = ref<WebSocketManager | null>(null)
  const isConnected = ref(false)
  const selectedUserId = ref<number | null>(null) // For private chat
  const authStore = useAuthStore()

  // Computed
  const onlineUsers = computed(() =>
    users.value.filter(user => user.status === 'online')
  )

  const filteredMessages = computed(() =>
    messages.value.filter(message =>
      !blockedUsers.value.includes(message.senderId)
    )
  )

  const privateChat = computed(() => {
    if (!selectedUserId.value) return []
    return privateMessages.value[selectedUserId.value] || []
  })

  const canRevokeMessage = (message: Message) => {
    if (message.senderId !== currentUser.value?.id) return false
    const timeDiff = Date.now() - new Date(message.timestamp).getTime()
    return timeDiff <= 2 * 60 * 1000 // 2 minutes
  }

  // Actions
  const initializeWebSocket = async (serverUrl: string, token: string) => {
    // 如果已经连接，不要重复连接
    if (isConnected.value && wsManager.value) {
      console.log('WebSocket already connected, skipping initialization')
      return
    }

    // 如果WebSocket manager存在但未连接，先清理旧的连接
    if (wsManager.value) {
      console.log('Cleaning up existing WebSocket manager...')
      wsManager.value.disconnect()
      wsManager.value = null
    }

    try {
      console.log('Creating new WebSocket manager...')
      wsManager.value = new WebSocketManager(serverUrl)

      // Set up event listeners
      wsManager.value.on('user_joined', (user: User) => {
        if (!users.value.find(u => u.id === user.id)) {
          users.value.push(user)
        }
      })

      wsManager.value.on('user_left', (userId: number) => {
        users.value = users.value.filter(user => user.id !== userId)
        typingUsers.value = typingUsers.value.filter(id => id !== userId)
      })

      wsManager.value.on('auth_success', (data: { userId: number, username: string }) => {
        console.log('WebSocket authentication successful:', data)
        console.log('Setting isConnected to true')
        isConnected.value = true
      })

      wsManager.value.on('auth_error', (data: { error: string }) => {
        console.error('WebSocket authentication failed:', data.error)
        console.log('Setting isConnected to false due to auth error')
        console.log('Clearing expired token - but NOT auto-redirecting')

        // 认证失败时清理过期的token
        isConnected.value = false
        localStorage.removeItem('auth_token')
        localStorage.removeItem('user_data')
        currentUser.value = null

        // 只清理状态，不强制跳转
        // 让用户手动点击重新登录按钮
      })

      wsManager.value.on('message', (message: Message) => {
        message.canRevoke = canRevokeMessage(message)
        messages.value.push(message)
      })

      wsManager.value.on('private_message', (message: Message) => {
        const userId = message.senderId === currentUser.value?.id
          ? message.targetUserId!
          : message.senderId

        if (!privateMessages.value[userId]) {
          privateMessages.value[userId] = []
        }
        privateMessages.value[userId].push(message)
      })

      wsManager.value.on('user_list', (userList: User[]) => {
        users.value = userList
      })

      wsManager.value.on('status_change', ({ userId, status }: { userId: number, status: string }) => {
        const user = users.value.find(u => u.id === userId)
        if (user) {
          user.status = status as 'online' | 'busy' | 'offline'
        }
      })

      wsManager.value.on('message_revoked', (messageId: number) => {
        const messageIndex = messages.value.findIndex(m => m.id === messageId)
        if (messageIndex !== -1) {
          messages.value.splice(messageIndex, 1)
        }
      })

      wsManager.value.on('typing', ({ userId, isTyping }: { userId: number, isTyping: boolean }) => {
        if (isTyping) {
          if (!typingUsers.value.includes(userId)) {
            typingUsers.value.push(userId)
          }
        } else {
          typingUsers.value = typingUsers.value.filter(id => id !== userId)
        }
      })

      wsManager.value.on('connection_failed', () => {
        console.error('WebSocket connection failed')
        isConnected.value = false
        // 连接失败时只设置状态，不强制跳转
      })

      await wsManager.value.connect(token)
      // isConnected在auth_success事件中设置
    } catch (error) {
      console.error('Failed to initialize WebSocket:', error)
      isConnected.value = false
      // 连接失败时只记录错误，不强制跳转
      throw error
    }
  }

  const sendMessage = (content: string) => {
    console.log('chatStore.sendMessage called with:', content)
    console.log('wsManager.value:', wsManager.value)
    console.log('content.trim():', content.trim())

    if (wsManager.value && content.trim()) {
      console.log('Calling wsManager.sendChatMessage')
      wsManager.value.sendChatMessage(content.trim())
    } else {
      console.log('Cannot send message - wsManager or content issue')
      console.log('wsManager.value exists:', !!wsManager.value)
      console.log('content.trim() exists:', !!content.trim())
    }
  }

  const sendPrivateMessage = (content: string, targetUserId: number) => {
    if (wsManager.value && content.trim()) {
      wsManager.value.sendPrivateMessage(content.trim(), targetUserId)
    }
  }

  const updateStatus = (status: 'online' | 'busy' | 'offline') => {
    if (wsManager.value && currentUser.value) {
      currentUser.value.status = status
      wsManager.value.updateStatus(status)
    }
  }

  const revokeMessage = (messageId: number) => {
    if (wsManager.value) {
      wsManager.value.revokeMessage(messageId)
    }
  }

  const blockUser = (userId: number) => {
    if (!blockedUsers.value.includes(userId)) {
      blockedUsers.value.push(userId)
      wsManager.value?.blockUser(userId)
    }
  }

  const unblockUser = (userId: number) => {
    blockedUsers.value = blockedUsers.value.filter(id => id !== userId)
    wsManager.value?.unblockUser(userId)
  }

  const startTyping = () => {
    wsManager.value?.startTyping()
  }

  const stopTyping = () => {
    wsManager.value?.stopTyping()
  }

  const selectUser = (userId: number | null) => {
    selectedUserId.value = userId
  }

  const logout = () => {
    console.log('ChatStore logout called')

    // 断开WebSocket连接
    if (wsManager.value) {
      console.log('Disconnecting WebSocket...')
      wsManager.value.disconnect()
      wsManager.value = null
    }

    // 清理状态
    currentUser.value = null
    users.value = []
    messages.value = []
    privateMessages.value = {}
    blockedUsers.value = []
    typingUsers.value = []
    isConnected.value = false
    selectedUserId.value = null

    // 清理localStorage
    localStorage.removeItem('auth_token')
    localStorage.removeItem('user_data')
  }

  const setCurrentUser = (user: AuthUser) => {
    currentUser.value = user
    localStorage.setItem('auth_token', user.token)
    localStorage.setItem('user_data', JSON.stringify(user))
  }

  const loadFromStorage = () => {
    const token = localStorage.getItem('auth_token')
    const userData = localStorage.getItem('user_data')

    if (token && userData) {
      try {
        const user = JSON.parse(userData)
        // 确保用户对象包含token
        currentUser.value = { ...user, token }
        console.log('Loaded user from storage:', currentUser.value)
      } catch (error) {
        console.error('Failed to parse stored user data:', error)
        localStorage.removeItem('auth_token')
        localStorage.removeItem('user_data')
      }
    }
  }

  return {
    // State
    currentUser,
    users,
    messages,
    privateMessages,
    blockedUsers,
    typingUsers,
    isConnected,
    selectedUserId,

    // Computed
    onlineUsers,
    filteredMessages,
    privateChat,

    // Actions
    initializeWebSocket,
    sendMessage,
    sendPrivateMessage,
    updateStatus,
    revokeMessage,
    blockUser,
    unblockUser,
    startTyping,
    stopTyping,
    selectUser,
    logout,
    setCurrentUser,
    loadFromStorage,
    canRevokeMessage
  }
})
