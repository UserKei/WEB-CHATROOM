export interface User {
  id: number
  username: string
  status: 'online' | 'busy' | 'offline'
  avatar?: string
}

export interface Message {
  id: number
  senderId: number
  senderName: string
  content: string
  timestamp: Date
  type: 'text' | 'private'
  targetUserId?: number
  isRead: boolean
  canRevoke: boolean
}

export interface ChatRoom {
  id: number
  name: string
  users: User[]
  messages: Message[]
}

export interface WebSocketMessage {
  type: 'user_joined' | 'user_left' | 'message' | 'private_message' | 'user_list' | 'status_change' | 'message_revoked' | 'typing' | 'block_user' | 'unblock_user'
  data: any
  timestamp: Date
}

export class WebSocketManager {
  private ws: WebSocket | null = null
  private reconnectAttempts = 0
  private maxReconnectAttempts = 5
  private reconnectDelay = 3000
  private listeners: { [key: string]: Function[] } = {}

  constructor(private url: string) {}

  connect(token: string): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        // 构造WebSocket URL - 如果是相对路径，转换为ws://协议
        let wsUrl = this.url
        if (wsUrl.startsWith('/')) {
          const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
          wsUrl = `${protocol}//${window.location.host}${wsUrl}`
        }

        this.ws = new WebSocket(`${wsUrl}?token=${token}`)

        this.ws.onopen = () => {
          console.log('WebSocket connected')
          this.reconnectAttempts = 0
          resolve()
        }

        this.ws.onmessage = (event) => {
          try {
            const message: WebSocketMessage = JSON.parse(event.data)
            this.emit(message.type, message.data)
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error)
          }
        }

        this.ws.onclose = (event) => {
          console.log('WebSocket disconnected:', event.code, event.reason)
          this.handleReconnect()
        }

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error)
          reject(error)
        }
      } catch (error) {
        reject(error)
      }
    })
  }

  private handleReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++
      console.log(`Attempting to reconnect... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`)

      setTimeout(() => {
        this.connect(localStorage.getItem('auth_token') || '')
          .catch(error => {
            console.error('Reconnection failed:', error)
          })
      }, this.reconnectDelay)
    } else {
      console.error('Max reconnection attempts reached')
      this.emit('connection_failed', null)
    }
  }

  sendMessage(message: Partial<WebSocketMessage>) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        ...message,
        timestamp: new Date()
      }))
    } else {
      console.error('WebSocket is not connected')
    }
  }

  // Event system
  on(event: string, callback: Function) {
    if (!this.listeners[event]) {
      this.listeners[event] = []
    }
    this.listeners[event].push(callback)
  }

  off(event: string, callback: Function) {
    if (this.listeners[event]) {
      this.listeners[event] = this.listeners[event].filter(cb => cb !== callback)
    }
  }

  private emit(event: string, data: any) {
    if (this.listeners[event]) {
      this.listeners[event].forEach(callback => callback(data))
    }
  }

  disconnect() {
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
  }

  // Chat-specific methods
  sendChatMessage(content: string) {
    this.sendMessage({
      type: 'message',
      data: { content }
    })
  }

  sendPrivateMessage(content: string, targetUserId: number) {
    this.sendMessage({
      type: 'private_message',
      data: { content, targetUserId }
    })
  }

  updateStatus(status: 'online' | 'busy' | 'offline') {
    this.sendMessage({
      type: 'status_change',
      data: { status }
    })
  }

  revokeMessage(messageId: number) {
    this.sendMessage({
      type: 'message_revoked',
      data: { messageId }
    })
  }

  startTyping() {
    this.sendMessage({
      type: 'typing',
      data: { isTyping: true }
    })
  }

  stopTyping() {
    this.sendMessage({
      type: 'typing',
      data: { isTyping: false }
    })
  }

  blockUser(userId: number) {
    this.sendMessage({
      type: 'block_user',
      data: { userId }
    })
  }

  unblockUser(userId: number) {
    this.sendMessage({
      type: 'unblock_user',
      data: { userId }
    })
  }
}
