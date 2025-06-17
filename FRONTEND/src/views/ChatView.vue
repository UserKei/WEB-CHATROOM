<template>
  <div class="chat-container flex">
    <!-- Sidebar -->
    <div class="w-80 sidebar flex flex-col">
      <!-- Header -->
      <div class="p-6 border-b border-white/20">
        <div class="flex items-center justify-between">
          <div class="flex items-center space-x-3">
            <div class="avatar text-lg">
              {{ currentUser?.username?.[0]?.toUpperCase() }}
            </div>
            <div>
              <h2 class="text-lg font-semibold text-gray-800">{{ currentUser?.username }}</h2>
              <div class="flex items-center space-x-2">
                <div :class="statusClasses[currentUser?.status || 'offline']"></div>
                <select
                  v-model="currentStatus"
                  @change="updateUserStatus"
                  class="text-sm text-gray-600 bg-transparent border-none focus:outline-none"
                >
                  <option value="online">Online</option>
                  <option value="busy">Busy</option>
                  <option value="offline">Offline</option>
                </select>
              </div>
            </div>
          </div>
          <button
            @click="logout"
            class="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-white/20 transition-colors"
          >
            <ArrowRightOnRectangleIcon class="h-5 w-5" />
          </button>
        </div>
      </div>

      <!-- Chat Mode Toggle -->
      <div class="p-4 border-b border-white/20">
        <div class="flex bg-white/20 rounded-xl p-1">
          <button
            @click="selectedUserId = null"
            :class="[
              'flex-1 py-2 px-4 rounded-lg text-sm font-medium transition-all duration-200',
              selectedUserId === null
                ? 'bg-white text-gray-800 shadow-sm'
                : 'text-gray-600 hover:text-gray-800'
            ]"
          >
            General Chat
          </button>
          <button
            @click="showPrivateChats = true"
            :class="[
              'flex-1 py-2 px-4 rounded-lg text-sm font-medium transition-all duration-200',
              selectedUserId !== null
                ? 'bg-white text-gray-800 shadow-sm'
                : 'text-gray-600 hover:text-gray-800'
            ]"
          >
            Private
          </button>
        </div>
      </div>

      <!-- Online Users List -->
      <div class="flex-1 overflow-y-auto p-4">
        <h3 class="text-sm font-medium text-gray-700 mb-3">
          Online Users ({{ onlineUsers.length }})
        </h3>
        <div class="space-y-2">
          <div
            v-for="user in onlineUsers"
            :key="user.id"
            class="flex items-center justify-between p-3 rounded-xl hover:bg-white/30 transition-colors cursor-pointer group"
            @click="startPrivateChat(user.id)"
          >
            <div class="flex items-center space-x-3">
              <div class="relative">
                <div class="avatar text-sm">
                  {{ user.username[0].toUpperCase() }}
                </div>
                <div :class="statusClasses[user.status]" class="absolute -bottom-0.5 -right-0.5"></div>
              </div>
              <div>
                <p class="text-sm font-medium text-gray-800">{{ user.username }}</p>
                <p class="text-xs text-gray-500 capitalize">{{ user.status }}</p>
              </div>
            </div>
            <div class="flex space-x-1 opacity-0 group-hover:opacity-100 transition-opacity">
              <button
                @click.stop="blockUser(user.id)"
                class="p-1 text-gray-400 hover:text-red-500 transition-colors"
                title="Block User"
              >
                <NoSymbolIcon class="h-4 w-4" />
              </button>
              <button
                @click.stop="startPrivateChat(user.id)"
                class="p-1 text-gray-400 hover:text-blue-500 transition-colors"
                title="Private Message"
              >
                <ChatBubbleLeftEllipsisIcon class="h-4 w-4" />
              </button>
            </div>
          </div>
        </div>

        <!-- Blocked Users -->
        <div v-if="blockedUsers.length > 0" class="mt-6">
          <h3 class="text-sm font-medium text-gray-700 mb-3">
            Blocked Users
          </h3>
          <div class="space-y-2">
            <div
              v-for="userId in blockedUsers"
              :key="userId"
              class="flex items-center justify-between p-3 rounded-xl bg-red-50 border border-red-200"
            >
              <span class="text-sm text-red-700">User {{ userId }}</span>
              <button
                @click="unblockUser(userId)"
                class="text-xs text-red-600 hover:text-red-800 font-medium"
              >
                Unblock
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Main Chat Area -->
    <div class="flex-1 flex flex-col bg-white/10">
      <!-- Chat Header -->
      <div class="p-6 border-b border-white/20 bg-white/20">
        <div class="flex items-center justify-between">
          <div>
            <h1 class="text-xl font-semibold text-gray-800">
              {{ selectedUserId ? `Chat with ${getSelectedUserName()}` : 'General Chat' }}
            </h1>
            <div class="flex items-center space-x-2 mt-1">
              <div v-if="typingUsers.length > 0" class="text-sm text-gray-600">
                {{ getTypingText() }}
              </div>
              <div v-else class="text-sm text-gray-500">
                {{ selectedUserId ? 'Private conversation' : `${onlineUsers.length} users online` }}
              </div>
            </div>
          </div>
          <div class="flex items-center space-x-3">
            <div :class="isConnected ? 'status-online' : 'status-offline'" title="Connection Status"></div>
            <button
              v-if="selectedUserId"
              @click="selectedUserId = null"
              class="btn-secondary"
            >
              Back to General
            </button>
          </div>
        </div>
      </div>

      <!-- Messages Area -->
      <div
        ref="messagesContainer"
        class="flex-1 overflow-y-auto p-6 space-y-4"
        @scroll="handleScroll"
      >
        <div
          v-for="message in currentMessages"
          :key="message.id"
          class="flex"
          :class="message.senderId === currentUser?.id ? 'justify-end' : 'justify-start'"
          v-motion
          :initial="{ opacity: 0, y: 20 }"
          :enter="{ opacity: 1, y: 0, transition: { duration: 300 } }"
        >
          <div
            :class="[
              'max-w-xs lg:max-w-md',
              message.senderId === currentUser?.id ? 'message-sent' : 'message-received'
            ]"
            class="group relative"
          >
            <div v-if="message.senderId !== currentUser?.id" class="text-xs text-gray-500 mb-1">
              {{ message.senderName }}
            </div>
            <p class="text-sm whitespace-pre-wrap">{{ message.content }}</p>
            <div class="flex items-center justify-between mt-2">
              <span class="text-xs opacity-70">
                {{ formatTime(message.timestamp) }}
              </span>
              <div v-if="message.senderId === currentUser?.id" class="flex items-center space-x-1">
                <CheckIcon v-if="message.isRead" class="h-3 w-3 text-green-500" />
                <button
                  v-if="canRevokeMessage(message)"
                  @click="revokeMessage(message.id)"
                  class="opacity-0 group-hover:opacity-100 text-xs text-red-500 hover:text-red-700 transition-all"
                >
                  Revoke
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- Empty state -->
        <div v-if="currentMessages.length === 0" class="text-center py-12">
          <ChatBubbleLeftRightIcon class="h-16 w-16 text-gray-300 mx-auto mb-4" />
          <p class="text-gray-500">
            {{ selectedUserId ? 'No messages yet. Start the conversation!' : 'No messages yet. Be the first to say hello!' }}
          </p>
        </div>
      </div>

      <!-- Message Input -->
      <div class="p-6 border-t border-white/20 bg-white/20">
        <form @submit.prevent="sendMessage" class="flex space-x-4">
          <div class="flex-1 relative">
            <input
              v-model="newMessage"
              type="text"
              placeholder="Type your message..."
              class="input-apple pr-12"
              @input="handleTyping"
              @keydown.enter.prevent="sendMessage"
              :disabled="!isConnected"
            />
            <button
              type="button"
              class="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
            >
              <FaceSmileIcon class="h-5 w-5" />
            </button>
          </div>
          <button
            type="submit"
            :disabled="!newMessage.trim() || !isConnected"
            class="btn-primary px-6 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <PaperAirplaneIcon class="h-5 w-5" />
          </button>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useChatStore } from '@/stores/chat'
import { useAuthStore } from '@/stores/auth'
import {
  ArrowRightOnRectangleIcon,
  ChatBubbleLeftEllipsisIcon,
  ChatBubbleLeftRightIcon,
  NoSymbolIcon,
  CheckIcon,
  PaperAirplaneIcon,
  FaceSmileIcon
} from '@heroicons/vue/24/outline'

const router = useRouter()
const chatStore = useChatStore()
const authStore = useAuthStore()

const messagesContainer = ref<HTMLElement>()
const newMessage = ref('')
const currentStatus = ref(chatStore.currentUser?.status || 'online')
const showPrivateChats = ref(false)
const typingTimer = ref<number>()

const statusClasses = {
  online: 'status-online',
  busy: 'status-busy',
  offline: 'status-offline'
}

// Computed properties
const currentUser = computed(() => chatStore.currentUser)
const onlineUsers = computed(() =>
  chatStore.users.filter(user =>
    user.id !== currentUser.value?.id && user.status !== 'offline'
  )
)
const isConnected = computed(() => chatStore.isConnected)
const selectedUserId = computed({
  get: () => chatStore.selectedUserId,
  set: (value) => chatStore.selectUser(value)
})
const blockedUsers = computed(() => chatStore.blockedUsers)
const typingUsers = computed(() => chatStore.typingUsers)

const currentMessages = computed(() => {
  if (selectedUserId.value) {
    return chatStore.privateChat
  }
  return chatStore.filteredMessages
})

// Methods
const updateUserStatus = () => {
  chatStore.updateStatus(currentStatus.value as 'online' | 'busy' | 'offline')
}

const startPrivateChat = (userId: number) => {
  selectedUserId.value = userId
}

const getSelectedUserName = () => {
  if (!selectedUserId.value) return ''
  const user = chatStore.users.find(u => u.id === selectedUserId.value)
  return user?.username || 'Unknown User'
}

const getTypingText = () => {
  const typingUserNames = typingUsers.value
    .map(userId => chatStore.users.find(u => u.id === userId)?.username)
    .filter(Boolean)

  if (typingUserNames.length === 1) {
    return `${typingUserNames[0]} is typing...`
  } else if (typingUserNames.length === 2) {
    return `${typingUserNames[0]} and ${typingUserNames[1]} are typing...`
  } else if (typingUserNames.length > 2) {
    return 'Several people are typing...'
  }
  return ''
}

const formatTime = (timestamp: Date) => {
  const date = new Date(timestamp)
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

const sendMessage = () => {
  if (!newMessage.value.trim()) return

  if (selectedUserId.value) {
    chatStore.sendPrivateMessage(newMessage.value, selectedUserId.value)
  } else {
    chatStore.sendMessage(newMessage.value)
  }

  newMessage.value = ''
  chatStore.stopTyping()
  scrollToBottom()
}

const handleTyping = () => {
  chatStore.startTyping()

  if (typingTimer.value) {
    clearTimeout(typingTimer.value)
  }

  typingTimer.value = setTimeout(() => {
    chatStore.stopTyping()
  }, 3000)
}

const revokeMessage = (messageId: number) => {
  if (confirm('Are you sure you want to revoke this message?')) {
    chatStore.revokeMessage(messageId)
  }
}

const blockUser = (userId: number) => {
  if (confirm('Are you sure you want to block this user?')) {
    chatStore.blockUser(userId)
  }
}

const unblockUser = (userId: number) => {
  chatStore.unblockUser(userId)
}

const logout = async () => {
  if (confirm('Are you sure you want to logout?')) {
    chatStore.logout()
    await authStore.logout()
    router.push('/login')
  }
}

const canRevokeMessage = (message: any) => {
  return chatStore.canRevokeMessage(message)
}

const scrollToBottom = async () => {
  await nextTick()
  if (messagesContainer.value) {
    messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight
  }
}

const handleScroll = () => {
  // Handle scroll for loading more messages
}

// Watchers
watch(() => currentMessages.value.length, () => {
  scrollToBottom()
})

// Lifecycle
onMounted(async () => {
  // Check if user is authenticated
  if (!currentUser.value) {
    router.push('/login')
    return
  }

  // Initialize WebSocket connection if not already connected
  if (!isConnected.value) {
    try {
      await chatStore.initializeWebSocket('/ws', currentUser.value.token)
    } catch (error) {
      console.error('Failed to connect to chat server:', error)
      // WebSocket连接失败，清理无效的认证信息
      authStore.logout()
      router.push('/login')
    }
  }

  scrollToBottom()
})

onUnmounted(() => {
  if (typingTimer.value) {
    clearTimeout(typingTimer.value)
  }
  chatStore.stopTyping()
})
</script>
