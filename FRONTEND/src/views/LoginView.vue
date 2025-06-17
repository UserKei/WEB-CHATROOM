<template>
  <div class="min-h-screen flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
    <div
      class="max-w-md w-full space-y-8"
      v-motion
      :initial="{ opacity: 0, y: 50 }"
      :enter="{ opacity: 1, y: 0, transition: { duration: 800, ease: 'easeOut' } }"
    >
      <!-- Logo and Title -->
      <div class="text-center">
        <div
          class="w-20 h-20 mx-auto bg-gradient-to-r from-blue-500 to-purple-600 rounded-3xl flex items-center justify-center shadow-lg"
          v-motion
          :initial="{ scale: 0 }"
          :enter="{ scale: 1, transition: { delay: 200, duration: 600, type: 'spring', stiffness: 200 } }"
        >
          <ChatBubbleLeftRightIcon class="h-10 w-10 text-white" />
        </div>
        <h2
          class="mt-6 text-3xl font-bold text-gray-900 font-apple"
          v-motion
          :initial="{ opacity: 0 }"
          :enter="{ opacity: 1, transition: { delay: 400, duration: 600 } }"
        >
          {{ isLogin ? 'Welcome Back' : 'Join Us' }}
        </h2>
        <p
          class="mt-2 text-sm text-gray-600"
          v-motion
          :initial="{ opacity: 0 }"
          :enter="{ opacity: 1, transition: { delay: 500, duration: 600 } }"
        >
          {{ isLogin ? 'Sign in to your account' : 'Create your account to get started' }}
        </p>
      </div>

      <!-- Form Card -->
      <div
        class="glass-effect rounded-3xl p-8 shadow-apple"
        v-motion
        :initial="{ opacity: 0, scale: 0.95 }"
        :enter="{ opacity: 1, scale: 1, transition: { delay: 300, duration: 600 } }"
      >
        <form @submit.prevent="handleSubmit" class="space-y-6">
          <!-- Email field (register only) -->
          <div v-if="!isLogin" v-motion :initial="{ opacity: 0, x: -20 }" :enter="{ opacity: 1, x: 0, transition: { delay: 600, duration: 400 } }">
            <label for="email" class="block text-sm font-medium text-gray-700 mb-2">
              Email Address
            </label>
            <input
              id="email"
              v-model="form.email"
              type="email"
              autocomplete="email"
              class="input-apple"
              placeholder="Enter your email"
              :class="{ 'border-red-500 focus:ring-red-500': emailError }"
            />
            <p v-if="emailError" class="mt-1 text-sm text-red-600">{{ emailError }}</p>
          </div>

          <!-- Username field -->
          <div v-motion :initial="{ opacity: 0, x: -20 }" :enter="{ opacity: 1, x: 0, transition: { delay: isLogin ? 600 : 700, duration: 400 } }">
            <label for="username" class="block text-sm font-medium text-gray-700 mb-2">
              Username
            </label>
            <input
              id="username"
              v-model="form.username"
              type="text"
              autocomplete="username"
              class="input-apple"
              placeholder="Enter your username"
              :class="{ 'border-red-500 focus:ring-red-500': usernameError }"
            />
            <p v-if="usernameError" class="mt-1 text-sm text-red-600">{{ usernameError }}</p>
          </div>

          <!-- Password field -->
          <div v-motion :initial="{ opacity: 0, x: -20 }" :enter="{ opacity: 1, x: 0, transition: { delay: isLogin ? 700 : 800, duration: 400 } }">
            <label for="password" class="block text-sm font-medium text-gray-700 mb-2">
              Password
            </label>
            <div class="relative">
              <input
                id="password"
                v-model="form.password"
                :type="showPassword ? 'text' : 'password'"
                autocomplete="current-password"
                class="input-apple pr-10"
                placeholder="Enter your password"
                :class="{ 'border-red-500 focus:ring-red-500': passwordError }"
              />
              <button
                type="button"
                @click="showPassword = !showPassword"
                class="absolute inset-y-0 right-0 pr-3 flex items-center"
              >
                <EyeIcon v-if="!showPassword" class="h-5 w-5 text-gray-400 hover:text-gray-600" />
                <EyeSlashIcon v-else class="h-5 w-5 text-gray-400 hover:text-gray-600" />
              </button>
            </div>
            <p v-if="passwordError" class="mt-1 text-sm text-red-600">{{ passwordError }}</p>
          </div>

          <!-- Confirm Password field (register only) -->
          <div v-if="!isLogin" v-motion :initial="{ opacity: 0, x: -20 }" :enter="{ opacity: 1, x: 0, transition: { delay: 900, duration: 400 } }">
            <label for="confirmPassword" class="block text-sm font-medium text-gray-700 mb-2">
              Confirm Password
            </label>
            <input
              id="confirmPassword"
              v-model="form.confirmPassword"
              type="password"
              class="input-apple"
              placeholder="Confirm your password"
              :class="{ 'border-red-500 focus:ring-red-500': confirmPasswordError }"
            />
            <p v-if="confirmPasswordError" class="mt-1 text-sm text-red-600">{{ confirmPasswordError }}</p>
          </div>

          <!-- Error message -->
          <div v-if="authStore.error" class="text-red-600 text-sm text-center bg-red-50 p-3 rounded-xl">
            {{ authStore.error }}
          </div>

          <!-- Submit button -->
          <div v-motion :initial="{ opacity: 0, y: 20 }" :enter="{ opacity: 1, y: 0, transition: { delay: isLogin ? 800 : 1000, duration: 400 } }">
            <button
              type="submit"
              :disabled="authStore.loading || !isFormValid"
              class="btn-primary w-full py-3 text-base font-semibold disabled:opacity-50 disabled:cursor-not-allowed relative overflow-hidden"
            >
              <span v-if="!authStore.loading">
                {{ isLogin ? 'Sign In' : 'Create Account' }}
              </span>
              <div v-else class="flex items-center justify-center">
                <div class="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                {{ isLogin ? 'Signing In...' : 'Creating Account...' }}
              </div>
            </button>
          </div>
        </form>

        <!-- Switch mode -->
        <div
          class="mt-6 text-center"
          v-motion
          :initial="{ opacity: 0 }"
          :enter="{ opacity: 1, transition: { delay: isLogin ? 900 : 1100, duration: 400 } }"
        >
          <p class="text-sm text-gray-600">
            {{ isLogin ? "Don't have an account?" : 'Already have an account?' }}
            <button
              @click="toggleMode"
              class="font-medium text-apple-blue hover:text-blue-600 transition-colors duration-200"
            >
              {{ isLogin ? 'Sign up' : 'Sign in' }}
            </button>
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useChatStore } from '@/stores/chat'
import {
  ChatBubbleLeftRightIcon,
  EyeIcon,
  EyeSlashIcon
} from '@heroicons/vue/24/outline'

const router = useRouter()
const authStore = useAuthStore()
const chatStore = useChatStore()

const isLogin = ref(true)
const showPassword = ref(false)

const form = ref({
  email: '',
  username: '',
  password: '',
  confirmPassword: ''
})

const emailError = ref('')
const usernameError = ref('')
const passwordError = ref('')
const confirmPasswordError = ref('')

const validateEmail = (email: string) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

const validateForm = () => {
  emailError.value = ''
  usernameError.value = ''
  passwordError.value = ''
  confirmPasswordError.value = ''

  let isValid = true

  if (!isLogin.value) {
    if (!form.value.email) {
      emailError.value = 'Email is required'
      isValid = false
    } else if (!validateEmail(form.value.email)) {
      emailError.value = 'Please enter a valid email address'
      isValid = false
    }
  }

  if (!form.value.username) {
    usernameError.value = 'Username is required'
    isValid = false
  } else if (form.value.username.length < 3) {
    usernameError.value = 'Username must be at least 3 characters'
    isValid = false
  }

  if (!form.value.password) {
    passwordError.value = 'Password is required'
    isValid = false
  } else if (form.value.password.length < 6) {
    passwordError.value = 'Password must be at least 6 characters'
    isValid = false
  }

  if (!isLogin.value) {
    if (!form.value.confirmPassword) {
      confirmPasswordError.value = 'Please confirm your password'
      isValid = false
    } else if (form.value.password !== form.value.confirmPassword) {
      confirmPasswordError.value = 'Passwords do not match'
      isValid = false
    }
  }

  return isValid
}

const isFormValid = computed(() => {
  if (isLogin.value) {
    return form.value.username.length >= 3 && form.value.password.length >= 6
  } else {
    return (
      validateEmail(form.value.email) &&
      form.value.username.length >= 3 &&
      form.value.password.length >= 6 &&
      form.value.password === form.value.confirmPassword
    )
  }
})

const handleSubmit = async () => {
  if (!validateForm()) return

  try {
    if (isLogin.value) {
      console.log('Attempting login...')
      const { user, token } = await authStore.login({
        username: form.value.username,
        password: form.value.password
      })

      chatStore.setCurrentUser({ ...user, token })
      await chatStore.initializeWebSocket('/ws', token)

      router.push('/chat')
    } else {
      console.log('Attempting registration...')
      await authStore.register({
        username: form.value.username,
        email: form.value.email,
        password: form.value.password
      })

      console.log('Registration successful, attempting auto-login...')
      // Auto login after registration
      const { user, token } = await authStore.login({
        username: form.value.username,
        password: form.value.password
      })

      chatStore.setCurrentUser({ ...user, token })
      await chatStore.initializeWebSocket('/ws', token)

      router.push('/chat')
    }
  } catch (error) {
    console.error('Authentication error:', error)
    // Error will be displayed via authStore.error in template
  }
}

const toggleMode = () => {
  isLogin.value = !isLogin.value
  form.value = {
    email: '',
    username: '',
    password: '',
    confirmPassword: ''
  }
  emailError.value = ''
  usernameError.value = ''
  passwordError.value = ''
  confirmPasswordError.value = ''
}

onMounted(() => {
  // Check if already authenticated
  if (authStore.checkAuth()) {
    router.push('/chat')
  }
})
</script>
