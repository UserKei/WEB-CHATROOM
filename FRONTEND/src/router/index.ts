import { createRouter, createWebHistory } from 'vue-router'
import LoginView from '../views/LoginView.vue'
import ChatView from '../views/ChatView.vue'
import { useAuthStore } from '@/stores/auth'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      redirect: '/login'
    },
    {
      path: '/login',
      name: 'login',
      component: LoginView,
      meta: { requiresGuest: true }
    },
    {
      path: '/chat',
      name: 'chat',
      component: ChatView,
      meta: { requiresAuth: true }
    }
  ],
})

router.beforeEach((to, from, next) => {
  const authStore = useAuthStore()
  const isAuthenticated = authStore.checkAuth()

  console.log('Route guard - to:', to.path, 'isAuthenticated:', isAuthenticated)

  if (to.meta.requiresAuth && !isAuthenticated) {
    console.log('Redirecting to login - auth required but not authenticated')
    next('/login')
  } else if (to.meta.requiresGuest && isAuthenticated) {
    console.log('Redirecting to chat - guest route but authenticated')
    next('/chat')
  } else {
    console.log('Allowing navigation to:', to.path)
    next()
  }
})

export default router
