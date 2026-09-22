import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'dashboard', component: () => import('../views/Dashboard.vue') },
    { path: '/timeline', name: 'timeline', component: () => import('../views/Timeline.vue') },
    { path: '/reports', name: 'reports', component: () => import('../views/ReportDetail.vue') },
    { path: '/graph', name: 'graph', component: () => import('../views/KnowledgeGraph.vue') },
    { path: '/data', name: 'data', component: () => import('../views/DataLab.vue') },
    { path: '/llm', name: 'llm', component: () => import('../views/LLMAnalysis.vue') },
    { path: '/settings', name: 'settings', component: () => import('../views/Settings.vue') },
  ],
})

export default router
