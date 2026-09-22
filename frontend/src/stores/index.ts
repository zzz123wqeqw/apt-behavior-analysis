import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { Report, Stats } from '../types'
import { fetchReports } from '../api/reports'
import { fetchStats } from '../api/stats'

/** 全局状态（骨架）：报告列表 / 统计 / 当前报告 */
export const useAppStore = defineStore('app', () => {
  const reports = ref<Report[]>([])
  const stats = ref<Stats | null>(null)
  const currentReportId = ref<string>('')

  async function loadStats() {
    // TODO: 错误处理
    stats.value = await fetchStats()
  }

  async function loadReports(params?: Record<string, unknown>) {
    const res = await fetchReports(params)
    reports.value = res.items
  }

  return { reports, stats, currentReportId, loadStats, loadReports }
})
