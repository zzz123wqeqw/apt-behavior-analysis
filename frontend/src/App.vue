<template>
  <el-container class="layout">
    <el-aside width="200px" class="aside">
      <div class="logo">APT 研判系统</div>
      <el-menu :default-active="$route.path" router>
        <el-menu-item index="/">概览仪表盘</el-menu-item>
        <el-menu-item index="/data">数据管理</el-menu-item>
        <el-menu-item index="/timeline">事件时间线</el-menu-item>
        <el-menu-item index="/reports">研判报告</el-menu-item>
        <el-menu-item index="/graph">知识图谱</el-menu-item>
        <el-menu-item index="/llm">大模型分析</el-menu-item>
        <el-menu-item index="/settings">密钥配置</el-menu-item>
      </el-menu>
    </el-aside>
    <el-container class="body">
      <el-header class="topbar" height="44px">
        <span class="topbar-title">面向 APT 攻击的大模型行为特征识别与研判</span>
        <div class="status-group">
          <el-tooltip content="大模型模式：API（已配置 Key）/ 规则兜底" placement="bottom">
            <el-tag size="small" :type="status.llm.mode === 'api' ? 'success' : 'warning'">
              LLM {{ status.llm.mode === 'api' ? '已启用' : '兜底模式' }}
            </el-tag>
          </el-tooltip>
          <el-tooltip content="情报平台：微步 / VirusTotal / FOFA 已配置的 Key 数" placement="bottom">
            <el-tag size="small" :type="status.intelCount > 0 ? 'primary' : 'info'">
              情报 {{ status.intelCount }}/3
            </el-tag>
          </el-tooltip>
        </div>
      </el-header>
      <el-main>
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { onMounted, reactive } from 'vue'
import { fetchSettings, type SettingsStatus } from './api/settings'

// F5: 全局系统状态角标（LLM 模式 + 情报平台 Key 数）
const status = reactive<SettingsStatus & { intelCount: number }>({
  keys: { llm_api_key: false, vt_api_key: false, threatbook_api_key: false, fofa_api_key: false, api_token: false },
  llm: { available: false, model: '', mode: 'fallback' },
  intel: { virustotal: false, threatbook: false, fofa: false },
  intelCount: 0,
})

async function loadStatus() {
  try {
    const s: any = await fetchSettings()
    Object.assign(status, s)
    status.intelCount = [s.intel?.virustotal, s.intel?.threatbook, s.intel?.fofa].filter(Boolean).length
  } catch {
    /* 后端未启动时静默 */
  }
}

onMounted(loadStatus)
</script>

<style scoped>
.layout { height: 100vh; }
.aside { border-right: 1px solid var(--el-border-color); }
.logo { padding: 16px; font-weight: 700; }
.body { min-width: 0; }
.topbar { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--el-border-color); background: var(--el-bg-color); }
.topbar-title { font-size: 13px; color: var(--el-text-color-secondary); }
.status-group { display: flex; gap: 8px; }
</style>
