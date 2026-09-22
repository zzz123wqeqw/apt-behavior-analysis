<template>
  <div class="settings-page">
    <el-card shadow="never">
      <template #header>
        <div class="card-head">
          <span>密钥与平台配置</span>
          <el-button size="small" @click="load">刷新状态</el-button>
        </div>
      </template>

      <!-- 平台状态 -->
      <el-descriptions :column="3" border size="small" class="status-box">
        <el-descriptions-item label="LLM 分析">
          <el-tag :type="status.llm.available ? 'success' : 'warning'" size="small">
            {{ status.llm.available ? `已启用（${status.llm.model}）` : '规则兜底' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="VirusTotal">
          <el-tag :type="status.intel.virustotal ? 'success' : 'info'" size="small">
            {{ status.intel.virustotal ? '已配置' : '未配置' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="微步">
          <el-tag :type="status.intel.threatbook ? 'success' : 'info'" size="small">
            {{ status.intel.threatbook ? '已配置' : '未配置' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="FOFA 扩线">
          <el-tag :type="status.intel.fofa ? 'success' : 'info'" size="small">
            {{ status.intel.fofa ? '已配置' : '未配置' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="API Token">
          <el-tag :type="status.keys.api_token ? 'success' : 'danger'" size="small">
            {{ status.keys.api_token ? '已设置' : '未设置' }}
          </el-tag>
        </el-descriptions-item>
      </el-descriptions>

      <!-- 表单 -->
      <el-form label-width="170px" class="key-form" @submit.prevent>
        <el-form-item label="DeepSeek API Key（LLM）">
          <el-input v-model="form.deepseek_api_key" type="password" show-password
                    placeholder="sk-... 配置后启用 LLM 深度研判（留空不修改）" />
        </el-form-item>
        <el-form-item label="VirusTotal API Key">
          <el-input v-model="form.vt_api_key" type="password" show-password placeholder="IP/域名信誉查询" />
        </el-form-item>
        <el-form-item label="微步 ThreatBook Key">
          <el-input v-model="form.threatbook_api_key" type="password" show-password placeholder="威胁情报查询（溯源 Prompt 注入）" />
        </el-form-item>
        <el-form-item label="FOFA API Key">
          <el-input v-model="form.fofa_api_key" type="password" show-password placeholder="资产测绘与扩线" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="saving" @click="save">保存密钥（加密存储）</el-button>
          <el-button @click="resetForm">清空表单</el-button>
        </el-form-item>
      </el-form>

      <el-alert type="info" :closable="false" title="说明"
                :description="'密钥经 Fernet 加密后存于 backend/data/settings.json，保存后立即生效（LLM 客户端与情报客户端热更新）。若同时配置了 .env，settings.json 优先。'" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { fetchSettings, saveKeys, type SettingsStatus } from '../api/settings'

const status = ref<SettingsStatus>({
  keys: { llm_api_key: false, vt_api_key: false, threatbook_api_key: false, fofa_api_key: false, api_token: false },
  llm: { available: false, model: '', mode: 'fallback' },
  intel: { virustotal: false, threatbook: false, fofa: false },
})
const form = reactive({ deepseek_api_key: '', vt_api_key: '', threatbook_api_key: '', fofa_api_key: '' })
const saving = ref(false)

async function load() {
  try {
    status.value = await fetchSettings()
  } catch {
    ElMessage.error('加载配置状态失败')
  }
}

async function save() {
  saving.value = true
  try {
    await saveKeys({
      deepseek_api_key: form.deepseek_api_key || undefined,
      vt_api_key: form.vt_api_key || undefined,
      threatbook_api_key: form.threatbook_api_key || undefined,
      fofa_api_key: form.fofa_api_key || undefined,
    })
    ElMessage.success('密钥已保存并生效')
    resetForm()
    await load()
  } catch (e) {
    ElMessage.error('保存失败：' + (e as Error).message)
  } finally {
    saving.value = false
  }
}

function resetForm() {
  form.deepseek_api_key = ''
  form.vt_api_key = ''
  form.threatbook_api_key = ''
  form.fofa_api_key = ''
}

onMounted(load)
</script>

<style scoped>
.card-head { display: flex; justify-content: space-between; align-items: center; }
.status-box { margin-bottom: 20px; }
.key-form { max-width: 720px; margin-top: 8px; }
</style>
