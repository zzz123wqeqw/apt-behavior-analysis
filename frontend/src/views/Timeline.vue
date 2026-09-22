<template>
  <div class="timeline-page">
    <!-- 筛选栏 -->
    <el-card shadow="never" class="filter-bar">
      <div class="filters">
        <el-input v-model="keyword" placeholder="搜索 IP / 域名 / 进程 / 主机" clearable style="width: 260px" @keyup.enter="load" />
        <el-select v-model="typeFilter" placeholder="事件类型" clearable style="width: 130px">
          <el-option v-for="t in typeOptions" :key="t" :label="t" :value="t" />
        </el-select>
        <el-select v-model="sceneFilter" placeholder="场景" clearable style="width: 120px">
          <el-option label="A" value="A" /><el-option label="B" value="B" /><el-option label="C" value="C" />
        </el-select>
        <el-button type="primary" @click="load">查询</el-button>
      </div>
    </el-card>

    <!-- 时间线 -->
    <el-card shadow="never">
      <el-timeline v-loading="loading">
        <el-timeline-item
          v-for="ev in events" :key="ev.event_id"
          :timestamp="ev.ts" placement="top"
          :type="ev.label === 'attack' ? 'danger' : 'info'"
        >
          <div class="event-item" :class="{ attack: ev.label === 'attack' }">
            <div class="event-head">
              <el-tag size="small" :type="typeTag(ev.type)">{{ ev.type }}</el-tag>
              <span class="host">{{ ev.host }}</span>
              <el-tag v-if="ev.label === 'attack'" size="small" type="danger" effect="dark">攻击</el-tag>
              <el-tag v-else size="small" type="info">正常</el-tag>
            </div>
            <div class="event-desc">
              <template v-if="ev.type === 'flow'">
                {{ ev.src_ip }} → <b>{{ ev.dst_ip }}:{{ ev.dst_port }}</b>
                <span v-if="ev.domain" class="dim">（{{ ev.domain }}）</span>
                <span class="dim">[{{ ev.action }}]</span>
              </template>
              <template v-else-if="ev.type === 'dns'">
                查询 <b>{{ ev.domain }}</b> <span class="dim">[{{ ev.action }}]</span>
              </template>
              <template v-else-if="ev.type === 'process'">
                {{ ev.process }} <span v-if="ev.parent_process" class="dim">← 父进程 {{ ev.parent_process }}</span>
                <span class="dim">[{{ ev.action }}]</span>
              </template>
              <template v-else-if="ev.type === 'file'">
                {{ ev.file_path }} <span class="dim">[{{ ev.action }}]</span>
              </template>
              <template v-else>
                {{ ev.user }} <span class="dim">[{{ ev.action }}]</span>
              </template>
            </div>
          </div>
        </el-timeline-item>
      </el-timeline>
      <el-empty v-if="!loading && !events.length" description="暂无事件" />
      <div class="pager">
        <el-pagination
          layout="prev, pager, next, total" :total="total" :page-size="pageSize"
          v-model:current-page="page" @current-change="load"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { fetchEvents } from '../api/events'
import { searchAll } from '../api/search'
import type { Event } from '../types'

const events = ref<Event[]>([])
const loading = ref(false)
const keyword = ref('')
const typeFilter = ref('')
const sceneFilter = ref('')
const page = ref(1)
const pageSize = 20
const total = ref(0)
const allMatched = ref<Event[]>([])

const typeOptions = ['flow', 'dns', 'process', 'file', 'auth']

async function load() {
  loading.value = true
  try {
    const params: Record<string, unknown> = { limit: pageSize, offset: (page.value - 1) * pageSize }
    if (typeFilter.value) params.type = typeFilter.value
    if (sceneFilter.value) params.scene = sceneFilter.value
    let res: any
    if (keyword.value) {
      // 搜索命中全量缓存后前端分页（F7）
      if (page.value === 1 || !allMatched.value.length) {
        res = await searchAll(keyword.value, { search_type: 'event' })
        allMatched.value = (res as any).events || []
      }
      total.value = allMatched.value.length
      events.value = allMatched.value.slice((page.value - 1) * pageSize, page.value * pageSize)
    } else {
      allMatched.value = []
      res = await fetchEvents(params)
      events.value = res.items || []
      total.value = res.total || 0
    }
  } catch (e) {
    ElMessage.error('加载事件失败')
  } finally {
    loading.value = false
  }
}

function typeTag(t: string) {
  return { flow: 'primary', dns: 'warning', process: 'danger', file: 'success', auth: 'info' }[t] || ''
}

onMounted(load)
</script>

<style scoped>
.filter-bar { margin-bottom: 16px; }
.filters { display: flex; gap: 10px; flex-wrap: wrap; }
.event-item { padding: 4px 0; }
.event-item.attack { background: #fef0f0; border-radius: 6px; padding: 6px 8px; }
.event-head { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.host { font-weight: 600; font-size: 13px; }
.event-desc { font-size: 13px; color: var(--el-text-color-primary); }
.dim { color: var(--el-text-color-secondary); }
.pager { margin-top: 16px; display: flex; justify-content: flex-end; }
</style>
