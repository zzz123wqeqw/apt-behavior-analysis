<template>
  <div class="data-lab">
    <!-- 上传区 -->
    <el-card shadow="never" class="upload-card">
      <template #header>
        <div class="card-head"><span>上传数据</span>
          <span class="hint">支持 JSON / NDJSON（OTRF 事件日志）/ CSV，上传后自动解析计数</span>
        </div>
      </template>
      <el-upload
        drag :auto-upload="false" :limit="1" accept=".json,.ndjson,.csv,.txt"
        :on-change="onPick" :on-remove="() => (picked = null)"
        class="uploader"
      >
        <el-icon :size="42" class="up-icon"><UploadFilled /></el-icon>
        <div class="el-upload__text">拖拽文件到此处，或 <em>点击选择</em></div>
        <template #tip>
          <div class="el-upload__tip">最大 50MB；上传后可立即选中分析</div>
        </template>
      </el-upload>
      <div v-if="picked" class="pick-row">
        <span class="pick-name">{{ picked.name }}（{{ (picked.size / 1024).toFixed(1) }} KB）</span>
        <el-button type="primary" :loading="uploading" @click="doUpload">上传并解析</el-button>
      </div>
    </el-card>

    <!-- 数据源列表 / 切换 -->
    <el-card shadow="never">
      <template #header>
        <div class="card-head"><span>数据源（点击切换）</span>
          <el-button size="small" @click="load">刷新</el-button>
        </div>
      </template>
      <el-table :data="sources" highlight-current-row @current-change="onSelect" :row-class-name="rowClass">
        <el-table-column label="类型" width="90">
          <template #default="{ row }">
            <el-tag :type="typeTag(row.type)" size="small">{{ typeLabel(row.type) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="name" label="名称" min-width="240" show-overflow-tooltip />
        <el-table-column label="事件数" width="110">
          <template #default="{ row }">
            <span v-if="row.count >= 0">{{ row.count }}</span>
            <span v-else class="dim">大文件</span>
          </template>
        </el-table-column>
        <el-table-column prop="size_kb" label="大小(KB)" width="100" />
        <el-table-column prop="desc" label="说明" min-width="200" show-overflow-tooltip />
        <el-table-column label="操作" width="140">
          <template #default="{ row }">
            <el-button size="small" type="primary" plain :disabled="!selected || selected.id !== row.id"
                       @click.stop="runPipeline(row)">分析此数据</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-alert v-if="selected" type="success" :closable="false" class="sel-alert"
                :title="`已选择：${selected.name}（${selected.count >= 0 ? selected.count + ' 条事件' : '大文件'}）`" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { UploadFilled } from '@element-plus/icons-vue'
import { fetchSources, uploadFile, type DataSource } from '../api/data'
import { runAnalyze } from '../api/analyze'

const router = useRouter()
const sources = ref<DataSource[]>([])
const selected = ref<DataSource | null>(null)
const picked = ref<File | null>(null)
const uploading = ref(false)
const analyzing = ref(false)

async function load() {
  try {
    const res: any = await fetchSources()
    sources.value = res.items || []
    if (!selected.value && sources.value.length) selected.value = sources.value[0]
  } catch {
    ElMessage.error('加载数据源失败，请确认后端已启动')
  }
}

function onPick(file: any) {
  picked.value = file.raw
}
function onSelect(row: DataSource | null) {
  selected.value = row
}
function rowClass({ row }: { row: DataSource }) {
  return selected.value?.id === row.id ? 'cur-row' : ''
}

async function doUpload() {
  if (!picked.value) return
  uploading.value = true
  try {
    const src: any = await uploadFile(picked.value)
    ElMessage.success('上传成功')
    await load()
    selected.value = src
  } catch (e) {
    ElMessage.error('上传失败：' + (e as Error).message)
  } finally {
    uploading.value = false
  }
}

async function runPipeline(src: DataSource) {
  if (!src) return
  analyzing.value = true
  try {
    const res: any = await runAnalyze({ data_file: src.path, use_intel: false })
    ElMessage.success(`「${src.name}」研判完成，生成 ${res.report_ids?.length || 0} 份报告`)
    router.push({ path: '/reports' })
  } catch (e) {
    ElMessage.error('研判失败：' + (e as Error).message)
  } finally {
    analyzing.value = false
  }
}

function typeTag(t: string) {
  return { sim: 'primary', real: 'success', upload: 'warning' }[t] || ''
}
function typeLabel(t: string) {
  return { sim: '内置', real: '真实', upload: '上传' }[t] || t
}

onMounted(load)
</script>

<style scoped>
.upload-card { margin-bottom: 16px; }
.card-head { display: flex; justify-content: space-between; align-items: center; }
.hint { font-size: 12px; color: var(--el-text-color-secondary); font-weight: normal; }
.uploader { width: 100%; }
.up-icon { color: var(--el-color-primary); margin: 8px 0; }
.pick-row { display: flex; align-items: center; gap: 14px; margin-top: 14px; }
.pick-name { font-size: 13px; color: var(--el-text-color-primary); }
.dim { color: var(--el-text-color-secondary); }
.sel-alert { margin-top: 14px; }
:deep(.cur-row) { --el-table-tr-bg-color: var(--el-color-primary-light-9); }
</style>
