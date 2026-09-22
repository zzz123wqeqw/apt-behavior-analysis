<template>
  <div ref="el" class="behavior-chart" />
</template>

<script setup lang="ts">
import { onMounted, onBeforeUnmount, ref, watch } from 'vue'
import * as echarts from 'echarts'

const props = defineProps<{ data: Record<string, number> }>()
const el = ref<HTMLElement>()
let chart: echarts.ECharts | null = null

function render() {
  if (!el.value) return
  chart = chart || echarts.init(el.value)
  chart.setOption({
    tooltip: { trigger: 'item' },
    legend: { bottom: 0 },
    series: [{
      type: 'pie', radius: ['40%', '68%'],
      data: Object.entries(props.data || {}).map(([k, v]) => ({ name: k, value: v })),
    }],
  })
}

onMounted(render)
watch(() => props.data, render, { deep: true })
onBeforeUnmount(() => chart?.dispose())
</script>

<style scoped>
.behavior-chart { width: 100%; height: 300px; }
</style>
