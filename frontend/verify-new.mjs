// 新页面渲染验证：数据管理 / 大模型分析 / 密钥配置
import { chromium } from 'playwright'

const base = 'http://localhost:5173'
const shots = 'D:\\Users\\Mie\\Desktop\\课设\\frontend\\shots'

const browser = await chromium.launch()
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
const errors = []
page.on('pageerror', (e) => errors.push('pageerror: ' + e.message))
page.on('console', (m) => { if (m.type() === 'error') errors.push('console: ' + m.text()) })

// 1. 数据管理页
await page.goto(base + '/data', { waitUntil: 'networkidle' })
await page.waitForTimeout(1500)
await page.screenshot({ path: `${shots}\\05-datalab.png` })
const dlText = await page.textContent('body')
console.log('data lab has 数据源:', dlText.includes('数据源'), '| 内置模拟:', dlText.includes('内置模拟数据'), '| OTRF:', dlText.includes('c2 /'))

// 2. 大模型分析页（触发一次分析，fallback 结论）
await page.goto(base + '/llm', { waitUntil: 'networkidle' })
await page.waitForTimeout(1200)
await page.click('text=开始分析')
await page.waitForTimeout(6000)
await page.screenshot({ path: `${shots}\\06-llm.png` })
const llmText = await page.textContent('body')
console.log('llm page has 分析结论:', llmText.includes('分析结论'), '| 规则结论:', llmText.includes('规则引擎分析结论'), '| 事件总数:', llmText.includes('事件总数'))

// 3. 密钥配置页
await page.goto(base + '/settings', { waitUntil: 'networkidle' })
await page.waitForTimeout(1200)
await page.screenshot({ path: `${shots}\\07-settings.png` })
const stText = await page.textContent('body')
console.log('settings has LLM 分析:', stText.includes('LLM 分析'), '| 规则兜底:', stText.includes('规则兜底'), '| FOFA:', stText.includes('FOFA 扩线'))

console.log('JS errors:', errors.length ? errors.slice(0, 5) : 'none')
await browser.close()
