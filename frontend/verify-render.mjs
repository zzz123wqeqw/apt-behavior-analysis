// 无头浏览器渲染验证：Dashboard / Timeline / ReportDetail / KnowledgeGraph
import { chromium } from 'playwright'

const base = 'http://localhost:5173'
const shots = 'D:\\Users\\Mie\\Desktop\\课设\\frontend\\shots'

async function shoot(page, name, wait = 2500) {
  await page.waitForTimeout(wait)
  await page.screenshot({ path: `${shots}\\${name}.png`, fullPage: false })
  console.log('shot:', name)
}

const browser = await chromium.launch()
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
const errors = []
page.on('pageerror', (e) => errors.push('pageerror: ' + e.message))
page.on('console', (m) => { if (m.type() === 'error') errors.push('console: ' + m.text()) })

// 1. Dashboard
await page.goto(base + '/', { waitUntil: 'networkidle' })
await shoot(page, '01-dashboard')
console.log('dashboard text has 研判报告:', (await page.textContent('body')).includes('研判报告'))

// 2. Timeline
await page.goto(base + '/timeline', { waitUntil: 'networkidle' })
await shoot(page, '02-timeline')
console.log('timeline has 时间线:', (await page.textContent('body')).includes('事件'))

// 3. ReportDetail（默认第一份报告）
await page.goto(base + '/reports', { waitUntil: 'networkidle' })
await shoot(page, '03-report', 3000)
const body = await page.textContent('body')
console.log('report has 行为识别:', body.includes('行为识别'), '| 溯源:', body.includes('溯源'), '| 处置:', body.includes('处置'))

// 4. KnowledgeGraph
await page.goto(base + '/graph', { waitUntil: 'networkidle' })
await shoot(page, '04-graph', 3500)
console.log('graph canvas rendered:', (await page.$$('canvas')).length > 0)

console.log('JS errors:', errors.length ? errors.slice(0, 5) : 'none')
await browser.close()
