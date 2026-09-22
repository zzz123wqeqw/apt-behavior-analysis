// 前端渲染回归：截图验证评审后各页面
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const shots = 'D:\\Users\\Mie\\Desktop\\课设\\frontend\\shots\\review';
  const fs = require('fs');
  if (!fs.existsSync(shots)) fs.mkdirSync(shots, { recursive: true });

  const pages = [
    { path: '/', name: '01-dashboard' },
    { path: '/timeline', name: '02-timeline' },
    { path: '/reports', name: '03-report' },
    { path: '/graph', name: '04-graph' },
    { path: '/data', name: '05-datalab' },
    { path: '/llm', name: '06-llm' },
    { path: '/settings', name: '07-settings' },
  ];

  for (const p of pages) {
    await page.goto('http://localhost:5173' + p.path, { waitUntil: 'networkidle', timeout: 60000 });
    await page.waitForTimeout(1800);
    // 记录页面错误
    await page.screenshot({ path: `${shots}\\${p.name}.png`, fullPage: false });
    console.log('screenshot:', p.name);
  }

  // LLM 分析页：触发一次分析（fallback 模式，验证 markdown 渲染）
  await page.goto('http://localhost:5173/llm', { waitUntil: 'networkidle', timeout: 60000 });
  await page.waitForTimeout(1500);
  await page.click('button:has-text("开始分析")');
  await page.waitForTimeout(6000);
  await page.screenshot({ path: `${shots}\\08-llm-analysis.png`, fullPage: false });
  console.log('screenshot: 08-llm-analysis (after run)');

  await browser.close();
  console.log('ALL SHOTS DONE');
})().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
