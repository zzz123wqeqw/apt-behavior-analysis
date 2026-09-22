# APT 研判系统

**面向 APT 攻击的大模型行为特征识别与研判研究**

基于 LLM 的 APT 攻击研判系统：采集网络流量 / 终端行为 / 日志数据 → 行为特征识别（长期潜伏、内网横向移动、隐蔽数据传输、痕迹清理）→ 组织溯源 → 误报过滤 → 研判报告 → 知识图谱 → 情报平台增强。前后端分离，可一键全流程演示。

## 技术栈

- **后端**：Python 3.14 + FastAPI + SQLite + cryptography（Fernet 加密 / HMAC 完整性校验）+ httpx（情报平台客户端）
- **前端**：Vue3 + Vite + TypeScript + Element Plus + ECharts + AntV G6（知识图谱）

## 核心能力

| 模块 | 说明 |
| --- | --- |
| 数据采集 | 模拟三场景攻击数据（钓鱼+C2潜伏 / SMB横向移动 / DNS隧道+清痕，70% 正常噪声）；支持 OTRF Security-Datasets 真实事件日志（NDJSON，按 EventID/Channel 自动映射事件类型） |
| 特征识别 | 规则引擎预筛（features.json，事件规则+聚合规则）→ LLM 深度行为识别（JSON 约束输出+证据事件 ID），无 Key 时规则兜底 |
| 组织溯源 | RAG-lite：画像库 Top3 检索 + LLM 溯源（含【情报支撑】注入微步等平台结果），输出组织/路径/入口/意图/推理 |
| 误报过滤 | 证据数 / 置信度 / 规则交叉 / 情报一致性 → 状态（确认/待复核/误报）+ 风险等级 |
| 研判报告 | 行为/范围/时间线/三类处置建议（阻断/清除/溯源），敏感字段加密落库，HMAC 签名与完整性校验接口 |
| 知识图谱 | 自动构建（组织/行为/TTP/IOC/案例/资产 6 类节点 + 关联/具备/针对/涉及关系），G6 前端渲染，可筛选 |
| 情报平台 | 微步 / VirusTotal 双平台 IOC 查询 + FOFA 资产扩线 + 奇安信情报导入（均带限速与 SQLite 缓存，Key 缺失自动降级） |
| 数据管理 | 数据源列表（内置模拟 / OTRF 真实 / 用户上传），支持文件上传（JSON/NDJSON/CSV）、一键切换数据并重新研判 |
| 大模型分析 | 开放式 LLM 问答研判（选择数据源 + 提问 → 结构化结论），未配置 Key 时输出规则引擎结论 |
| 密钥配置 | 页面填写 DeepSeek / VT / 微步 / FOFA 密钥，Fernet 加密存储于 data/settings.json，保存后立即热生效 |

## 目录结构

```
apt-behavior-analysis/
├── 设计方案.md                # 完整设计方案（架构/模块/API/数据/图谱/情报平台接入）
├── README.md                  # 本文件
├── datasets/
│   ├── atomic/                # OTRF 真实事件日志（7 场景，44,024 条 Windows 事件）
│   ├── ioc/threatfox_recent.csv
│   └── README.md              # 场景清单与 EventID→类型映射
├── backend/
│   ├── main.py                # FastAPI 入口（lifespan 初始化 + CORS + 14 组路由）
│   ├── requirements.txt / .env.example / config.yaml
│   ├── data_gen.py            # 模拟数据生成（events.json + labels.json，121 条）
│   ├── evaluate.py            # 全流程评测（行为级 P/R/F1 + 归因率）
│   ├── app/
│   │   ├── core/              # config / database / security(Fernet+HMAC) / llm_client
│   │   ├── models/            # event / case / report / enrichment / graph
│   │   ├── services/          # parser / prefilter / detector / attribution / filter
│   │   │                      # report / graph_builder / pipeline / enricher / expander
│   │   │   └── intel/         # base(限速+缓存) / vt / threatbook / fofa / qianxin
│   │   └── api/routes/        # analyze / events / cases / reports / graph / stats
│   │                          # search / features / profiles / verify / intel / data
│   │                          # settings / llm（18 接口）
│   ├── data/
│   │   ├── events.json / labels.json        # 模拟数据
│   │   ├── features.json / apt_profiles.json # 行为规则库 / 组织画像库
│   │   ├── settings.json                    # 运行时密钥（Fernet 加密）
│   │   ├── apt.db                           # SQLite（6 表，敏感列加密）
│   │   └── output/evaluation.{json,md}      # 评测结果
│   └── tests/                # pytest（9 项，全通过）
└── frontend/
    ├── vite.config.ts        # /api 代理 -> localhost:8000
    └── src/
        ├── api/              # axios 封装（自动注入 Token / 解包 {code,message,data}）
        ├── types/ stores/ router/
        ├── views/            # Dashboard / Timeline / ReportDetail / KnowledgeGraph
        │                     # DataLab（数据管理）/ LLMAnalysis（大模型分析）/ Settings（密钥配置）
        └── components/       # StatCard / BehaviorChart / CaseTimeline / EvidenceList
```

## 运行方式

### 1. 后端（Windows，项目已自带 venv）

```powershell
cd backend
copy .env.example .env        # 按需填 DEEPSEEK_API_KEY / 各情报平台 Key（可留空，自动降级）
.\.venv\Scripts\python.exe data_gen.py                 # 生成模拟数据（可选）
.\.venv\Scripts\python.exe evaluate.py                 # 全流程跑通 + 评测（可选）
.\.venv\Scripts\python.exe -m uvicorn main:app --port 8000
# API 文档：http://localhost:8000/docs
```

### 2. 前端

```powershell
cd frontend
npm install
npm run dev                   # http://localhost:5173
```

### 3. 演示路径

1. 打开 http://localhost:5173 → 概览仪表盘（统计卡片 / 行为分布 / 风险分布 / 报告列表）
2. **数据管理**：上传自有数据或切换内置/OTRF 数据源 → 「分析此数据」一键研判
3. **大模型分析**：选数据源 + 提问 → LLM 开放式研判（未配 Key 时输出规则结论）
4. **密钥配置**：填写 DeepSeek/微步/VT/FOFA 密钥 → 加密保存即时生效
5. 「事件时间线」按类型/关键字筛选原始事件；「研判报告」查看行为证据、溯源推理、处置建议，可点「完整性校验」「情报增强」
6. 「知识图谱」全局查看组织-行为-TTP-IOC-资产关联，可按节点类型筛选、点击节点查看属性

### 4. 真实数据集接入（可选）

```powershell
cd backend
.\.venv\Scripts\python.exe -c "from app.services.pipeline import pipeline; ids=pipeline.run(data_file=r'..\datasets\atomic\c2\psh_powershell_httplistener_2020-11-0204130683.json', use_intel=False); print(ids)"
```

或 POST `/api/analyze` `{"data_file": "..."}`。parser 自动识别标准 JSON 与 OTRF NDJSON（按 EventID/Channel 映射）。

## 评测结果（规则兜底模式）

`backend/data/output/evaluation.md`（2026-09-22，窗口合并后 4 份报告）：

| 场景 | 行为 | Precision | Recall | F1 |
| --- | --- | --- | --- | --- |
| A（钓鱼+C2 潜伏） | hidden_channel, long_term_latency | 1.000 | 1.000 | 1.000 |
| B（SMB 横向移动） | lateral_movement | 1.000 | 1.000 | 1.000 |
| C（DNS 隧道+清痕） | hidden_channel, trace_cleaning | 1.000 | 1.000 | 1.000 |
| **总体** | — | **1.000** | **1.000** | **1.000** |

组织归因产出率 100%（按案例计：Kimsuky / Patchwork / APT33）。配置 `DEEPSEEK_API_KEY` 后由 LLM 实际推理，未配置则规则兜底，两种模式均可完整演示。

## 安全设计

- 敏感字段（src_ip / dst_ip / domain / file_hash / ioc / source_url / 报告时间线 / 图谱节点）Fernet 加密落库，密钥文件 `backend/keyfile` 首次运行自动生成
- 报告 HMAC-SHA256 签名覆盖全部 8 个字段（行为/归因/风险/状态/范围/时间线/处置建议），`GET /api/verify/{report_id}` 可校验完整性（防篡改）
- API 简单 Bearer Token 鉴权（`API_TOKEN`，部署前务必修改默认值并启用 HTTPS）
- `data_file` 参数白名单校验（仅允许 data/、data/uploads/、datasets/ 内文件），防任意文件读取
- 文件上传扩展名白名单（.json/.ndjson/.csv/.txt）+ 50MB 上限，边写边校验
- 情报强证据（IOC 评分 ≥85）需叠加行为置信度 ≥0.6 才可升级"确认"，防情报误报污染结论
- 各情报平台独立限速 + SQLite 缓存（TTL 24h），未配置 Key 自动降级不中断流程

## 测试

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest tests -q    # 9 passed
```
