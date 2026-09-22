# 数据集清单

下载日期：2026-09-22
来源：OTRF Security-Datasets（GitHub，MITRE ATT&CK 仿真攻击场景，官方公开）+ ThreatFox（abuse.ch，公开 IOC）

## 目录结构

```
datasets/
├── atomic/                       # 攻击行为事件日志（全部为恶意活动，带"标准答案"）
│   ├── c2/                       # 隐蔽通道/外传
│   ├── lateral_movement/         # 内网横向移动
│   ├── persistence/              # 持久化（长期潜伏）
│   └── trace_cleaning/           # 痕迹清理
└── ioc/
    └── threatfox_recent.csv      # ThreatFox 最近 30 天 IOC（1.4MB）
```

## 场景清单（合计 44,024 条事件）

| 行为类别 | 场景文件 | 事件数 | 说明 |
|---|---|---|---|
| 隐蔽数据传输 | c2/psh_powershell_httplistener | 110 | HTTP C2 监听（Empire 框架） |
| 隐蔽数据传输 | c2/psh_python_webserver | 2,395 | Python Web 服务（外传/服务端） |
| 内网横向移动 | lateral_movement/empire_psexec | 4,348 | PsExec 远程执行（DCERPC/SVCCTL） |
| 内网横向移动 | lateral_movement/empire_wmi | 6,383 | WMI 远程执行（IWbemServices） |
| 长期潜伏/持久化 | persistence/registry_runkey | 657 | 注册表 Run 键持久化（Empire） |
| 痕迹清理 | trace_cleaning/wevtutil_eventlog | 25,208 | wevtutil 修改事件日志路径 |
| 痕迹清理 | trace_cleaning/stop_eventlogging | 4,923 | 注册表停止事件日志服务 |

## 数据格式

- 每行一个 JSON 对象（NDJSON），Windows 事件日志：
  - Sysmon（Channel=Microsoft-Windows-Sysmon/Operational）：EventID 1 进程创建 / 3 网络连接 / 7 镜像加载 / 10 进程访问 / 11 文件创建 / 12 注册表 / 13 注册表值 / 22 DNS
  - Windows Security（Channel=Security）：4624/4625 登录、4656/4658 对象访问、5156 过滤平台连接、4103/800 PowerShell 模块日志等
- 常见字段：EventID、Channel、EventTime、@timestamp、Hostname、SourceImage/TargetImage（进程）、SourceAddress/DestAddress/SourcePort/DestPort（网络）、SourceProcessId/TargetProcessId、Message、UtcTime

## 与项目 Event schema 的映射（后续 B2 parser 实现）

| 项目 Event.type | 判定依据（Windows 事件） |
|---|---|
| process | Sysmon EventID 1（进程创建）/ 10（进程访问） |
| flow | Sysmon EventID 3（网络连接）/ Security 5156/5157 |
| file | Sysmon EventID 11（文件创建）/ 23（文件删除） |
| dns | Sysmon EventID 22（DNS 查询） |
| auth | Security 4624/4625/4648（登录） |

## 注意事项

- 所有场景均为**纯攻击活动**（无良性基线），用于识别与归因演示；若需误报过滤效果演示，可后续叠加模拟正常流量（data_gen 负责）。
- `persistence/schtasks` 场景（95MB）因被 Windows Defender 判定为含恶意载荷已删除；其余文件正常。
- 数据仅供研究与演示使用，请遵守各数据集许可（OTRF 数据集 CC BY 4.0 类许可；ThreatFox 数据引用其导出条款）。
- 下载地址：https://github.com/OTRF/Security-Datasets ；https://threatfox.abuse.ch/export/csv/recent/
