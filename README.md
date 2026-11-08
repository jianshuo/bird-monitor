# BiRD Monitor

macOS 上 iCloud Drive 同步守护进程 **bird** 的只读状态监控器：本地网页仪表盘 + 可双击的 Mac App。

## 用法

```bash
./make_app.sh                 # 生成 ~/Applications/BirdMonitor.app（自包含，双击即用）
open ~/Applications/BirdMonitor.app

# 或者直接用命令行
bin/bird-monitor open         # 没在跑就后台启动，并打开 http://127.0.0.1:8790/
bin/bird-monitor status | stop | restart
```

- 端口默认 8790，可用 `BIRD_MONITOR_PORT=xxxx` 修改
- 日志：`~/Library/Logs/BirdMonitor.log`
- 只依赖 macOS 自带命令和 Python 3 标准库

## 能看到什么

| 标签页 | 内容 | 来源 |
|---|---|---|
| 总览 | 健康检查、CPU/网络/磁盘/WAL 曲线、日志事件分布 | proc_pid_rusage、nettop、stat、log |
| 正在做什么 | 同步区状态、pending activity、上传预算、最近的 CloudKit 操作、bird 打开的文件、活跃组件 | `brctl dump -i`、log、lsof |
| 错误 | SyncHealthReport、错误/警告按模式归并（次数、首次、最后、原文） | `brctl dump -i`、log |
| 数据库内容 | client.db / server.db 的条目数、类型构成、资料库排行、扩展名、大小分布、修改时间线、设备来源、最大/最近文件、废纸篓 | 完整 `brctl dump` |
| 队列与差异 | 条目上挂着的 sync-up / downloader 任务；server ⇄ client 逐条差异 | 完整 `brctl dump` |
| App 资料库 | 177 个 app library 的状态标记、App 版本、条目数、占用 | `brctl dump -i` + 完整 dump |
| 进程与系统 | bird / cloudd / nsurlsessiond / fileproviderd 进程表、内存曲线、系统、调度器、client_state、server_state、启动历史、配额、XPC 客户端、设备 | 同上 |
| 实时日志 | bird 日志流，可按级别/关键字过滤 | `log stream` |
| 原始输出 | `brctl dump -i`、`brctl status` 原文（敏感 token 已隐藏） | |
| 安全说明 | 安全原则 + 本次运行实际执行过的全部命令及次数 | |

## 安全约束

1. **从不打开数据库文件**：client.db / server.db 只做 `stat()`，不 sqlite、不复制、不读内容。
2. **库内容由 bird 自己交出**：`brctl dump` 通过 XPC 请求正在运行的 bird 读库输出（dump 头部写着 `from: running bird`）。
3. **禁用危险参数**：绝不用 `dump -d`（直接读库文件）、`dump -u`（升级数据库）、`diagnose`。
4. **只读命令**：ps、nettop、lsof、/usr/bin/log、brctl status/quota/accounts/dump、libproc `proc_pid_rusage`。
5. **不打扰 bird**：brctl 调用串行执行；概要 60 秒一次（约 1 秒）；完整 dump 60 分钟一次（bird 满载约 20 秒，图上用黄色阴影标出），可手动触发；`brctl quota` 会让 bird 向 iCloud 发一次配额请求，所以 30 分钟才查一次，并在操作列表里标为「本监控器触发」。
6. **不外传**：只监听 127.0.0.1，数据只在内存，push token / change token / record name 在展示前隐藏。

名称里的 `{n}` 是 macOS 自带的隐私脱敏（保留首尾字符，中间 n 个字符隐藏），监控器无法、也不尝试还原。

## 开发

```bash
brctl dump -o /tmp/d.txt && python3 server.py --selftest /tmp/d.txt   # 离线验证解析器
```
