# BiRD Monitor

macOS 上 iCloud Drive 同步守护进程 **bird** 的只读状态监控器：一条命令启动的本地网页仪表盘。

## 用法

```bash
ln -s ~/code/bird-monitor/bin/bird-monitor ~/.local/bin/bird-monitor   # 装一次

bird-monitor            # 没在跑就后台启动，并打开 http://127.0.0.1:8790/
bird-monitor status     # 看是否在运行
bird-monitor stop | restart
```

### 看另一台 Mac（远程）

```bash
bird-monitor pro sync     # 把代码 rsync 到远程 ~/code/bird-monitor 并（重）启动，建好 SSH 隧道
bird-monitor pro          # 确保远程在跑 + 隧道 + 打开 http://127.0.0.1:8791/
bird-monitor pro status   # 远程服务和隧道状态
bird-monitor pro stop     # 关隧道并停掉远程服务
```

远程的监控器同样只监听它自己的 127.0.0.1，本机经 `ssh -L` 隧道访问，不对网络开放。远程主机默认是 ssh 别名 `pro`，
可用 `BIRD_MONITOR_REMOTE=<ssh 主机>` 改；本机隧道端口默认 8791（`BIRD_MONITOR_TUNNEL_PORT`）。需要免密 SSH。

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

## 大文件逐个上传（bin/icloud-serial-upload）

bird 把所有待传文件打成一批上传，网络断一次整批失败重来。上行慢、连接又时常断开时，几十 GB 的一批可能永远传不完
（监控器会报「上传反复失败」）。这个工具让 bird 一次只传一个，大文件切成一小时内传得完的块：

```bash
icloud-serial-upload plan --dry-run --chunk 800M <iCloud Drive 里的待传文件…>   # 先检查、看计划
icloud-serial-upload plan --chunk 800M <文件…>   # 挪到 ~/iCloudSerialUpload，超过块大小的按字节切块并 SHA-256 校验
nohup icloud-serial-upload run &                 # 传完一个（不再出现在 brctl status 的待传列表）就放回下一个
icloud-serial-upload status                      # 进度、实测速度、预计剩余时间
```

- 只接受「完整在本地、且 brctl status 显示正等待上传」的文件：服务器上已有的文件挪出 iCloud Drive 等于删除，一律拒绝
- 只用同卷改名，从不删除；原文件保留在 `~/iCloudSerialUpload/originals/`
- 分块名 `xxx.zip.001 …`，旁边附「合并说明」（`cat xxx.zip.0* > xxx.zip` 及原文件 SHA-256），Keka / 7-Zip 可直接打开 `.001`
- 块大小按实测最慢速度留余量：一次只传一个文件时 iCloud 并行度低，实测约 0.36 MB/s，800 MB ≈ 37 分钟

## 名称还原

macOS 26 起 `brctl dump` 会把名称脱敏成 `D{7}s` 这样（保留首尾字符，中间 n 个字符隐藏），本身不可逆。
监控器的做法是到本机文件系统里找回真名：

1. 资料库名（如 `i{4}d.c{1}m.t{5}t.m{1}q`）与 `~/Library/Mobile Documents` 下的文件夹名（`~` 换回 `.`）按「首尾字符＋长度」比对；
2. 文件按 dump 里记录的父目录链逐级 `ls`，只在同一目录内比对，撞车时再用类型和大小区分，仍分不开就标「歧义」，不猜；
3. 只读：只 `scandir` / `lstat`，不打开文件；云端占位（dataless）目录不列，避免触发下载；只解析页面上展示的条目。

在 Neo 上实测：展示的条目还原率约 80%（其余多为已删除、本地无文件），资料库名 177/177，并用另一台 macOS 15 的明文 dump 核对资料库名 103/103 一致。
页面右上角「真名 / 脱敏」可一键切换，截图分享前切回脱敏。真名只显示在本机浏览器里，不落盘、不外传。

已在 macOS 15.7 和 26.4 上验证。

## 开发

```bash
brctl dump -o /tmp/d.txt && python3 server.py --selftest /tmp/d.txt   # 离线验证解析器
```
