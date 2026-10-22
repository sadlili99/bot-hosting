# 梨园托管台 · Bot 托管（真实托管版 v2）

一个能**真正托管 Python Bot** 的控制台：上传 .py → 服务器真实运行进程 → 看真实日志与真实 CPU/内存 → 启停/重启/删除。界面里没有任何演示数据：未登录不显示数据，后端没连上就只显示未连接状态。

## 它怎么工作

- 后端 `server.py`（Python 标准库，零依赖）同时提供页面和 API
- 每个 Bot 一个独立进程：
  - 有 systemd 的服务器：用 systemd 瞬时服务托管，`CPUQuota` / `MemoryMax` 真实限额，崩溃由 systemd 自动拉起，日志进 journal
  - 无 systemd 的环境（如 Codespaces）：回退独立进程组 + 内存上限，崩溃由后端看门狗自动重启（最多连 5 次）
- 指标全部实时读真实来源：进程 `/proc`、systemd `CPUUsageNSec/MemoryCurrent`、主机 `/proc/stat`、`/proc/meminfo`

## 数据保留（重点）

- 账号、会话、Bot 登记、扫描结果、操作审计都在 SQLite：`data/hosting.db`
- 上传的源文件存两份：磁盘 `data/bots/<id>/main.py` + 数据库 BLOB 备份，磁盘文件丢了能按库恢复
- 日志存 `data/logs/`（进程模式）或 journal（systemd 模式）
- **退出登录、重启后端，Bot 和文件都还在**；systemd 模式下后端重启期间 Bot 进程不中断，重启后自动重新接管显示
- 部署平台必须给 `data/` 一块不会被重置的磁盘，否则平台重启会丢数据（见下方各方式说明）

## 安全

- 第一次打开时创建管理员（scrypt 哈希存库），之后登录使用，HttpOnly 会话 Cookie（7 天）
- 登录限流（同 IP 每分钟 10 次）、写接口校验来源
- 上传先静态扫描（带行号）：删文件、系统命令、读凭证等高风险调用必须管理员勾选确认才登记
- 每个 Bot 独立工作目录、独立进程/服务，互不干扰

## 运行方式

### 1）GitHub Codespaces（在 GitHub 上真跑，临时公网）

仓库已带 `.devcontainer` 配置：打开仓库 → Code → Codespaces → Create，环境起来后后端自动在 8080 启动。
把 8080 端口的可见性改成 **Public**，用生成的 `*.app.github.dev` 地址打开即可。
注意：Codespace 闲置约 30 分钟会停机，停机期间 Bot 不运行；免费额度有限，适合试用演示，不适合长期营业。

### 2）自己的服务器（长期正解）

```bash
git clone https://github.com/sadlili99/bot-hosting.git
cd bot-hosting
python3 server.py            # 默认 8080，PORT 环境变量可改
```

或用仓库里的 `liyuan-bot-host.service` 注册成系统服务（改路径后 `systemctl enable --now liyuan-bot-host`）。
前面再挂 Nginx/Caddy 反代 HTTPS 即可对外使用。

### 3）GitHub Pages 上的页面

Pages 地址（`https://sadlili99.github.io/bot-hosting/`）只是同一份前端静态页，本身跑不了后端：
打开会显示「后端未连接」，把方式 1 或 2 的后端 https 地址填进登录页下方的「后端地址设置」即可连上管理。

## 接口一览

| 接口 | 说明 |
|---|---|
| `GET /api/health` | 后端健康检查（含 systemd 是否可用） |
| `POST /api/setup` / `POST /api/login` / `POST /api/logout` | 初始化管理员 / 登录 / 退出 |
| `GET /api/host` | 主机真实指标 |
| `GET /api/bots` | Bot 列表（真实状态与指标） |
| `POST /api/bots` | 上传 .py（请求头带名称/限额，体为文件内容） |
| `POST /api/bots/<id>/start\|stop\|restart` | 启停重启 |
| `GET /api/bots/<id>/logs` | 真实日志（文件或 journal） |
| `GET /api/bots/<id>/download` | 下载源文件（校验与原件一致） |
| `DELETE /api/bots/<id>` | 停止并删除 |
| `GET /api/audit` | 操作审计 |
