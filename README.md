# Security Baseline Checker（安全基线检查系统）

基于 **GB/T 22239-2019《信息安全技术 网络安全等级保护基本要求》** 的主机 / 数据库 / 中间件安全基线检查系统。通过 Web 页面即可对大批量主机发起自动化基线检查，输出符合率报告并可导出 Word 检查报告。

## 功能特性

- **多基线检查库（276 项）**
  - Linux 主机基线（50 项）：身份鉴别 / 访问控制 / 安全审计 / 剩余信息保护 / 入侵防范 / 恶意代码防范 / 资源控制
  - Windows 主机基线（50 项）：同上七大类
  - 数据库基线（80 项）：MySQL/MariaDB、PostgreSQL、Oracle、SQL Server、MongoDB、Redis、达梦 DM
  - 中间件基线（88 项）：Nginx、Apache、Tomcat、WebLogic、Kafka、Redis、RabbitMQ、Nacos
- **自动判定 + 人工复核**：可自动判定的检查项（检查命令 + 通过标准）自动输出"符合 / 不符合"；指导书标注人工核查的项展示命令输出与通过标准，人工点选判定
- **组件自动识别**：检查前自动探测目标主机上安装的数据库/中间件，只对识别到的组件执行对应基线
- **批量 + 定时扫描**：多主机批量运行；定时任务支持每天 / 每N小时 / 每周，运行组汇总展示
- **批量主机导入**：粘贴文本或上传 CSV 批量导入主机 SSH / WinRM 凭据（加密存储）
- **多协议连接**：Linux 走 SSH；Windows 可选 SSH（OpenSSH）或 WinRM（原生，无需额外安装）
- **Word 报告导出**：汇总表 + 不符合项清单 + 全量明细，一键导出 `.docx`

## 技术栈

Python 3.10+ / Flask / SQLite / Paramiko / pywinrm / python-docx。无外部 CDN 依赖，纯内网可部署。

## 快速开始

```bash
# 1. 克隆并安装依赖
git clone https://github.com/0to1-labs/security-baseline-checker.git
cd security-baseline-checker
python3 -m venv venv
venv/bin/pip install -r requirements.txt      # Windows: venv\Scripts\pip

# 2. （可选）自定义初始管理员密码
export INIT_ADMIN_PASSWORD='你的强密码'

# 3. 启动（默认监听 0.0.0.0:8090）
venv/bin/python app.py
```

浏览器访问 `http://<ip>:8090`，默认账号 `admin`（初始密码见上方环境变量，默认 `Baseline@2026`，**登录后请立即修改**）。

### 生产部署（systemd）

```bash
sudo cp baseline-checker.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now baseline-checker
```

服务单元默认部署目录为 `/opt/security-baseline`，可按需修改。

## 使用流程

1. **主机管理** → 添加主机（IP、端口、系统类型、连接方式 SSH/WinRM、账号密码；数据库基线可另填数据库账号密码），或粘贴/上传 CSV 批量导入：

   ```
   名称,IP,端口,系统类型,连接方式,账号,密码,数据库账号,数据库密码
   web-01,192.168.1.10,22,linux,ssh,root,P@ssw0rd,,
   db-01,192.168.1.20,22,linux,ssh,root,P@ssw0rd,root,DbP@ss
   win-01,192.168.1.30,5985,windows,winrm,administrator,P@ssw0rd,,
   ```

2. **发起检查** → 勾选多台主机 → 选择"自动识别（推荐）"或指定基线 → 开始
3. **查看结果** → 运行组页看各主机识别到的组件和任务汇总 → 点进单个任务看逐项判定，人工复核待人工项 → 导出 Word 报告
4. **定时任务** → 新建（多选主机 + 频率）→ 系统自动按时批量扫描

## 检查库来源与维护

`checklib.json` 为结构化检查库（检查项 / 检查命令 / 通过标准 / 人工核查标记）。如需从自己的基线检查指导书 docx 重新生成：

```bash
python parse_lib.py <指导书所在目录>
```

docx 需满足"检查项 | 检查项含义 | 为什么要检查 | 预期结果 | 检查命令与通过判定"的表格结构。

## 安全说明

- 目标主机凭据使用 **Fernet 对称加密** 存储于服务器本地（`data/` 目录，请勿泄露该目录）
- 所有检查命令均为**只读命令**，不会修改目标主机任何配置
- 检查数据（SQLite）与密钥文件均在 `data/` 目录，`data/` 已在 `.gitignore` 中，不会被提交
- 本系统面向**已授权环境**的合规检查，请勿用于未授权测试
- 建议：为系统配置 HTTPS 反向代理、限制访问来源 IP、及时修改初始密码

## 目录结构

```
├── app.py            # Flask 应用（Web UI、任务调度、报告导出）
├── engine.py         # 检查引擎（SSH/WinRM 连接器、组件探测、判定执行）
├── rules.py          # 自动判定规则库（正则/数值/空输出/自定义函数）
├── parse_lib.py      # 检查指导书 docx → checklib.json 生成器
├── checklib.json     # 276 项结构化检查库
├── baseline-checker.service
├── templates/        # 页面模板
└── static/           # 样式
```

## License

MIT
