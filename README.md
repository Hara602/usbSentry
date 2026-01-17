# usbSentry 是一个用于监控U盘内文件操作的工具
这是一个基于 Go 语言开发的系统后台 Agent，用于实时监控 USB 移动存储设备的插入状态及USB 设备上的文件操作活动（如文件修改、写入等）。

# 功能特性
1. USB 热插拔检测：自动识别已挂载的 USB 存储设备。
2. 文件活动监测：实时监控 USB 目录下的文件修改操作。
3. 进程关联：精准识别是哪个进程（如 gedit）触发了文件操作。
4. 结构化日志：输出 JSON 格式日志，便于集成到 ELK 或其他日志分析平台。

# 环境要求
操作系统: Linux (后续考虑添加 Windows 平台)

编程语言: Go 1.20+

权限: 需要 root 权限运行以访问 /proc 文件系统及某些设备节点。

# 快速开始
1.编译项目
```bash
# 下载依赖
go mod tidy

# 编译二进制文件
go build -o usbSentry ./cmd/agent/main.go
```
2.运行
```bash
sudo ./usbSentry
```

3.示例
```bash
2025-12-16T16:31:38.157+0800	INFO	agent/main.go:24	🛡️ USB Sentry Agent Starting...
2025-12-16T16:31:38.158+0800	INFO	agent/main.go:51	✅ USB Connected
2025-12-16T16:31:38.158+0800	INFO	agent/main.go:66	👀 Monitoring started	
```

# 功能列表及TODO
- [x] USB 热插拔检测：自动识别挂载的USB存储设备
- [x] 进程关联：精准识别是哪个进程触发了文件操作
- [x] 设备信息采集：记录设备的供应商 ID (VID)、产品 ID (PID)、序列号(serial)、设备类型
- [x] 文件活动监测：实时监控 USB 目录下的文件操作
  - 文件写后关闭 [√]
  - 文件创建 [√]
  - 文件删除 [√]
- [x] BadUSB监测：如果一个 USB 设备树下同时拥有 08(存储) 和 03(HID) 接口，则判定为 BadUSB
- [ ] 黑名单和白名单