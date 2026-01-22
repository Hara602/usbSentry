//go:build linux

package monitor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/Hara602/usbSentry/internal/analysis"
	"github.com/Hara602/usbSentry/internal/model"
	"github.com/Hara602/usbSentry/internal/sysutil"
	"golang.org/x/sys/unix"
)

type fanotifyMonitor struct {
	fdBlocker  int // 用于拦截和精准路径 (PRE_CONTENT)
	fdRecorder int // 用于记录文件名 (NOTIF + DFID)
	mountPath  string
	selfPid    int
	events     chan model.FileEvent
	stop       chan struct{}
}

var typeInspector = analysis.NewTypeInspector()

func newMonitor() (FileMonitor, error) {
	// 1. 初始化 Blocker (保镖): 负责拦截、执行检查、文件写入完成检查
	// 使用 PRE_CONTENT，内核会直接给 FD
	flagsBlocker := uint(unix.FAN_CLASS_PRE_CONTENT |
		unix.FAN_CLOEXEC |
		unix.FAN_UNLIMITED_QUEUE |
		unix.FAN_UNLIMITED_MARKS |
		unix.FAN_NONBLOCK)

	fdBlocker, err := unix.FanotifyInit(flagsBlocker, unix.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("fanotify init blocker failed: %v", err)
	}

	// 2. 初始化 Recorder (记者): 负责记录创建和删除
	// 使用 REPORT_DFID_NAME，可以拿到 CREATE/DELETE 的文件名
	flagsRecorder := uint(unix.FAN_CLASS_NOTIF |
		unix.FAN_REPORT_DFID_NAME |
		unix.FAN_CLOEXEC |
		unix.FAN_UNLIMITED_QUEUE |
		unix.FAN_UNLIMITED_MARKS)

	fdRecorder, err := unix.FanotifyInit(flagsRecorder, unix.O_RDONLY)
	if err != nil {
		unix.Close(fdBlocker) // 失败要回滚
		return nil, fmt.Errorf("fanotify init recorder failed: %v", err)
	}

	return &fanotifyMonitor{
		fdBlocker:  fdBlocker,
		fdRecorder: fdRecorder,
		mountPath:  "",
		selfPid:    os.Getpid(),
		events:     make(chan model.FileEvent, 100),
		stop:       make(chan struct{}),
	}, nil
}

func (f *fanotifyMonitor) Start() {
	// 启动两个协程，分别监听两个 FD
	go f.readLoop(f.fdBlocker, "Blocker")
	go f.readLoop(f.fdRecorder, "Recorder")
}

// 通用的读取循环
func (f *fanotifyMonitor) readLoop(fd int, role string) {
	var buf [4096]byte
	for {
		select {
		case <-f.stop:
			return
		default:
			n, err := unix.Read(fd, buf[:])

			// 处理非阻塞读取的 EAGAIN 错误
			if err == unix.EAGAIN {
				time.Sleep(2 * time.Millisecond)
				continue
			}

			if err != nil {
				if errors.Is(err, unix.EBADF) || errors.Is(err, unix.EINTR) {
					return
				}
				// 其他错误简单记录后继续
				continue
			}

			// 遍历 Buffer 处理所有事件
			offset := 0
			for offset < n {
				if offset+model.FanotifyEventMetadataSize > n {
					break
				}

				reader := bytes.NewReader(buf[offset : offset+model.FanotifyEventMetadataSize])
				var metadata unix.FanotifyEventMetadata
				if err := binary.Read(reader, binary.LittleEndian, &metadata); err != nil {
					sysutil.LogSugar.Error("fanotify metadata read failed: %v", err)
					break
				}

				// 检查完整性
				if metadata.Event_len < uint32(model.FanotifyEventMetadataSize) || offset+int(metadata.Event_len) > n {
					break
				}

				// 处理单个事件 (传递 fd 用于回写响应)
				f.processOneEvent(fd, role, buf[offset:offset+int(metadata.Event_len)], metadata)

				offset += int(metadata.Event_len)
			}
		}
	}
}

func (f *fanotifyMonitor) AddWatch(mountPath string) error {
	f.mountPath = mountPath

	// 1. Blocker 监听：权限拦截 + 写入完成
	// 这些事件都有 FD，路径精准
	maskBlocker := uint64(unix.FAN_CLOSE_WRITE |
		unix.FAN_OPEN_PERM | // 拦截打开
		unix.FAN_OPEN_EXEC_PERM | // 拦截执行
		unix.FAN_EVENT_ON_CHILD)

	err := unix.FanotifyMark(f.fdBlocker, unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM, maskBlocker, unix.AT_FDCWD, mountPath)
	if err != nil {
		return fmt.Errorf("blocker mark failed: %v", err)
	}

	// 2. Recorder 监听：创建、删除、移动
	// 这些事件没有 FD，但有文件名
	maskRecorder := uint64(unix.FAN_CREATE |
		unix.FAN_DELETE |
		unix.FAN_MOVED_TO |
		unix.FAN_MOVED_FROM |
		unix.FAN_ONDIR |
		unix.FAN_EVENT_ON_CHILD)

	err = unix.FanotifyMark(f.fdRecorder, unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM, maskRecorder, unix.AT_FDCWD, mountPath)
	if err != nil {
		fmt.Println("⚠️  Warning: Recorder MARK_FILESYSTEM failed, trying directory only mode...")
		// 尝试降级
		err = unix.FanotifyMark(f.fdRecorder, unix.FAN_MARK_ADD, maskRecorder, unix.AT_FDCWD, mountPath)
	}

	return err
}

func (f *fanotifyMonitor) RemoveWatch(mountPath string) {
	// 两个都要移除
	maskBlocker := uint64(unix.FAN_CLOSE_WRITE | unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM | unix.FAN_EVENT_ON_CHILD)
	_ = unix.FanotifyMark(f.fdBlocker, unix.FAN_MARK_REMOVE|unix.FAN_MARK_MOUNT, maskBlocker, unix.AT_FDCWD, mountPath)

	maskRecorder := uint64(unix.FAN_CREATE | unix.FAN_DELETE | unix.FAN_MOVED_TO | unix.FAN_MOVED_FROM | unix.FAN_ONDIR | unix.FAN_EVENT_ON_CHILD)
	_ = unix.FanotifyMark(f.fdRecorder, unix.FAN_MARK_REMOVE|unix.FAN_MARK_MOUNT, maskRecorder, unix.AT_FDCWD, mountPath)
}

// processOneEvent 处理单个事件
func (f *fanotifyMonitor) processOneEvent(fd int, role string, eventBuf []byte, metadata unix.FanotifyEventMetadata) {
	// 检查版本
	if metadata.Vers != unix.FANOTIFY_METADATA_VERSION {
		return
	}

	// 1. 确保 FD 关闭 (非常重要，防止泄露)
	// Blocker 模式下内核会给打开的 FD
	if metadata.Fd >= 0 {
		defer unix.Close(int(metadata.Fd))
	}

	// 防死锁逻辑：如果是自己触发的事件，直接放行
	if int(metadata.Pid) == f.selfPid {
		if metadata.Mask&unix.FAN_ALL_PERM_EVENTS != 0 {
			// 必须回复 Allow，否则自己的 os.Open 会卡死
			f.replyAllow(fd, metadata.Fd)
		}
		return // 直接退出，不要自己监控自己
	}

	// 获取进程信息
	pid := int32(metadata.Pid)
	procName := getProcName(int(pid))
	eventOp := getEventOp(metadata.Mask)
	filePath := ""

	// 2. 路径获取逻辑 (双轨制)

	if role == "Blocker" {
		// [Blocker]：直接从 FD 获取路径
		// 优势：在 FAT32 上也能拿到绝对路径！
		if metadata.Fd >= 0 {
			linkPath := fmt.Sprintf("/proc/self/fd/%d", metadata.Fd)
			if path, err := os.Readlink(linkPath); err == nil {
				filePath = path
			}
		}
	} else {
		// [Recorder]：从 Buffer 解析文件名
		// 优势：能拿到 DELETE 的文件名
		// 劣势：FAT32 上拿不到父目录，只能拼接到 U 盘根目录 (但这做日志足够了)
		filePath = f.parseFileNameFromBuffer(eventBuf)
		if filePath != "" {
			// 简单降级：拼接到挂载点根目录
			filePath = filepath.Join(f.mountPath, "...", filePath)
		}
	}

	// 如果没拿到路径，且不需要裁决，就提前结束
	if filePath == "" && (metadata.Mask&unix.FAN_ALL_PERM_EVENTS == 0) {
		return
	}

	// 3. 业务逻辑

	// A. 伪装文件检测 (仅 Blocker 的 CLOSE_WRITE 有效)
	if strings.Contains(eventOp, "CLOSE_WRITE") && filePath != "" {
		// 异步执行扫描！
		// 必须放到 go func 里，否则 Inspect 耗时会导致主循环无法读取下一个事件
		// 进而导致队列堆积，最终卡死系统
		go func(path string, pName string, pID int32) {
			result, err := typeInspector.Inspect(path)
			if err != nil {
				return
			}
			if result.IsMasquerade {
				sysutil.LogSugar.Warnf("🚨 Masquerade detected! [%s] %s", result.RiskLevel, path)
				// 隔离逻辑...
			} else {
				sysutil.LogSugar.Infof("✅ Safe file: %s (Type: %s)", path, result.RealExt)
			}
		}(filePath, procName, pid)
	}

	// B. 权限裁决 (拦截逻辑)
	if metadata.Mask&unix.FAN_ALL_PERM_EVENTS != 0 {
		// 默认放行
		f.replyAllow(fd, metadata.Fd)
	}

	// 4. 发送事件到 Channel
	f.events <- model.FileEvent{
		PID:       pid,
		ProcName:  procName,
		FilePath:  filePath,
		Operation: eventOp,
		TimeStamp: time.Now(),
	}
}

// 解析 Buffer 中的文件名 (用于 CREATE/DELETE 等没有 FD 的事件)
func (f *fanotifyMonitor) parseFileNameFromBuffer(buf []byte) string {
	reader := bytes.NewReader(buf)
	// 跳过 Metadata
	if _, err := reader.Seek(int64(model.FanotifyEventMetadataSize), io.SeekStart); err != nil {
		return ""
	}

	for {
		var infoFid model.FanotifyEventInfoFid
		if err := binary.Read(reader, binary.LittleEndian, &infoFid); err != nil {
			break
		}

		if infoFid.Hdr.InfoType == unix.FAN_EVENT_INFO_TYPE_DFID_NAME {
			var fileHandle model.FileHandle
			if err := binary.Read(reader, binary.LittleEndian, &fileHandle); err != nil {
				break
			}

			// 跳过 Handle 数据 (FAT32上我们不需要去解析它，因为解析会失败)
			if _, err := io.ReadFull(reader, make([]byte, fileHandle.HandleBytes)); err != nil {
				break
			}

			// 计算文件名长度
			headerSize := binary.Size(infoFid) + binary.Size(fileHandle)
			nameLen := int(infoFid.Hdr.Len) - headerSize - int(fileHandle.HandleBytes)

			if nameLen > 0 {
				nameBuf := make([]byte, nameLen)
				if _, err := io.ReadFull(reader, nameBuf); err == nil {
					// 去掉结尾的 null 字符
					if idx := bytes.IndexByte(nameBuf, 0); idx != -1 {
						return string(nameBuf[:idx])
					}
					return string(nameBuf)
				}
			}
		} else {
			// 跳过非 DFID_NAME 信息
			pad := int(infoFid.Hdr.Len) - binary.Size(infoFid)
			if pad > 0 {
				reader.Seek(int64(pad), io.SeekCurrent)
			}
		}
	}
	return ""
}

func getProcName(pid int) string {
	path := filepath.Join("/proc", strconv.Itoa(pid), "comm")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "process exited too fast"
		}
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

func (f *fanotifyMonitor) Stop() {
	close(f.stop)
	unix.Close(f.fdBlocker)
	unix.Close(f.fdRecorder)
}

func (f *fanotifyMonitor) Events() <-chan model.FileEvent { return f.events }

func getEventOp(mask uint64) string {
	var events []string
	if mask&unix.FAN_OPEN_PERM == unix.FAN_OPEN_PERM {
		events = append(events, "OPEN_PERM")
	}
	if mask&unix.FAN_OPEN_EXEC_PERM == unix.FAN_OPEN_EXEC_PERM {
		events = append(events, "EXEC_PERM")
	}
	if mask&unix.FAN_ACCESS_PERM == unix.FAN_ACCESS_PERM {
		events = append(events, "ACCESS_PERM")
	}
	if mask&unix.FAN_CREATE == unix.FAN_CREATE {
		events = append(events, "CREATE")
	}
	if mask&unix.FAN_CLOSE_WRITE == unix.FAN_CLOSE_WRITE {
		events = append(events, "CLOSE_WRITE")
	}
	if mask&unix.FAN_DELETE == unix.FAN_DELETE {
		events = append(events, "DELETE")
	}
	if mask&unix.FAN_MOVED_TO != 0 {
		events = append(events, "MOVED_TO")
	}

	if len(events) == 0 {
		return fmt.Sprintf("OTHER(0x%x)", mask)
	}
	return strings.Join(events, "|")
}

// 统一回复 Allow
func (f *fanotifyMonitor) replyAllow(fanotifyFd int, fileFd int32) {
	response := unix.FanotifyResponse{
		Fd:       fileFd,
		Response: uint32(unix.FAN_ALLOW),
	}
	buf := (*[unsafe.Sizeof(response)]byte)(unsafe.Pointer(&response))[:]
	unix.Write(fanotifyFd, buf)
}
