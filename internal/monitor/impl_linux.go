//go:build linux

package monitor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/Hara602/usbSentry/internal/model"
	"github.com/Hara602/usbSentry/internal/sysutil"
	"golang.org/x/sys/unix"
)

// 核心逻辑：Fanotify 初始化 -> AddWatch (FAN_MARK_MOUNT) -> 循环读取 -> 解析 PID/ProcName

type fanotifyMonitor struct {
	fd     int
	events chan model.FileEvent
	stop   chan struct{}
}

func newMonitor() (FileMonitor, error) {
	flags := uint(unix.FAN_CLASS_NOTIF |
		unix.FAN_CLOEXEC |
		unix.FAN_UNLIMITED_QUEUE |
		unix.FAN_UNLIMITED_MARKS)
	eventFlags := uint(unix.O_RDONLY)
	fd, err := unix.FanotifyInit(flags, eventFlags)
	if err != nil {
		return nil, fmt.Errorf("fanotify init failed: %v", err)

	}
	return &fanotifyMonitor{
		fd:     fd,
		events: make(chan model.FileEvent, 100),
		stop:   make(chan struct{}),
	}, nil
}

func (f *fanotifyMonitor) Start() {
	go func() {
		var buf [4096]byte
		for {
			select {
			case <-f.stop:
				return
			default:
				n, err := unix.Read(f.fd, buf[:])
				if err != nil {
					continue
				}
				f.processEvents(buf[:n])

			}
		}
	}()
}

func (f *fanotifyMonitor) AddWatch(mountPath string) error {
	// FAN_MARK_MOUNT: 监控整个挂载点，这是监控 U 盘最高效的方式
	mask := uint64(unix.FAN_CLOSE_WRITE |
		unix.FAN_ONDIR |
		unix.FAN_EVENT_ON_CHILD)
	err := unix.FanotifyMark(f.fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, mask, unix.AT_FDCWD, mountPath)
	if err != nil {
		sysutil.LogSugar.Errorf("fanotify add watch failed: %v", err)
	}
	return err
}

func (f *fanotifyMonitor) RemoveWatch(mountPath string) {
	mask := uint32(unix.FAN_CREATE | unix.FAN_DELETE | unix.FAN_CLOSE_WRITE | unix.FAN_ONDIR | unix.FAN_EVENT_ON_CHILD)
	_ = unix.FanotifyMark(f.fd, unix.FAN_MARK_REMOVE|unix.FAN_MARK_MOUNT, uint64(mask), unix.AT_FDCWD, mountPath)
}

// processEvents 用来处理文件事件，获取修改文件的进程名及进程PID
func (f *fanotifyMonitor) processEvents(buf []byte) {
	reader := bytes.NewReader(buf)
	metadataSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for reader.Len() >= metadataSize {
		var metadata unix.FanotifyEventMetadata

		// 读取结构体
		if err := binary.Read(reader, binary.LittleEndian, &metadata); err != nil {
			break
		}

		// 检查版本
		if metadata.Vers != unix.FANOTIFY_METADATA_VERSION {
			continue
		}

		// 获取路径(通过FD)
		path := "unknown"
		if metadata.Fd >= 0 {
			linkPath := fmt.Sprintf("/proc/self/fd/%d", int(metadata.Fd))
			target, err := os.Readlink(linkPath)
			if err == nil {
				path = target
			} else {
				path = fmt.Sprintf("err_resolve: %s", err.Error())
			}

			unix.Close(int(metadata.Fd))
		}

		// 获取进程信息
		pid := int32(metadata.Pid)
		procName := getProcName(int(pid))

		op := "UNKNOWN"
		if metadata.Mask&unix.FAN_CLOSE_WRITE == unix.FAN_CLOSE_WRITE {
			// 文件写入后被关闭
			op = "CLOSE_WRITE"
		}
		// TODO: fanotify可以通过FAN_REPORT_FID模式监控文件的创建与删除，但是较为麻烦，留待后续开发
		// if metadata.Mask&unix.FAN_CREATE == unix.FAN_CREATE {
		// 	op = "CREATE"
		// } else if metadata.Mask&unix.FAN_DELETE == unix.FAN_DELETE {
		// 	op = "DELETE"
		// }
		if op != "UNKNOWN" {
			f.events <- model.FileEvent{
				PID:       pid,
				ProcName:  procName,
				FilePath:  path,
				Operation: op,
				TimeStamp: time.Now(),
			}
		}
	}
}

func getProcName(pid int) string {
	path := filepath.Join("/proc", strconv.Itoa(pid), "comm")
	b, err := os.ReadFile(path)
	if err != nil {
		// 如果是进程的文件不存在，说明进程已经退出了
		if os.IsNotExist(err) {
			return "process exited too fast"
		}
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

func (f *fanotifyMonitor) Stop() {
	close(f.stop)
	unix.Close(f.fd)
}

func (f *fanotifyMonitor) Events() <-chan model.FileEvent { return f.events }
