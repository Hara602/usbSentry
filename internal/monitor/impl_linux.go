//go:build linux

package monitor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Hara602/usbSentry/internal/analysis"
	"github.com/Hara602/usbSentry/internal/model"
	"github.com/Hara602/usbSentry/internal/sysutil"
	"golang.org/x/sys/unix"
)

type fanotifyMonitor struct {
	fd     int
	events chan model.FileEvent
	stop   chan struct{}
}

var typeInspector = analysis.NewTypeInspector()
var mountPoint string

func newMonitor() (FileMonitor, error) {
	flags := uint(unix.FAN_CLASS_NOTIF |
		unix.FAN_REPORT_DFID_NAME |
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
				var offset uint32
				for offset < uint32(n) {
					var fanotifyEventMetadata unix.FanotifyEventMetadata
					reader := bytes.NewReader(buf[:24])
					err := binary.Read(reader, binary.LittleEndian, &fanotifyEventMetadata)
					if err != nil {
						sysutil.LogSugar.Error("fanotify metadata read failed: %v", err)
					}

					f.processEvents(buf[offset+model.FanotifyEventMetadataSize:], fanotifyEventMetadata)
					offset += fanotifyEventMetadata.Event_len

				}

			}
		}
	}()
}

func (f *fanotifyMonitor) AddWatch(mountPath string) error {
	mountPoint = mountPath

	mask := uint64(unix.FAN_CLOSE_WRITE |
		unix.FAN_CREATE |
		unix.FAN_DELETE |
		unix.FAN_MOVED_TO |
		unix.FAN_MOVED_FROM |
		unix.FAN_ONDIR |
		unix.FAN_EVENT_ON_CHILD)

	// 标记监控点
	// 监控标志：创建、删除、移动
	// FAN_MARK_FILESYSTEM: 监控整个文件系统（挂载点），这样能递归监控所有子目录
	err := unix.FanotifyMark(f.fd, unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM, mask, unix.AT_FDCWD, mountPath)

	if err != nil {
		// 如果 MARK_FILESYSTEM 失败，尝试退化为普通目录监控 (不递归)
		fmt.Println("⚠️  Warning: FAN_MARK_FILESYSTEM failed, trying directory only mode...")
		err = unix.FanotifyMark(f.fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, mountPath)
		if err != nil {
			sysutil.LogSugar.Fatalf("FanotifyMark failed: %v", err)
		}
	}
	return err
}

func (f *fanotifyMonitor) RemoveWatch(mountPath string) {
	mask := uint32(unix.FAN_CREATE | unix.FAN_DELETE | unix.FAN_CLOSE_WRITE | unix.FAN_ONDIR | unix.FAN_EVENT_ON_CHILD)
	_ = unix.FanotifyMark(f.fd, unix.FAN_MARK_REMOVE|unix.FAN_MARK_MOUNT, uint64(mask), unix.AT_FDCWD, mountPath)
}

// 每次只处理一个事件
// fanotify事件结构：[FanotifyEventMetadata] + [FanotifyEventInfoFid1] + [FanotifyEventInfoFid2] ...
func (f *fanotifyMonitor) processEvents(buf []byte, fanotifyEventMetadata unix.FanotifyEventMetadata) {
	// buf内容：
	// [FanotifyEventInfoFid1] + [FanotifyEventInfoFid2] ...
	reader := bytes.NewReader(buf)
	// 检查版本
	if fanotifyEventMetadata.Vers != unix.FANOTIFY_METADATA_VERSION {
		return
	}
	// 获取进程信息
	pid := int32(fanotifyEventMetadata.Pid)
	procName := getProcName(int(pid))

	// 事件操作
	eventOp := getEventOp(fanotifyEventMetadata.Mask)

	// 循环读取每个FanotifyEventInfoFid
	// FanotifyEventInfoFid结构: [Header] + [FSID] + [FileHandle:只预留了位置] + [Name:一个以空字符终止的字符串，该字符串标识创建/删除/移动的目录项名称]
	// var offset uint32
	for {
		// 通过FanotifyEventInfoFid获取被修改的文件名称
		fileName := ""

		// 读取FanotifyEventInfoFid
		var FanotifyEventInfoFid model.FanotifyEventInfoFid
		if err := binary.Read(reader, binary.LittleEndian, &FanotifyEventInfoFid); err != nil {
			break
		}
		// sysutil.LogSugar.Debug(FanotifyEventInfoFid)

		// 只关心 DFID_NAME 类型的信息
		if FanotifyEventInfoFid.Hdr.InfoType == unix.FAN_EVENT_INFO_TYPE_DFID_NAME {
			// handle_bytes 是f_handle的长度字段
			var fileHandle model.FileHandle
			if err := binary.Read(reader, binary.LittleEndian, &fileHandle); err != nil {
				break
			}

			// 跳过FileHandle中的FHandle
			if _, err := reader.Seek(int64(fileHandle.HandleBytes), io.SeekCurrent); err != nil {
				sysutil.LogSugar.Error("reader.Seek(int64(fileHandle.HandleBytes), io.SeekCurrent):", err)
				break
			}

			// FanotifyEventInfoHeader(4字节) + FSID(8字节) + FileHandle(8字节) + FHandle
			nameLen := int(FanotifyEventInfoFid.Hdr.Len) - 4 - 8 - 8 - int(fileHandle.HandleBytes)
			if nameLen <= 0 {
				sysutil.LogSugar.Error("nameLen <= 0")
				break
			}

			// 读取文件名称，读完后reader指针指向了下一个FanotifyEventInfoFid
			nameBuf := make([]byte, nameLen)
			if _, err := io.ReadFull(reader, nameBuf); err != nil {
				sysutil.LogSugar.Error("io.ReadFull(reader, nameBuf):	", err)
				break
			}
			// bytes.IndexByte 找第一个 null 字符
			if idx := bytes.IndexByte(nameBuf, 0); idx != -1 {
				fileName = string(nameBuf[:idx])
			}

		}
		if fileName == "" {
			continue
		}

		if eventOp == "CLOSE_WRITE" {

			filePath := filepath.Join(mountPoint, fileName)
			result, err := typeInspector.Inspect(filePath)
			if err != nil {
				sysutil.LogSugar.Infof("filetype inspect failed:%s, err:%v", filePath, err)
			}
			if result.IsMasquerade {
				sysutil.LogSugar.Warnf("find masquerade file![%s]%s", result.RiskLevel, filePath)
				sysutil.LogSugar.Warnf("detailed:%s", result.Message)
				if result.RiskLevel == "HIGH" {
					os.Rename(filePath, filePath+".quarantine") // 隔离
				}
			} else {
				sysutil.LogSugar.Infof("✅ safe file: %s (Type: %s)", filePath, result.RealExt)
			}
		}

		f.events <- model.FileEvent{
			PID:       pid,
			ProcName:  procName,
			FilePath:  fileName,
			Operation: eventOp,
			TimeStamp: time.Now(),
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

func getEventOp(mask uint64) string {
	var events []string
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
	if mask&unix.FAN_MOVED_FROM != 0 {
		events = append(events, "MOVED_FROM")
	}
	if len(events) == 0 {
		return fmt.Sprintf("OTHER(0x%x)", mask)
	}
	return filepath.Join(events...) // 借用 Join 拼接字符串
}
