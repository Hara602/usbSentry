package monitor

import "github.com/Hara602/usbSentry/internal/model"

type FileMonitor interface {
	Start()
	Stop()
	AddWatch(mountPath string) error // 动态添加监控 (Req 2)
	RemoveWatch(mountPath string)
	Events() <-chan model.FileEvent
}

func New() (FileMonitor, error) {
	return newMonitor()
}
