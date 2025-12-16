package watcher

import "github.com/Hara602/usbSentry/internal/model"

// DeviceWatcher 定义接口
type DeviceWatcher interface {
	Start() (<-chan model.USBEvent, error)
	Stop()
}

func New() DeviceWatcher {
	return newWatcher()
}
