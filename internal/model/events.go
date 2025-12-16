package model

import "time"

// USBEvent 硬件插拔事件
type USBEvent struct {
	Action     string // "add", "remove"
	DevicePath string // e.g., /dev/sdb1
	MountPoint string // e.g., /media/usb
	VendorID   string
	ProductID  string
	Serial     string
	DeviceType string // "udisk", "badusb_suspect"
	TimeStamp  time.Time
}

type FileEvent struct {
	PID       int32  // 进程ID
	ProcName  string // 进程名
	FilePath  string
	Operation string
	TimeStamp time.Time
}
