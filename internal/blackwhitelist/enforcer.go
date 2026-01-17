package blackwhitelist

import (
	"fmt"
	"os"
	"path/filepath"
)

// BlockDevice 通过 Sysfs 禁用设备
// busID 类似于 "1-1.2" (从 uevent 获取)
func BlockDevice(busID string) error {
	// 路径: /sys/bus/usb/devices/1-1.2/authorized
	path := filepath.Join("/sys/bus/usb/devices", busID, "authorized")
	// 写入 "0" 代表物理层级禁用
	err := os.WriteFile(path, []byte("0"), 0644)
	if err != nil {
		return fmt.Errorf("block failed: %v", err)
	}
	return nil
}
