package analysis

import (
	"os"
	"path/filepath"
	"strings"
)

// CheckBadUSB 如果一个 USB 设备树下同时拥有 08(存储) 和 03(HID) 接口，则判定为 BadUSB
func CheckBadUSB(sysPath string) (bool, string) {
	files, err := os.ReadDir(sysPath)
	if err != nil {
		return false, "unknown"
	}
	hasStorage := false
	hasHID := false
	for _, f := range files {
		// 遍历接口目录，例如 1-1:1.0
		if strings.Contains(f.Name(), ":") {
			classPath := filepath.Join(sysPath, f.Name(), "bInterfaceClass")
			content, _ := os.ReadFile(classPath)
			classCode := strings.TrimSpace(string(content))
			if classCode == "03" {
				hasHID = true
			}
			if classCode == "08" {
				hasStorage = true
			}
		}
	}
	if hasStorage && hasHID {
		return true, "BADUSB_SUSPECT"
	} else if hasStorage {
		return false, "udisk"
	}
	return false, "other"
}
