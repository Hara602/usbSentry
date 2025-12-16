//go:build linux

package sysutil

import (
	"bufio"
	"os"
	"strings"
	"time"
)

// WaitForMount 轮询 /proc/mounts 等待设备挂载
func WaitForMount(devPath string) string {
	// 尝试 3 秒，因为 Udev event 触发时，文件系统可能还没挂载好
	for i := 0; i < 30; i++ {
		f, _ := os.Open("/proc/mounts")
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 && fields[0] == devPath {
				f.Close()
				return fields[1]
			}
		}
		f.Close()
		time.Sleep(100 * time.Millisecond)
	}
	return ""
}
