package blackwhitelist

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

var BWdb *sql.DB

// InitBlackWhiteDB 初始化数据库表结构
func InitBlackWhiteDB(dbPath string) error {
	var err error
	BWdb, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// 联合主键 (vid, pid, serial) 防止重复
	schema := `
	CREATE TABLE IF NOT EXISTS blackwhitelist (
		vid TEXT,
		pid TEXT,
		serial TEXT,
		reason TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (vid, pid, serial)
	);
	`
	_, err = BWdb.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}
	return nil
}

func IsBlocked(vid, pid, serial string) (bool, string) {
	// 无序列号直接阻断 (硬编码的高危规则)
	if serial == "" || serial == "000000000000" {
		return true, "Unknown or empty serial number"
	}

	// 查数据库黑名单
	var exists int
	err := BWdb.QueryRow(
		"SELECT 1 FROM blackwhitelist WHERE vid = ? AND pid = ? AND serial = ?",
		vid, pid, serial,
	).Scan(&exists)

	if err == nil && exists == 1 {
		return true, "Device is in blacklist"
	}

	// 默认放行
	return false, ""

}

// AddBlockRule 添加黑名单工具函数
func AddBlockRule(vid, pid, serial, reason string) {
	if BWdb != nil {
		BWdb.Exec(
			"INSERT OR IGNORE INTO blackwhitelist(vid,pid,serial,reason)VALUES (?, ?, ?, ?)",
			vid, pid, serial, reason,
		)
	}
}
