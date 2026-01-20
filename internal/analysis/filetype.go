package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/h2non/filetype"
)

// Result 检测结果
type Result struct {
	IsMasquerade bool   // 是否是伪装文件
	RealExt      string // 真实的类型后缀 (根据文件头)
	DeclaredExt  string // 声明的后缀 (文件名)
	RiskLevel    string // 风险等级: HIGH, MEDIUM, LOW, SAFE
	Message      string // 详细描述
}

// TypeInspector 文件类型检查器
type TypeInspector struct {
	// 使用 sync.Map 或读写锁保护 map，虽然在这个场景下 map 只读，
	// 但为了后续可能支持动态加载规则，加上锁更安全。
	aliasMap map[string]map[string]bool
	mu       sync.RWMutex
}

// NewTypeInspector 初始化检查器
func NewTypeInspector() *TypeInspector {
	inspector := &TypeInspector{
		aliasMap: make(map[string]map[string]bool),
	}
	inspector.initRules()
	return inspector
}

// initRules 初始化兼容性规则 (白名单)
// 这里定义了哪些“表里不一”是合法的
func (t *TypeInspector) initRules() {
	// 辅助函数：快速构建 map
	allow := func(realType string, allowedExts ...string) {
		if _, ok := t.aliasMap[realType]; !ok {
			t.aliasMap[realType] = make(map[string]bool)
		}
		// 允许真实的后缀本身 (zip -> zip)
		t.aliasMap[realType][realType] = true
		// 允许别名
		for _, ext := range allowedExts {
			t.aliasMap[realType][ext] = true
		}
	}

	// === 核心兼容性规则 ===

	// 1. ZIP 家族：最大的误报源
	// docx, xlsx 等本质都是 zip
	allow("zip",
		"docx", "docm", "dotx", "dotm", // Word
		"xlsx", "xlsm", "xltx", "xltm", // Excel
		"pptx", "pptm", "potx", "potm", // PowerPoint
		"jar", "war", "ear", // Java
		"apk",               // Android
		"odt", "ods", "odp", // OpenOffice
		"crx",   // Chrome Extension
		"whl",   // Python Wheel
		"nupkg", // Nuget
	)

	// 2. XML 家族
	allow("xml", "svg", "html", "htm", "kml", "dae", "plist", "config", "xml")

	// 3. 媒体容器
	allow("mp4", "m4v", "mov", "qt") // QuickTime 容器通常通用
	allow("ogg", "ogv", "oga", "spx")
	allow("mov", "qt", "mp4") // 反向兼容

	// 4. 可执行文件 (PE)
	// 有时候 .dll, .sys, .scr 也是 PE 格式，需要警惕但它们在技术上是一样的
	allow("exe", "dll", "sys", "scr", "cpl", "ocx")

	// 5. 压缩包
	allow("gz", "gzip", "tgz")
	allow("tar", "tar")
	allow("rar", "rar")
	allow("7z", "7z")
}

// Inspect 执行检测
func (t *TypeInspector) Inspect(filePath string) (*Result, error) {
	// 获取声明的后缀 (Declared Extension)
	rawExt := filepath.Ext(filePath)
	if rawExt == "" {
		// 没有后缀的文件，通常视为安全或需人工审查，这里暂且放行
		// 也可以策略性标记为 "SUSPICIOUS"
		return &Result{
			IsMasquerade: false,
			RiskLevel:    "SAFE",
			Message:      "No extension",
		}, nil
	}
	declaredExt := strings.ToLower(strings.TrimPrefix(rawExt, "."))

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open file failed:%v", err)
	}
	defer file.Close()

	// 读取文件头 (262 bytes 是 filetype 库建议的最佳长度)
	head := make([]byte, 262)
	n, err := file.Read(head)
	if err != nil && n == 0 {
		// 空文件：没有 Magic Bytes，无法判断，视为安全
		return &Result{IsMasquerade: false, RiskLevel: "SAFE", Message: "Empty file"}, nil
	}

	// 匹配真实类型
	kind, _ := filetype.Match(head)

	// 未知类型 (Unknown)
	// 很多纯文本文件(txt, go, c, py, md, json)会被识别为 Unknown
	// 策略：默认信任。
	if kind == filetype.Unknown {
		return &Result{
			IsMasquerade: false,
			RealExt:      "unknown",
			DeclaredExt:  declaredExt,
			RiskLevel:    "SAFE",
			Message:      "Unknown binary signature (likely text)",
		}, nil
	}

	realExt := kind.Extension

	// 文件类型扩展后缀与真实扩展完美匹配
	if realExt == declaredExt {
		return &Result{IsMasquerade: false, RealExt: realExt, DeclaredExt: declaredExt, RiskLevel: "SAFE"}, nil
	}

	// 检查兼容性白名单 (Alias Check)
	t.mu.RLock()
	allowedMap, exists := t.aliasMap[realExt]
	t.mu.RUnlock()

	if exists {
		if allowedMap[declaredExt] {
			// 在白名单里，虽然后缀不一致，但是合法的 (如 zip -> docx)
			return &Result{
				IsMasquerade: false,
				RealExt:      realExt,
				DeclaredExt:  declaredExt,
				RiskLevel:    "SAFE",
				Message:      fmt.Sprintf("Allowed alias: %s is compatible with %s", declaredExt, realExt),
			}, nil
		}
	}

	// 提升风险等级判断
	risk := "MEDIUM"
	if realExt == "exe" || realExt == "elf" || realExt == "dll" {
		risk = "HIGH" // 可执行文件伪装成其他格式，极度危险
	}

	msg := fmt.Sprintf("Type Mismatch! Header is '%s' but file is '%s'", realExt, declaredExt)

	return &Result{
		IsMasquerade: true,
		RealExt:      realExt,
		DeclaredExt:  declaredExt,
		RiskLevel:    risk,
		Message:      msg,
	}, nil

}
