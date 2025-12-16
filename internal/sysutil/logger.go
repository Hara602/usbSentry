package sysutil

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Log *zap.Logger
var LogSugar *zap.SugaredLogger

func InitLogger() {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder        // 格式化时间输出
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder // 彩色级别
	// 开发模式：输出到控制台，带颜色和行号
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(config.EncoderConfig),
		zapcore.AddSync(os.Stdout),
		zap.DebugLevel,
	)
	Log = zap.New(core, zap.AddCaller())
	LogSugar = Log.Sugar()
}
