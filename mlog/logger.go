/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package mlog

import (
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type LogConfig struct {
	// Level, See also zapcore.ParseLevel.
	Level string `yaml:"level"`

	// File that logger will be writen into.
	// Default is stderr.
	File string `yaml:"file"`

	// Production enables json output.
	Production bool `yaml:"production"`

	// Size of log file limit. Default is 1M.
	// Supported units: K, M, G, T. If no unit, defaults to M.
	Size string `yaml:"size"`

	// Max number of old log files to retain. Default is 3.
	// Set to a negative number to retain all files.
	Backups int `yaml:"backups"`
}

var (
	stderr = zapcore.Lock(os.Stderr)
	lvl    = zap.NewAtomicLevelAt(zap.InfoLevel)
	l      = zap.New(zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()), stderr, lvl))
	s      = l.Sugar()

	nop = zap.NewNop()

	isDebug bool
)

func IsDebug() bool {
	return isDebug
}

func NewLogger(lc LogConfig) (*zap.Logger, error) {
	lvl, err := zapcore.ParseLevel(lc.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}
	if lvl <= zapcore.DebugLevel {
		isDebug = true
	} else {
		isDebug = false
	}

	var out zapcore.WriteSyncer
	if lf := lc.File; len(lf) > 0 {
		maxSize, err := ParseSize(lc.Size)
		if err != nil {
			return nil, fmt.Errorf("invalid log size limit: %w", err)
		}

		backups := lc.Backups
		if backups == 0 {
			backups = 3
		}

		rotator := &Rotator{
			Filename:   lf,
			MaxSize:    maxSize,
			MaxBackups: backups,
		}
		out = zapcore.AddSync(rotator)
	} else {
		out = stderr
	}

	encoderConfig := zap.NewDevelopmentEncoderConfig()
	encoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.Format("2006-01-02 15:04:05"))
	}

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		out,
		lvl,
	)

	return zap.New(core), nil
}

// L is a global logger.
func L() *zap.Logger {
	return l
}

// SetLevel sets the log level for the global logger.
func SetLevel(l zapcore.Level) {
	lvl.SetLevel(l)
}

// S is a global logger.
func S() *zap.SugaredLogger {
	return s
}

// Nop is a logger that never writes out logs.
func Nop() *zap.Logger {
	return nop
}
