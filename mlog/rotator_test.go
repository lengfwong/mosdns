package mlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestParseSize(t *testing.T) {
	size, err := ParseSize("")
	if err != nil {
		t.Fatalf("ParseSize(\"\") failed: %v", err)
	}
	if expected := int64(5 * 1024 * 1024); size != expected {
		t.Errorf("expected default size %d, got %d", expected, size)
	}

	size, err = ParseSize("10M")
	if err != nil {
		t.Fatalf("ParseSize(\"10M\") failed: %v", err)
	}
	if expected := int64(10 * 1024 * 1024); size != expected {
		t.Errorf("expected size %d, got %d", expected, size)
	}
}

func TestNewLoggerBackups(t *testing.T) {
	lc := LogConfig{
		File:    "test.log",
		Backups: 0,
	}
	// Verify that ParseSize and logger construction work without forcing backups to 3
	_, err := NewLogger(lc)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
}

func TestNewLoggerProduction(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test_prod.log")
	lc := LogConfig{
		File:       tmpFile,
		Production: true,
	}
	logger, err := NewLogger(lc)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	logger.Info("hello production", zap.String("key", "val"))
	_ = logger.Sync()

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("read log file failed: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("expected valid json from production logger, got %s: %v", string(data), err)
	}
	if m["key"] != "val" || m["msg"] != "hello production" {
		t.Fatalf("unexpected json log content: %v", m)
	}
}
