package mlog

import (
	"testing"
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
