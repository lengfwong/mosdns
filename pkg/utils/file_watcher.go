package utils

import (
	"os"
	"time"
)

// FileWatcher periodically checks the modification time of the specified files.
type FileWatcher struct {
	done chan struct{}
}

// StartFileWatcher starts a new FileWatcher that checks files every 'interval'.
// If any file modification time changes or a file is missing, onChange is triggered.
// Note: onChange must be safe to run concurrently with other components.
func StartFileWatcher(files []string, interval time.Duration, onChange func(changedFiles []string)) *FileWatcher {
	if len(files) == 0 {
		return nil
	}
	fw := &FileWatcher{
		done: make(chan struct{}),
	}
	go func() {
		modTimes := make(map[string]time.Time)
		for _, f := range files {
			stat, err := os.Stat(f)
			if err == nil {
				modTimes[f] = stat.ModTime()
			}
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-fw.done:
				return
			case <-ticker.C:
				var changedFiles []string
				for _, f := range files {
					stat, err := os.Stat(f)
					if err != nil {
						if os.IsNotExist(err) {
							// File is missing or deleted.
							if mt, ok := modTimes[f]; ok && !mt.IsZero() {
								modTimes[f] = time.Time{} // mark as missing
								changedFiles = append(changedFiles, f)
							}
						}
						continue
					}

					if mt, ok := modTimes[f]; !ok || mt != stat.ModTime() {
						modTimes[f] = stat.ModTime()
						changedFiles = append(changedFiles, f)
					}
				}
				if len(changedFiles) > 0 {
					onChange(changedFiles)
				}
			}
		}
	}()
	return fw
}

// Close stops the FileWatcher.
func (fw *FileWatcher) Close() error {
	if fw != nil {
		close(fw.done)
	}
	return nil
}
