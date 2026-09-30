package logs

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"
	"time"

	"github.com/coroot/logparser"
	"k8s.io/klog/v2"
)

var (
	tailPollInterval = time.Second

	// tailMaxLineSize bounds the size of a partially read line kept in memory while waiting for its end.
	// When exceeded, the accumulated data is emitted as a separate entry.
	tailMaxLineSize = 1 << 20
)

type TailReader struct {
	fileName string
	ch       chan<- logparser.LogEntry

	file   *os.File
	info   os.FileInfo
	reader *bufio.Reader

	stop    context.CancelFunc
	stopped chan struct{}
}

func NewTailReader(fileName string, ch chan<- logparser.LogEntry) (*TailReader, error) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &TailReader{
		fileName: fileName,
		ch:       ch,
		stop:     cancel,
		stopped:  make(chan struct{}),
	}
	var err error
	if r.file, err = os.Open(fileName); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if r.file != nil { // the file may not exist yet, poll() waits for it to appear
		if r.info, err = r.file.Stat(); err != nil {
			_ = r.file.Close()
			return nil, err
		}
		if _, err = r.file.Seek(0, io.SeekEnd); err != nil {
			_ = r.file.Close()
			return nil, err
		}
		r.reader = bufio.NewReader(r.file)
	}

	go func() {
		var prefix string
		flush := func() {
			if prefix != "" {
				r.emit(prefix)
				prefix = ""
			}
		}
		for {
			select {
			case <-ctx.Done():
				r.stopped <- struct{}{}
				return
			default:
				if r.reader == nil {
					if r.poll(ctx) {
						// the partial line belongs to the previous file (or its truncated content)
						flush()
					}
					continue
				}
				line, err := r.reader.ReadString('\n')
				if err != nil {
					prefix += line
					if len(prefix) >= tailMaxLineSize {
						flush()
					}
					if r.poll(ctx) {
						flush()
					}
					continue
				}
				if prefix != "" {
					line = prefix + line
					prefix = ""
				}
				r.emit(strings.TrimSuffix(line, "\n"))
			}
		}
	}()

	return r, nil
}

func (r *TailReader) emit(content string) {
	r.ch <- logparser.LogEntry{
		Timestamp: time.Now(),
		Content:   content,
		Level:     logparser.LevelUnknown,
	}
}

func (r *TailReader) Stop() {
	klog.Infoln("stopping tail reader for", r.fileName)
	r.stop()
	<-r.stopped
	if r.file != nil {
		_ = r.file.Close()
	}
}

// poll waits until there is new data to read. It returns true if the reader has been switched
// to a new file or rewound because of truncation, i.e., any previously read partial line is stale.
func (r *TailReader) poll(ctx context.Context) bool {
	ticker := time.NewTicker(tailPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			if info, err := os.Stat(r.fileName); err != nil {
				if r.file != nil {
					_ = r.file.Close()
					r.file = nil
				}
			} else {
				if r.file == nil {
					f, err := os.Open(r.fileName)
					if err != nil {
						continue
					}
					r.file = f
					r.info = info
					r.reader = bufio.NewReader(r.file)
					return true
				}
				if r.moved(info) || r.truncated(info) {
					r.info = info
					return true
				}
				if r.appended(info) {
					r.info = info
					return false
				}
			}
		}
	}
}

func (r *TailReader) moved(info os.FileInfo) bool {
	if !os.SameFile(r.info, info) {
		f, err := os.Open(r.fileName)
		_ = r.file.Close()
		if err != nil {
			r.file = nil
			r.reader = nil
			return false
		}
		r.file = f
		r.reader = bufio.NewReader(r.file)
		return true
	}
	return false
}

func (r *TailReader) truncated(info os.FileInfo) bool {
	if r.file == nil {
		return false
	}
	if info.Size() < r.info.Size() {
		if _, err := r.file.Seek(0, io.SeekStart); err == nil {
			r.reader.Reset(r.file)
			return true
		}
	}
	return false
}

func (r *TailReader) appended(info os.FileInfo) bool {
	if r.file == nil {
		return false
	}
	if info.Size() > r.info.Size() {
		return true
	}
	return false
}
