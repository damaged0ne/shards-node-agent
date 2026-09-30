package logs

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coroot/logparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTailReader(t *testing.T) {
	f, err := ioutil.TempFile("/tmp", "log")
	assert.NoError(t, err)
	defer os.Remove(f.Name())

	// the file doesn't exist yet
	err = os.Remove(f.Name())
	assert.NoError(t, err)

	tailPollInterval = time.Millisecond * 100
	ch := make(chan logparser.LogEntry, 10)
	tr, err := NewTailReader(f.Name(), ch)
	assert.NoError(t, err)
	defer tr.Stop()

	write := func(s string) {
		_, err = f.WriteString(s)
		assert.NoError(t, err)
	}

	wait := func() {
		time.Sleep(time.Second)
	}

	get := func(expected string) {
		entry := <-ch
		assert.Equal(t, expected, entry.Content)
	}

	// the file is created
	wait()
	f, err = os.Create(f.Name())
	assert.NoError(t, err)

	write("foo 1\n")
	get("foo 1")

	// append
	write("bar 1\nbuz 1\n")
	get("bar 1")
	get("buz 1")

	// no end of line
	write("foo 2\nba")
	wait()
	write("r 2\n")
	get("foo 2")
	get("bar 2")

	// move
	err = os.Rename(f.Name(), f.Name()+".1")
	assert.NoError(t, err)
	defer os.Remove(f.Name() + ".1")
	f, err = os.Create(f.Name())
	assert.NoError(t, err)
	write("foo 3\nbar 3\n")
	get("foo 3")
	get("bar 3")

	// truncate
	f, err = os.OpenFile(f.Name(), os.O_WRONLY|os.O_TRUNC, 0)
	assert.NoError(t, err)
	write("foo 4\n")
	get("foo 4")

	// delete
	err = os.Remove(f.Name())
	assert.NoError(t, err)
	wait()
	f, err = os.Create(f.Name())
	assert.NoError(t, err)
	write("foo 5\n")
	get("foo 5")
}

func newTestTailReader(t *testing.T) (*os.File, chan logparser.LogEntry, *TailReader) {
	tailPollInterval = time.Millisecond * 20
	f, err := os.Create(filepath.Join(t.TempDir(), "log"))
	require.NoError(t, err)
	ch := make(chan logparser.LogEntry, 10)
	tr, err := NewTailReader(f.Name(), ch)
	require.NoError(t, err)
	t.Cleanup(func() {
		tr.Stop()
		_ = f.Close()
	})
	return f, ch, tr
}

func writeAndWait(t *testing.T, f *os.File, s string) {
	_, err := f.WriteString(s)
	require.NoError(t, err)
	time.Sleep(tailPollInterval * 5)
}

func expectEntry(t *testing.T, ch chan logparser.LogEntry, expected string) {
	select {
	case e := <-ch:
		assert.Equal(t, expected, e.Content)
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for %q", expected)
	}
}

func expectNoEntry(t *testing.T, ch chan logparser.LogEntry) {
	select {
	case e := <-ch:
		t.Fatalf("unexpected entry %q", e.Content)
	case <-time.After(tailPollInterval * 5):
	}
}

func TestTailReaderMultiChunkLine(t *testing.T) {
	f, ch, _ := newTestTailReader(t)
	writeAndWait(t, f, "part1-")
	writeAndWait(t, f, "part2-")
	writeAndWait(t, f, "part3-")
	expectNoEntry(t, ch)
	writeAndWait(t, f, "part4\nnext\n")
	expectEntry(t, ch, "part1-part2-part3-part4")
	expectEntry(t, ch, "next")
}

func TestTailReaderMaxLineSize(t *testing.T) {
	orig := tailMaxLineSize
	t.Cleanup(func() { tailMaxLineSize = orig }) // runs after the reader is stopped
	tailMaxLineSize = 10
	f, ch, _ := newTestTailReader(t)
	writeAndWait(t, f, "12345")
	expectNoEntry(t, ch)
	writeAndWait(t, f, "678901")
	expectEntry(t, ch, "12345678901")
	writeAndWait(t, f, "23\n")
	expectEntry(t, ch, "23")
}

func TestTailReaderTruncationResetsPartialLine(t *testing.T) {
	f, ch, _ := newTestTailReader(t)
	writeAndWait(t, f, "foo 1\npartial-")
	expectEntry(t, ch, "foo 1")

	w, err := os.OpenFile(f.Name(), os.O_WRONLY|os.O_TRUNC, 0)
	require.NoError(t, err)
	defer w.Close()
	writeAndWait(t, w, "bar\n")
	// the partial line of the truncated content is flushed as is and not glued to the new data
	expectEntry(t, ch, "partial-")
	expectEntry(t, ch, "bar")
}

func TestTailReaderRotationResetsPartialLine(t *testing.T) {
	f, ch, _ := newTestTailReader(t)
	writeAndWait(t, f, "foo 1\npartial-")
	expectEntry(t, ch, "foo 1")

	require.NoError(t, os.Rename(f.Name(), f.Name()+".1"))
	nf, err := os.Create(f.Name())
	require.NoError(t, err)
	defer nf.Close()
	writeAndWait(t, nf, "bar\n")
	expectEntry(t, ch, "partial-")
	expectEntry(t, ch, "bar")
}

func openFds(t *testing.T) int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("/proc/self/fd is not available")
	}
	return len(entries)
}

func TestTailReaderClosesRotatedFile(t *testing.T) {
	f, ch, _ := newTestTailReader(t)
	writeAndWait(t, f, "foo\n")
	expectEntry(t, ch, "foo")
	require.NoError(t, f.Close())
	before := openFds(t)

	require.NoError(t, os.Rename(f.Name(), f.Name()+".1"))
	nf, err := os.Create(f.Name())
	require.NoError(t, err)
	defer nf.Close()
	writeAndWait(t, nf, "bar\n")
	expectEntry(t, ch, "bar")
	// the descriptor of the rotated file must be released: only nf has been added
	assert.Equal(t, before+1, openFds(t))
}
