//go:build amd64

package ebpftracer

import (
	"bufio"
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// startTracer runs a tracer draining its events into the returned channel (only L7 events of this process are kept)
func startTracer(t *testing.T) (*Tracer, <-chan Event) {
	var uname unix.Utsname
	require.NoError(t, unix.Uname(&uname))
	require.NoError(t, common.SetKernelVersion(string(bytes.Split(uname.Release[:], []byte{0})[0])))

	events := make(chan Event, 10000)
	l7Events := make(chan Event, 1000)
	pid := uint32(os.Getpid())
	go func() {
		for e := range events {
			if e.Type == EventTypeL7Request && e.Pid == pid {
				l7Events <- e
			}
		}
	}()
	tt := NewTracer(0, 0, false)
	require.NoError(t, tt.Run(events))
	t.Cleanup(func() {
		tt.Close()
		close(events) // must not panic: Close guarantees that no more events are sent
	})
	return tt, l7Events
}

func waitL7Event(t *testing.T, ch <-chan Event, match func(e Event) bool) *l7.RequestData {
	timeout := time.After(5 * time.Second)
	for {
		select {
		case e := <-ch:
			if match(e) {
				return e.L7Request
			}
		case <-timeout:
			t.Fatal("no L7 event")
			return nil
		}
	}
}

func listen(t *testing.T) net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func connFd(t *testing.T, c net.Conn) uint64 {
	rc, err := c.(*net.TCPConn).SyscallConn()
	require.NoError(t, err)
	var fd uintptr
	require.NoError(t, rc.Control(func(f uintptr) { fd = f }))
	return uint64(fd)
}

// "100 Continue" must be skipped, the final response status must be reported (issue #220)
func TestL7HttpInterimResponse(t *testing.T) {
	skipIfNotVM(t)
	_, events := startTracer(t)
	l := listen(t)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		_, _ = r.ReadString('\n')
		_, _ = c.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n"))
		time.Sleep(300 * time.Millisecond)
		_, _ = c.Write([]byte("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"))
		time.Sleep(time.Second)
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Write([]byte("POST /upload HTTP/1.1\r\nHost: test\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n"))
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(buf[:n], []byte("HTTP/1.1 100")))
	_, err = c.Write([]byte("abc"))
	require.NoError(t, err)
	_, err = c.Read(buf)
	require.NoError(t, err)

	seen := map[bool]bool{}
	for len(seen) < 2 { // the client and the server sides
		r := waitL7Event(t, events, func(e Event) bool { return !seen[e.L7Request.IsInbound] })
		seen[r.IsInbound] = true
		assert.Equal(t, l7.ProtocolHTTP, r.Protocol)
		assert.Equal(t, l7.Status(201), r.Status, "inbound=%v", r.IsInbound)
		assert.GreaterOrEqual(t, r.Duration, 300*time.Millisecond)
		assert.NotZero(t, r.Timestamp)
	}
}

// A request left pending on a closed connection must not be matched with a response
// on a new connection reusing the same fd (issue #372)
func TestL7StaleRequestOnFdReuse(t *testing.T) {
	skipIfNotVM(t)
	_, events := startTracer(t)
	l := listen(t)
	fds := make(chan uint64, 2)
	go func() {
		// the first connection: the request is never answered
		c, err := l.Accept()
		if err != nil {
			return
		}
		fds <- connFd(t, c)
		_, _ = bufio.NewReader(c).ReadString('\n')
		time.Sleep(time.Second)
		_ = c.Close()

		// the second connection: likely the same fd
		c, err = l.Accept()
		if err != nil {
			return
		}
		fds <- connFd(t, c)
		_, _ = bufio.NewReader(c).ReadString('\n')
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		time.Sleep(time.Second)
		_ = c.Close()
	}()

	c1, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	_, err = c1.Write([]byte("GET /1 HTTP/1.1\r\nHost: test\r\n\r\n"))
	require.NoError(t, err)
	time.Sleep(1500 * time.Millisecond)
	_ = c1.Close()

	c2, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer c2.Close()
	_, err = c2.Write([]byte("GET /2 HTTP/1.1\r\nHost: test\r\n\r\n"))
	require.NoError(t, err)
	_, err = c2.Read(make([]byte, 1024))
	require.NoError(t, err)

	if fd1, fd2 := <-fds, <-fds; fd1 != fd2 {
		t.Skipf("the server fd was not reused: %d != %d", fd1, fd2)
	}
	r := waitL7Event(t, events, func(e Event) bool { return e.L7Request.IsInbound })
	assert.Equal(t, l7.Status(200), r.Status)
	assert.Less(t, r.Duration, 500*time.Millisecond)
	assert.Contains(t, string(r.Payload), "GET /2")
}

// Close must return even if nobody reads the events, and no event must be sent after it returns
func TestCloseStopsReaders(t *testing.T) {
	skipIfNotVM(t)
	var uname unix.Utsname
	require.NoError(t, unix.Uname(&uname))
	require.NoError(t, common.SetKernelVersion(string(bytes.Split(uname.Release[:], []byte{0})[0])))

	events := make(chan Event, 16)
	stopDraining := make(chan struct{})
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			select {
			case <-events:
			case <-stopDraining:
				return
			}
		}
	}()
	tt := NewTracer(0, 0, false)
	require.NoError(t, tt.Run(events))
	close(stopDraining)
	<-drained

	// fill the channel: the readers get blocked on sending
	l := listen(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	for i := 0; i < 2000 && len(events) < cap(events); i++ {
		if c, err := net.Dial("tcp", l.Addr().String()); err == nil {
			_ = c.Close()
		}
	}

	closed := make(chan struct{})
	go func() {
		tt.Close()
		close(events)
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close hung")
	}
	tt.Close() // idempotent
}

// "100 Continue" and the final response written at once
func TestL7HttpInterimResponseCoalesced(t *testing.T) {
	skipIfNotVM(t)
	_, events := startTracer(t)
	l := listen(t)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = bufio.NewReader(c).ReadString('\n')
		_, _ = c.Write([]byte("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))
		time.Sleep(time.Second)
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Write([]byte("POST /upload HTTP/1.1\r\nHost: test\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n"))
	require.NoError(t, err)
	_, err = c.Read(make([]byte, 1024))
	require.NoError(t, err)

	seen := map[bool]bool{}
	for len(seen) < 2 {
		r := waitL7Event(t, events, func(e Event) bool { return !seen[e.L7Request.IsInbound] })
		seen[r.IsInbound] = true
		assert.Equal(t, l7.Status(202), r.Status, "inbound=%v", r.IsInbound)
	}
}
