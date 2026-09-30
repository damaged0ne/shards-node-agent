package l7

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"inet.af/netaddr"
)

func mysqlPacket(cmd byte, body []byte) []byte {
	size := len(body) + 1
	return append([]byte{byte(size), byte(size >> 8), byte(size >> 16), 0, cmd}, body...)
}

func TestMysqlParser(t *testing.T) {
	p := NewMysqlParser()

	assert.Equal(t, "SELECT 1", p.Parse(mysqlPacket(MysqlComQuery, []byte("SELECT 1")), 0))

	// partial payload
	pkt := mysqlPacket(MysqlComQuery, []byte("SELECT * FROM table"))
	assert.Equal(t, "SELECT * F...", p.Parse(pkt[:15], 0))

	// prepared statements
	assert.Equal(t, "PREPARE 7 FROM SELECT ?", p.Parse(mysqlPacket(MysqlComStmtPrepare, []byte("SELECT ?")), 7))
	assert.Equal(t, "SELECT ?", p.Parse(mysqlPacket(MysqlComStmtExecute, []byte{7, 0, 0, 0}), 0))
	assert.Equal(t, "", p.Parse(mysqlPacket(MysqlComStmtClose, []byte{7, 0, 0, 0}), 0))
	assert.Equal(t, "EXECUTE 7 /* unknown */", p.Parse(mysqlPacket(MysqlComStmtExecute, []byte{7, 0, 0, 0}), 0))

	// too short
	assert.Equal(t, "", p.Parse([]byte{1, 0, 0, 0, MysqlComQuery}, 0))

	// msgSize == 0 used to panic: slice bounds out of range [5:4]
	assert.NotPanics(t, func() {
		assert.Equal(t, "", p.Parse([]byte{0, 0, 0, 0, MysqlComQuery, 'a', 'b', 'c', 'd'}, 0))
		assert.Equal(t, "", p.Parse([]byte{0, 0, 0, 0, MysqlComStmtPrepare, 'a', 'b', 'c', 'd'}, 0))
	})
	// msgSize == 1: the packet contains only the command byte
	assert.Equal(t, "", p.Parse([]byte{1, 0, 0, 0, MysqlComQuery, 'a', 'b', 'c', 'd'}, 0))
}

func pgMsg(typ byte, body ...[]byte) []byte {
	b := bytes.Join(body, nil)
	l := len(b) + 4
	return append([]byte{typ, byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}, b...)
}

func TestPostgresParser(t *testing.T) {
	p := NewPostgresParser()
	z := []byte{0}

	assert.Equal(t, "SELECT 1", p.Parse(pgMsg(PostgresFrameQuery, []byte("SELECT 1"), z)))
	assert.Equal(t, "SELECT 1...", p.Parse(pgMsg(PostgresFrameQuery, []byte("SELECT 1"))))

	assert.Equal(t, "PREPARE s1 AS SELECT $1", p.Parse(pgMsg(PostgresFrameParse, []byte("s1"), z, []byte("SELECT $1"), z, []byte{0, 0})))
	assert.Equal(t, "SELECT $1", p.Parse(pgMsg(PostgresFrameBind, []byte("portal"), z, []byte("s1"), z, []byte{0, 0})))
	assert.Equal(t, "", p.Parse(pgMsg(PostgresFrameClose, []byte("S"), []byte("s1"), z)))
	assert.Equal(t, "EXECUTE s1 /* unknown */", p.Parse(pgMsg(PostgresFrameBind, []byte("portal"), z, []byte("s1"), z, []byte{0, 0})))

	// truncated Parse message
	assert.Equal(t, "PREPARE s2 AS SELECT...", p.Parse(pgMsg(PostgresFrameParse, []byte("s2"), z, []byte("SELECT"))))

	// malformed
	assert.Equal(t, "", p.Parse([]byte{PostgresFrameQuery}))
	assert.Equal(t, "", p.Parse(pgMsg(PostgresFrameBind, []byte("portal"))))
	assert.Equal(t, "", p.Parse(pgMsg(PostgresFrameParse, []byte("s3"))))
	assert.Equal(t, "", p.Parse(pgMsg(PostgresFrameClose)))
	assert.Equal(t, "", p.Parse(pgMsg(PostgresFrameClose, []byte("P"), []byte("s1"), z)))
}

func dnsPayload(t testing.TB, answers ...dnsmessage.Resource) []byte {
	name := dnsmessage.MustNewName("example.com.")
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers:   answers,
	}
	b, err := msg.Pack()
	require.NoError(t, err)
	return b
}

func TestParseDns(t *testing.T) {
	name := dnsmessage.MustNewName("example.com.")
	hdr := func(typ dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: name, Type: typ, Class: dnsmessage.ClassINET}
	}
	payload := dnsPayload(t,
		dnsmessage.Resource{Header: hdr(dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}}},
		dnsmessage.Resource{Header: hdr(dnsmessage.TypeAAAA), Body: &dnsmessage.AAAAResource{AAAA: netaddr.MustParseIP("::1").As16()}},
	)
	typ, domain, ips := ParseDns(payload)
	assert.Equal(t, "TypeA", typ)
	assert.Equal(t, "example.com", domain)
	assert.Equal(t, []netaddr.IP{netaddr.MustParseIP("1.2.3.4"), netaddr.MustParseIP("::1")}, ips)

	typ, domain, ips = ParseDns(payload[:len(payload)-3])
	assert.Equal(t, "", typ)
	assert.Equal(t, "", domain)
	assert.Nil(t, ips)

	typ, _, _ = ParseDns(nil)
	assert.Equal(t, "", typ)
}

func http2HeadersFrame(t testing.TB, streamId uint32, headers ...string) []byte {
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for i := 0; i+1 < len(headers); i += 2 {
		require.NoError(t, enc.WriteField(hpack.HeaderField{Name: headers[i], Value: headers[i+1]}))
	}
	var buf bytes.Buffer
	fr := http2.NewFramer(&buf, nil)
	require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{StreamID: streamId, BlockFragment: hb.Bytes(), EndHeaders: true}))
	return buf.Bytes()
}

func http2DataFrame(t testing.TB, streamId uint32, data []byte) []byte {
	var buf bytes.Buffer
	require.NoError(t, http2.NewFramer(&buf, nil).WriteData(streamId, false, data))
	return buf.Bytes()
}

func TestHttp2Parser(t *testing.T) {
	p := NewHttp2Parser()
	start := uint64(time.Hour)

	req := append([]byte(http2.ClientPreface), http2HeadersFrame(t, 1, ":method", "POST", ":path", "/svc/Method", ":scheme", "http")...)
	req = append(req, http2DataFrame(t, 1, []byte("body"))...)
	assert.Nil(t, p.Parse(MethodHttp2ClientFrames, req, start))

	resp := http2HeadersFrame(t, 1, ":status", "200")
	resp = append(resp, http2DataFrame(t, 1, []byte("data"))...)
	resp = append(resp, http2HeadersFrame(t, 1, "grpc-status", "5")...)
	res := p.Parse(MethodHttp2ServerFrames, resp, start+uint64(time.Second))
	require.Len(t, res, 1)
	assert.Equal(t, "POST", res[0].Method)
	assert.Equal(t, "/svc/Method", res[0].Path)
	assert.Equal(t, "http", res[0].Scheme)
	assert.Equal(t, Status(200), res[0].Status)
	assert.Equal(t, Status(5), res[0].GrpcStatus)
	assert.Equal(t, time.Second, res[0].Duration)

	// a response without grpc-status
	p.Parse(MethodHttp2ClientFrames, http2HeadersFrame(t, 3, ":method", "GET", ":path", "/", ":scheme", "https"), start)
	res = p.Parse(MethodHttp2ServerFrames, http2HeadersFrame(t, 3, ":status", "404"), start+10)
	require.Len(t, res, 1)
	assert.Equal(t, Status(404), res[0].Status)
	assert.Equal(t, Status(-1), res[0].GrpcStatus)

	assert.Nil(t, p.Parse(MethodHttp2ClientFrames, nil, start))
	assert.Nil(t, p.Parse(MethodHttp2ClientFrames, []byte(http2.ClientPreface), start))
	assert.Nil(t, p.Parse(MethodProduce, req, start))
}

func TestHttp2ParserOutOfOrder(t *testing.T) {
	p := NewHttp2Parser()
	start := uint64(time.Hour)
	p.Parse(MethodHttp2ClientFrames, http2HeadersFrame(t, 1, ":method", "GET", ":path", "/", ":scheme", "http"), start)
	// the response event has an earlier timestamp than the request
	res := p.Parse(MethodHttp2ServerFrames, http2HeadersFrame(t, 1, ":status", "200"), start-1)
	require.Len(t, res, 1)
	assert.Equal(t, time.Duration(0), res[0].Duration)
}

func TestHttp2ParserInvalidHeaderBlock(t *testing.T) {
	p := NewHttp2Parser()
	// a HEADERS frame with an undecodable block (an indexed field referencing a non-existent table entry),
	// the block itself looks like a DATA frame header of a huge length.
	bad := []byte{0, 0, 9, byte(http2.FrameHeaders), byte(http2.FlagHeadersEndHeaders), 0, 0, 0, 1,
		0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 1}
	payload := append(bad, http2HeadersFrame(t, 3, ":method", "GET", ":path", "/ok", ":scheme", "http")...)
	p.Parse(MethodHttp2ClientFrames, payload, 1)
	req := p.activeRequests[3]
	require.NotNil(t, req, "the frame following the invalid header block must be parsed")
	assert.Equal(t, "/ok", req.Path)
}

func TestParseHttpDoesNotModifyPayload(t *testing.T) {
	buf := make([]byte, 0, 64)
	buf = append(buf, "GET /path"...)
	full := buf[:cap(buf)]
	copy(full[len(buf):], "XXXX")
	m, u := ParseHttp(buf)
	assert.Equal(t, "GET", m)
	assert.Equal(t, "/path...", u)
	assert.Equal(t, "XXXX", string(full[len(buf):len(buf)+4]))
}
