package l7

import (
	"testing"

	"golang.org/x/net/http2"
)

// The fuzz tests below feed arbitrary (e.g., truncated or misclassified) payloads to the parsers
// and only check that they don't panic.

func FuzzParseHttp(f *testing.F) {
	f.Add([]byte("GET /path HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	f.Add([]byte("POST /too-long"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		ParseHttp(payload)
	})
}

func FuzzHttp2Parser(f *testing.F) {
	f.Add(append([]byte(http2.ClientPreface), http2HeadersFrame(f, 1, ":method", "GET", ":path", "/", ":scheme", "http")...),
		http2HeadersFrame(f, 1, ":status", "200", "grpc-status", "0"), uint64(100), uint64(200))
	f.Add([]byte{0, 0, 9, 1, 4, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff}, []byte{0, 0, 1, 1, 4, 0, 0, 0, 1, 0x88}, uint64(200), uint64(100))
	f.Fuzz(func(t *testing.T, req, resp []byte, reqTime, respTime uint64) {
		p := NewHttp2Parser()
		p.Parse(MethodHttp2ClientFrames, req, reqTime)
		for _, r := range p.Parse(MethodHttp2ServerFrames, resp, respTime) {
			if r.Duration < 0 {
				t.Fatalf("negative duration: %v", r.Duration)
			}
		}
	})
}

func FuzzPostgresParser(f *testing.F) {
	f.Add([]byte("Q\x00\x00\x00\x0dSELECT 1\x00"))
	f.Add([]byte("P\x00\x00\x00\x16s1\x00SELECT $1\x00\x00\x00"))
	f.Add([]byte("B\x00\x00\x00\x10portal\x00s1\x00\x00\x00"))
	f.Add([]byte("C\x00\x00\x00\x08Ss1\x00"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		p := NewPostgresParser()
		p.Parse(payload)
		p.Parse(payload)
	})
}

func FuzzMysqlParser(f *testing.F) {
	f.Add([]byte("\x09\x00\x00\x00\x03SELECT 1"), uint32(0))
	f.Add([]byte("\x09\x00\x00\x00\x16SELECT ?"), uint32(1))
	f.Add([]byte("\x05\x00\x00\x00\x17\x01\x00\x00\x00"), uint32(1))
	f.Add([]byte("\x05\x00\x00\x00\x19\x01\x00\x00\x00"), uint32(1))
	f.Add([]byte("\x00\x00\x00\x00\x03abcd"), uint32(0))
	f.Fuzz(func(t *testing.T, payload []byte, statementId uint32) {
		p := NewMysqlParser()
		p.Parse(payload, statementId)
	})
}

func FuzzParseDns(f *testing.F) {
	f.Add(dnsPayload(f))
	f.Fuzz(func(t *testing.T, payload []byte) {
		ParseDns(payload)
	})
}

func FuzzParseMemcached(f *testing.F) {
	f.Add([]byte("incr 1111 2222\r\n"))
	f.Add([]byte("gets 1111 2222 3333\r\n"))
	f.Add([]byte("gat 0 k1 k2\r\n"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		ParseMemcached(payload)
	})
}

func FuzzParseRedis(f *testing.F) {
	f.Add([]byte("*3\r\n$4\r\nLLEN\r\n$6\r\nmylist\r\n$2\r\nxy\r\n"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		ParseRedis(payload)
	})
}

func FuzzParseMongo(f *testing.F) {
	f.Add([]byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdd\x07\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x02a\x00\x02\x00\x00\x00b\x00\x00"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		ParseMongo(payload)
	})
}

func FuzzParseClickhouse(f *testing.F) {
	f.Add([]byte{0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x8, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'})
	f.Fuzz(func(t *testing.T, payload []byte) {
		ParseClickhouse(payload)
	})
}

func FuzzParseZookeeper(f *testing.F) {
	f.Add([]byte("\x00\x00\x00\x0d\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x02/a"))
	f.Add([]byte("\x00\x00\x00\x0d\x00\x00\x00\x01\x00\x00\x00\x0e\x00\x00\x00\x05\x00\xff\xff\xff\xff\x00\x00\x00\x02/a"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		ParseZookeeper(payload)
	})
}
