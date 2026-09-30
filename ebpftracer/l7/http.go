package l7

import (
	"bytes"
)

func ParseHttp(payload []byte) (string, string) {
	method, rest, ok := bytes.Cut(payload, space)
	if !ok {
		return "", ""
	}
	if !isHttpMethod(string(method)) {
		return "", ""
	}
	uri, _, ok := bytes.Cut(rest, space)
	if !ok {
		// don't append to uri: it shares the backing array with payload
		return string(method), string(uri) + "..."
	}
	return string(method), string(uri)
}
