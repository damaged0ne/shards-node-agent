package promagent

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"k8s.io/klog/v2"
)

// userinfoRe matches the credentials part of URLs (scheme://user:password@host).
var userinfoRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s@"']+@`)

// Redact removes credentials embedded in URLs from s.
func Redact(s string) string {
	return userinfoRe.ReplaceAllString(s, "${1}xxxxx@")
}

// NewLogger returns a slog.Logger that writes to klog through the agent's rate limited output.
// Info and debug records are only written with -v >= 1 and >= 3 respectively, warnings and errors
// are both written as warnings (the Prometheus libraries log per-target errors, which must not
// bypass the rate limiter). Credentials in URLs are redacted.
func NewLogger(component string) *slog.Logger {
	return slog.New(&klogHandler{prefix: component + ": "})
}

// NewQuietLogger is like NewLogger, but writes warnings and errors only with -v >= 1.
func NewQuietLogger(component string) *slog.Logger {
	return slog.New(&klogHandler{prefix: component + ": ", quiet: true})
}

type klogHandler struct {
	prefix string
	attrs  string
	group  string
	quiet  bool
}

func (h *klogHandler) Enabled(_ context.Context, l slog.Level) bool {
	switch {
	case l >= slog.LevelWarn:
		return !h.quiet || klog.V(1).Enabled()
	case l >= slog.LevelInfo:
		return klog.V(1).Enabled()
	default:
		return klog.V(3).Enabled()
	}
}

func (h *klogHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(h.prefix)
	b.WriteString(r.Message)
	b.WriteString(h.attrs)
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&b, h.group, a)
		return true
	})
	msg := Redact(b.String())
	if r.Level >= slog.LevelWarn {
		klog.WarningDepth(1, msg)
	} else {
		klog.InfoDepth(1, msg)
	}
	return nil
}

func (h *klogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var b strings.Builder
	b.WriteString(h.attrs)
	for _, a := range attrs {
		writeAttr(&b, h.group, a)
	}
	return &klogHandler{prefix: h.prefix, attrs: b.String(), group: h.group, quiet: h.quiet}
}

func (h *klogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &klogHandler{prefix: h.prefix, attrs: h.attrs, group: h.group + name + ".", quiet: h.quiet}
}

func writeAttr(b *strings.Builder, group string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() == slog.KindGroup {
		g := group
		if a.Key != "" {
			g += a.Key + "."
		}
		for _, ga := range a.Value.Group() {
			writeAttr(b, g, ga)
		}
		return
	}
	v := a.Value.String()
	if strings.ContainsAny(v, " \t\n\"") {
		v = fmt.Sprintf("%q", v)
	}
	b.WriteString(" ")
	b.WriteString(group)
	b.WriteString(a.Key)
	b.WriteString("=")
	b.WriteString(v)
}
