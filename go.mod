module github.com/edaniels/zeroconf

go 1.13
toolchain go1.24.1

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/edaniels/golog v0.0.0-20220930140416-6e52e83a97fc
	github.com/miekg/dns v1.1.41
	github.com/pkg/errors v0.9.1
	golang.org/x/net v0.36.0
)

require go.uber.org/multierr v1.6.0

require (
	github.com/benbjohnson/clock v1.1.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/zap v1.23.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)
