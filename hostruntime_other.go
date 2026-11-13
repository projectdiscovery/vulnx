//go:build !linux && !darwin

package vulnx

import "context"

func collectHostRuntime(ctx context.Context, r *HostRuntime) {
	r.Status = "unavailable"
	r.Scope = "runtime collection is not supported on this operating system"
}
