package vulnx

import "context"

func collectHostRuntime(ctx context.Context, r *HostRuntime) {
	collectRuntimeProc(ctx, r, "/proc", runtimeProcFiles())
}
