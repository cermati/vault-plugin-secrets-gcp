package gcpsecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

type workerEntry struct {
	name     string
	runFunc  func(*backend, context.Context, *logical.Request) error
	minDelay time.Duration
	lastRun  time.Time
}

var workerEntries = []*workerEntry{
	{
		name:     "cachecleanup",
		runFunc:  WorkerCleanUpStaleCacheEntries,
		minDelay: 5 * time.Minute,
	},
}

// RunAllWorker run all workers which lastRun is older than now-minDelay
func RunAllWorker(b *backend, ctx context.Context, req *logical.Request) error {
	b.Logger().Debug("Running workers...")

	for _, worker := range workerEntries {
		if !worker.lastRun.Before(time.Now().Add(-worker.minDelay)) {
			continue
		}

		b.Logger().Debug(fmt.Sprintf("Running worker %s", worker.name))
		worker.lastRun = time.Now()

		if err := worker.runFunc(b, ctx, req); err != nil {
			b.Logger().Error(
				fmt.Sprintf("Error running worker %s", worker.name),
				"err", err.Error(),
			)
		}
	}

	b.Logger().Debug("Finished running all workers")

	return nil
}
