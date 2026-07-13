package dnsverify

import (
	"context"
	"sync"
)

// VerifyJob describes one DNS record to verify.
type VerifyJob struct {
	RecordID   string
	RecordType string
	Name       string
	Domain     string
	Expected   string
	Cloud      bool
}

// VerifyAll runs DNS checks concurrently while preserving result order.
func (c *Checker) VerifyAll(ctx context.Context, jobs []VerifyJob, workers int) []Result {
	if len(jobs) == 0 {
		return nil
	}
	if workers <= 0 {
		workers = DefaultWorkers
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}

	results := make([]Result, len(jobs))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for i, job := range jobs {
		wg.Add(1)
		go func(i int, job VerifyJob) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			if err := ctx.Err(); err != nil {
				results[i] = Result{
					RecordID: job.RecordID,
					Name:     job.Name,
					Type:     job.RecordType,
					Expected: job.Expected,
					Status:   "error",
					Detail:   err.Error(),
				}
				return
			}

			verify := c.Verify(ctx, job.RecordType, job.Name, job.Domain, job.Expected, job.Cloud)
			verify.RecordID = job.RecordID
			results[i] = verify
		}(i, job)
	}

	wg.Wait()
	return results
}
