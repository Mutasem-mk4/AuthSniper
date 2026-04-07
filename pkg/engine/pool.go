package engine

import (
	"net/http"
	"sync"

	"github.com/user/authsniper/pkg/analyzer"
	"github.com/user/authsniper/pkg/requester"
	"github.com/user/authsniper/pkg/ui"
)

type Job struct {
	BaseReq   *http.Request
	BodyBytes []byte
}

type Result struct {
	Target string
	IsBOLA bool
	Score  float64
}

type Pool struct {
	numWorkers int
	client     *requester.Client
	tokenA     string
	tokenB     string
	results    chan Result
}

func NewPool(workers int, client *requester.Client, tokenA, tokenB string) *Pool {
	return &Pool{
		numWorkers: workers,
		client:     client,
		tokenA:     tokenA,
		tokenB:     tokenB,
		results:    make(chan Result),
	}
}

func (p *Pool) Start(jobs <-chan Job, outputFile string) {
	var wg sync.WaitGroup

	for i := 0; i < p.numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				targetStr := job.BaseReq.URL.String()

				respA, respB, respU := p.client.Multiplex(job.BaseReq, job.BodyBytes, p.tokenA, p.tokenB)

				if respA.Error != nil {
					continue
				}

				isBOLA, score := analyzer.Compare(respA.Body, respB.Body, respU.Body, respA.StatusCode, respB.StatusCode, respU.StatusCode)

				p.results <- Result{Target: targetStr, IsBOLA: isBOLA, Score: score}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(p.results)
	}()

	for res := range p.results {
		if res.IsBOLA {
			ui.PrintSuccess(res.Target, res.Score)
			if outputFile != "" {
				ui.WriteJSONL(outputFile, res.Target, res.Score)
			}
		}
	}
}
