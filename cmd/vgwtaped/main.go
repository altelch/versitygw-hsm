// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// vgwtaped is the HSM tiering daemon for the posix-hsm backend. It performs
// all physical data movement: archive waves (tiering), restores, expiry
// sweeps, and purge/GC. The daemon talks to the gateway only through the
// shared state directory.
//
// Usage: vgwtaped --rootdir /data --state-dir /data-hsm --policy pol.yaml --driver mock|bareos ...
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posixhsm"
	"github.com/versity/versitygw/backend/posixhsm/daemon"
	"github.com/versity/versitygw/backend/posixhsm/policy"
	"github.com/versity/versitygw/backend/posixhsm/queue"
)

var (
	rootdir       string
	stateDir      string
	policyPath    string
	driverName    string
	bareosConsole string
	bareosPool    string
	bareosDrive   string
	wg            sync.WaitGroup
	workers       int
	scanInterval  time.Duration
	gcEnabled     bool
	logDebug      bool
)

func buildDriver() (posixhsm.HsmDriver, error) {
	switch driverName {
	case "", "mock":
		return posixhsm.NewMockDriver(stateDir)
	case "bareos":
		if bareosConsole == "" {
			return nil, fmt.Errorf("bareos driver: --bareos-console host:port is required")
		}
		return posixhsm.NewBareosDriver(posixhsm.BareosOpts{
			Console: bareosConsole,
			Pool:    bareosPool,
			Drive:   bareosDrive,
		})
	default:
		return nil, fmt.Errorf("unknown driver %q (supported: mock, bareos)", driverName)
	}
}

func runDaemon(_ *cli.Context) error {
	if rootdir == "" {
		return fmt.Errorf("--rootdir is required")
	}
	if stateDir == "" {
		return fmt.Errorf("--state-dir is required")
	}
	if policyPath == "" {
		return fmt.Errorf("--policy is required")
	}

	pol, err := policy.Load(policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	meta := meta.XattrMeta{}.WithRootDir(rootdir)
	q, err := queue.New(stateDir)
	if err != nil {
		return fmt.Errorf("init queue: %w", err)
	}

	drv, err := buildDriver()
	if err != nil {
		return fmt.Errorf("init driver: %w", err)
	}
	defer drv.Close()

	d := daemon.New(daemon.Config{
		Driver:   drv,
		Queue:    q,
		Meta:     meta,
		Policy:   pol,
		Lister:   daemon.NewFSLister(rootdir),
		WaveSize: 256,
	})

	log.Printf("vgwtaped starting: rootdir=%s state-dir=%s driver=%q workers=%d scan-interval=%s",
		rootdir, stateDir, drv.Name(), workers, scanInterval)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		s := <-sigChan
		log.Printf("signal %v received, shutting down", s)
		cancel()
	}()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go workerRestore(ctx, d, i)
	}

	wg.Add(1)
	go loopTierSweep(ctx, d, scanInterval, logDebug)

	wg.Wait()
	return nil
}

func workerRestore(ctx context.Context, d *daemon.Daemon, id int) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := d.RestoreJobs(ctx, 16)
		if err != nil {
			if logDebug {
				log.Printf("restore worker %d: %v", id, err)
			}
		} else if n > 0 {
			log.Printf("restore worker %d completed %d", id, n)
		} else {
			select {
			case <-ctx.Done():
				return
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
}

func loopTierSweep(ctx context.Context, d *daemon.Daemon, interval time.Duration, logDebug bool) {
	defer wg.Done()
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	runOnce(ctx, d, logDebug)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runOnce(ctx, d, logDebug)
		}
	}
}

func runOnce(ctx context.Context, d *daemon.Daemon, logDebug bool) {
	if n, err := d.Tier(ctx); err != nil {
		if logDebug {
			log.Printf("tier pass: %v", err)
		}
	} else if n > 0 {
		log.Printf("tier pass tiered %d objects", n)
	}
	if n, err := d.Sweep(ctx); err != nil {
		if logDebug {
			log.Printf("sweep pass: %v", err)
		}
	} else if n > 0 {
		log.Printf("sweep pass re-tiered %d objects", n)
	}
	if gcEnabled {
		gcFile := stateDir + "/gc-queue"
		if n, err := d.GC(ctx, gcFile); err != nil {
			if logDebug {
				log.Printf("gc pass: %v", err)
			}
		} else if n > 0 {
			log.Printf("gc pass purged %d locators", n)
		}
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "vgwtaped"
	app.Usage = "HSM tiering daemon for the posix-hsm S3 backend"
	app.Flags = []cli.Flag{
		&cli.StringFlag{Name: "rootdir", Usage: "absolute path to the posix-hsm root directory", EnvVars: []string{"VGWTAPED_ROOTDIR"}, Destination: &rootdir},
		&cli.StringFlag{Name: "state-dir", Usage: "shared HSM state directory (job queue, driver state)", EnvVars: []string{"VGWTAPED_STATE_DIR"}, Destination: &stateDir},
		&cli.StringFlag{Name: "policy", Usage: "path to a tiering policy YAML file", EnvVars: []string{"VGWTAPED_POLICY"}, Destination: &policyPath},
		&cli.StringFlag{Name: "driver", Value: "mock", Usage: "HSM driver: mock (default) or bareos", EnvVars: []string{"VGWTAPED_DRIVER"}, Destination: &driverName},
		&cli.StringFlag{Name: "bareos-console", Usage: "bareos console endpoint host:port (eg 127.0.0.1:913)", EnvVars: []string{"VGWTAPED_BAREOS_CONSOLE"}, Destination: &bareosConsole},
		&cli.StringFlag{Name: "bareos-pool", Value: "Default", Usage: "bareos pool name", EnvVars: []string{"VGWTAPED_BAREOS_POOL"}, Destination: &bareosPool},
		&cli.StringFlag{Name: "bareos-drive", Usage: "bareos drive label (eg 'File1')", EnvVars: []string{"VGWTAPED_BAREOS_DRIVE"}, Destination: &bareosDrive},
		&cli.IntFlag{Name: "workers", Value: 4, Usage: "number of concurrent restore workers", EnvVars: []string{"VGWTAPED_WORKERS"}, Destination: &workers},
		&cli.DurationFlag{Name: "scan-interval", Value: 5 * time.Minute, Usage: "interval between tier/sweep/gc passes", EnvVars: []string{"VGWTAPED_SCAN_INTERVAL"}, Destination: &scanInterval},
		&cli.BoolFlag{Name: "gc", Value: true, Usage: "enable periodic purge pass", EnvVars: []string{"VGWTAPED_GC"}, Destination: &gcEnabled},
		&cli.BoolFlag{Name: "debug", Value: false, Usage: "verbose logging", EnvVars: []string{"VGWTAPED_DEBUG"}, Destination: &logDebug},
	}
	app.Before = func(ctx *cli.Context) error {
		if workers <= 0 {
			return fmt.Errorf("--workers must be positive")
		}
		return nil
	}
	app.Action = runDaemon

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("vgwtaped: %v", err)
	}
}
