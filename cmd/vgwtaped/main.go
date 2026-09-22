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
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posixhsm"
	"github.com/versity/versitygw/backend/posixhsm/daemon"
	"github.com/versity/versitygw/backend/posixhsm/policy"
	"github.com/versity/versitygw/backend/posixhsm/queue"
	"github.com/versity/versitygw/backend/posixhsm/state"
)

var (
	rootdir        string
	stateDir       string
	sidecarDir     string
	policyPath     string
	driverName     string
	bareosClient   string
	bareosBackup   string
	bareosRestore  string
	bareosConf     string
	bareosDirector string
	zfsDataset     string
	wg             sync.WaitGroup
	workers        int
	scanInterval   time.Duration
	gcEnabled      bool
	logDebug       bool
)

func buildDriver() (posixhsm.HsmDriver, error) {
	switch driverName {
	case "", "mock":
		return posixhsm.NewMockDriver(stateDir)
	case "bareos":
		return posixhsm.NewBareosDriver(posixhsm.BareosOpts{
			Client:         bareosClient,
			BackupJob:      bareosBackup,
			RestoreJob:     bareosRestore,
			BConsoleConfig: bareosConf,
			Director:       bareosDirector,
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

	absRoot, aerr := filepath.Abs(rootdir)
	if aerr != nil {
		return fmt.Errorf("resolve rootdir: %w", aerr)
	}
	// Canonicalize rootdir once and use it everywhere: the daemon's xattr
	// path resolution (state.XattrMeta{}.WithRootDir) bypasses its own
	// rootdir only when the passed bucket is absolute, and lister-emitted
	// candidate paths are also used as raw paths by the daemon, so both
	// must agree on an absolute root.
	//
	// The metadata storer must match the gateway's mode: xattr is the
	// default; --sidecar selects the split-file representation and must
	// point at the SAME sidecar directory the gateway was started with.
	ms := meta.XattrMeta{}.WithRootDir(absRoot)
	if sidecarDir != "" {
		absSidecar, serr := filepath.Abs(sidecarDir)
		if serr != nil {
			return fmt.Errorf("resolve sidecar dir: %w", serr)
		}
		if absSidecar == absRoot || strings.HasPrefix(absSidecar, absRoot+string(filepath.Separator)) {
			return fmt.Errorf("--sidecar %q must not be inside --rootdir %q (the daemon would tier its own metadata)", absSidecar, absRoot)
		}
		sc, serr := meta.NewSideCar(absSidecar)
		if serr != nil {
			return fmt.Errorf("failed to init sidecar metadata: %w", serr)
		}
		ms = state.NewPathRelStorer(sc, absRoot)
		log.Printf("using sidecar directory for metadata: %s", absSidecar)
	}
	q, err := queue.New(stateDir)
	if err != nil {
		return fmt.Errorf("init queue: %w", err)
	}

	drv, err := buildDriver()
	if err != nil {
		return fmt.Errorf("init driver: %w", err)
	}
	defer drv.Close()

	var lister daemon.Lister = daemon.NewFSLister(absRoot)
	if zfsDataset != "" {
		lister = daemon.NewZfsLister(absRoot, zfsDataset, stateDir, daemon.NewExecZfsRunner("zfs"))
		log.Printf("vgwtaped using ZFS diff against dataset %q (mount root must equal --rootdir)", zfsDataset)
	}

	d := daemon.New(daemon.Config{
		Driver:   drv,
		Queue:    q,
		Meta:     ms,
		Policy:   pol,
		Lister:   lister,
		WaveSize: 256,
	})
	if s, ok := drv.(daemon.SingleWaveArchiver); ok && s.SingleWave() {
		log.Printf("driver %q reports single-wave: archiving the full due set in one job per tier/sweep pass", drv.Name())
	}

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
		&cli.StringFlag{Name: "sidecar", Usage: "sidecar metadata directory (must equal the gateway's --sidecar, absolute path recommended); default: xattrs on the object files", EnvVars: []string{"VGWTAPED_SIDECAR"}, Destination: &sidecarDir},
		&cli.StringFlag{Name: "policy", Usage: "path to a tiering policy YAML file", EnvVars: []string{"VGWTAPED_POLICY"}, Destination: &policyPath},
		&cli.StringFlag{Name: "driver", Value: "mock", Usage: "HSM driver: mock (default) or bareos", EnvVars: []string{"VGWTAPED_DRIVER"}, Destination: &driverName},
		&cli.StringFlag{Name: "bareos-client", Usage: "Bareos Client (File Daemon) resource for this gateway host", EnvVars: []string{"VGWTAPED_BAREOS_CLIENT"}, Destination: &bareosClient},
		&cli.StringFlag{Name: "bareos-backup", Usage: "name of a Type=Backup Job that archives the tiered objects", EnvVars: []string{"VGWTAPED_BAREOS_BACKUP"}, Destination: &bareosBackup},
		&cli.StringFlag{Name: "bareos-restore", Usage: "name of a Type=Restore Job used for in-place single-file restores", EnvVars: []string{"VGWTAPED_BAREOS_RESTORE"}, Destination: &bareosRestore},
		&cli.StringFlag{Name: "bareos-conf", Usage: "bconsole -c config dir/file (defines the Director to talk to)", EnvVars: []string{"VGWTAPED_BAREOS_CONF"}, Destination: &bareosConf},
		&cli.StringFlag{Name: "bareos-director", Usage: "bconsole -D directory (named console), optional", EnvVars: []string{"VGWTAPED_BAREOS_DIRECTOR"}, Destination: &bareosDirector},
		&cli.StringFlag{Name: "zfs-dataset", Usage: "ZFS dataset name to tier (enables incremental scan via zfs diff; mount point must equal --rootdir)", EnvVars: []string{"VGWTAPED_ZFS_DATASET"}, Destination: &zfsDataset},
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
