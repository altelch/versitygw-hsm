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

package gwcli

import (
	"errors"
	"fmt"
	"io/fs"
	"math"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posix"
	"github.com/versity/versitygw/backend/posixhsm"
	"github.com/versity/versitygw/backend/posixhsm/queue"
)

var (
	hsmGlacier bool
)

// PosixHsmStateDir holds the shared HSM state directory, parsed from the
// --hsm-state-dir flag.
var PosixHsmStateDir string

// PosixHsmCommand returns the "posix-hsm" subcommand, common to all
// versitygw binaries. It is a posix backend with glacier-style
// hierarchical-storage-management: object data is tiered to a secondary
// store (e.g. tape) by the vgwtaped daemon while metadata stays on disk.
func PosixHsmCommand() *cli.Command {
	return &cli.Command{
		Name:  "posix-hsm",
		Usage: "posix filesystem storage backend with HSM tiering (glacier-style)",
		Description: `A posix storage backend with glacier-style hierarchical storage
management. Objects are served from a posix filesystem like the "posix"
backend, but object data may be tiered to a secondary store (e.g. tape) by
the vgwtaped daemon. Offline objects are reported with the GLACIER storage
class and cannot be read or copied until a restore is completed. Bucket
structure and semantics match the "posix" backend.`,
		Action: runPosixHsm,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "hsm-state-dir",
				Usage:       "shared HSM state directory (job queue, driver state) used by the vgwtaped daemon",
				EnvVars:     []string{"VGW_HSM_STATE_DIR"},
				Destination: &PosixHsmStateDir,
			},
			&cli.BoolFlag{
				Name:        "glacier",
				Usage:       "enable glacier emulation mode (default on for posix-hsm)",
				Aliases:     []string{"g"},
				EnvVars:     []string{"VGW_HSM_GLACIER"},
				Value:       true,
				Destination: &hsmGlacier,
			},
			&cli.BoolFlag{
				Name:        "chuid",
				Usage:       "chown newly created files and directories to client account UID",
				EnvVars:     []string{"VGW_CHOWN_UID"},
				Destination: &chownuid,
			},
			&cli.BoolFlag{
				Name:        "chgid",
				Usage:       "chown newly created files and directories to client account GID",
				EnvVars:     []string{"VGW_CHOWN_GID"},
				Destination: &chowngid,
			},
			&cli.BoolFlag{
				Name:        "bucketlinks",
				Usage:       "allow symlinked directories at bucket level to be treated as buckets",
				EnvVars:     []string{"VGW_BUCKET_LINKS"},
				Destination: &bucketlinks,
			},
			&cli.StringFlag{
				Name:        "versioning-dir",
				Usage:       "the directory path to enable bucket versioning",
				EnvVars:     []string{"VGW_VERSIONING_DIR"},
				Destination: &versioningDir,
			},
			&cli.UintFlag{
				Name:        "dir-perms",
				Usage:       "default directory permissions for new directories",
				EnvVars:     []string{"VGW_DIR_PERMS"},
				DefaultText: "0755",
				Value:       0755,
				Destination: &dirPerms,
			},
			&cli.UintFlag{
				Name:        "file-perms",
				Usage:       "default file permissions for new objects",
				EnvVars:     []string{"VGW_FILE_PERMS"},
				DefaultText: "0644",
				Value:       0644,
				Destination: &filePerms,
			},
			&cli.StringFlag{
				Name:        "sidecar",
				Usage:       "use provided sidecar directory to store metadata",
				EnvVars:     []string{"VGW_META_SIDECAR"},
				Destination: &sidecar,
			},
			&cli.IntFlag{
				Name:        "concurrency",
				Usage:       "maximum concurrent actions allowed",
				EnvVars:     []string{"VGW_POSIX_CONCURRENCY"},
				Value:       5000,
				Destination: &actionsConcurrency,
			},
			&cli.BoolFlag{
				Name:        "nometa",
				Usage:       "disable metadata storage",
				EnvVars:     []string{"VGW_META_NONE"},
				Destination: &nometa,
			},
			&cli.StringFlag{
				Name:        "object-lock-mode",
				Usage:       "lock mode for conditional object publishes: flock, fcntl, local, or none",
				EnvVars:     []string{"VGW_OBJECT_LOCK_MODE"},
				DefaultText: "flock",
				Destination: &objectLockMode,
			},
			&cli.StringFlag{
				Name:        "default-etag",
				Usage:       "default ETag value returned for objects that do not have a stored etag attribute",
				EnvVars:     []string{"VGW_DEFAULT_ETAG"},
				Destination: &defaultEtag,
			},
			&cli.BoolFlag{
				Name:        "data-integrity-etag",
				Usage:       "use data-integrity checksum-derived ETags instead of MD5-based ETags",
				EnvVars:     []string{"VGW_DATA_INTEGRITY_ETAG"},
				Destination: &dataIntegrityEtag,
			},
		},
	}
}

func runPosixHsm(ctx *cli.Context) error {
	if ctx.NArg() == 0 {
		return errors.New("no directory provided for operation")
	}
	gwroot := ctx.Args().Get(0)

	if dirPerms > math.MaxUint32 {
		return fmt.Errorf("invalid directory permissions: %d", dirPerms)
	}
	if filePerms > maxFilePerms {
		return fmt.Errorf("invalid file permissions: %o, must be within 0000-0777", filePerms)
	}
	if nometa && sidecar != "" {
		return errors.New("cannot use both nometa and sidecar metadata")
	}
	if actionsConcurrency <= 0 {
		return fmt.Errorf("concurrency must be positive, got %d", actionsConcurrency)
	}

	opts := posix.PosixOpts{
		ChownUID:            chownuid,
		ChownGID:            chowngid,
		BucketLinks:         bucketlinks,
		VersioningDir:       versioningDir,
		ObjectLockMode:      posix.ObjectLockMode(objectLockMode),
		ValidateBucketNames: DisableStrictBucketNames,
		Concurrency:         actionsConcurrency,
		CopyObjectThreshold: CopyObjectThreshold,
		DefaultEtag:         defaultEtag,
		DataIntegrityEtag:   dataIntegrityEtag,
	}
	opts.SetNewDirPerm(fs.FileMode(dirPerms))
	opts.SetNewFilePerm(fs.FileMode(filePerms))

	var ms meta.MetadataStorer
	switch {
	case sidecar != "":
		sc, err := meta.NewSideCar(sidecar)
		if err != nil {
			return fmt.Errorf("failed to init sidecar metadata: %w", err)
		}
		ms = sc
		opts.SideCarDir = sidecar
	case nometa:
		return errors.New("posix-hsm requires metadata storage (xattr or sidecar)")
	default:
		ms = meta.XattrMeta{}
		if err := (meta.XattrMeta{}).Test(gwroot); err != nil {
			return fmt.Errorf("xattr check failed: %w", err)
		}
	}

	be, err := posix.New(gwroot, ms, opts)
	if err != nil {
		return fmt.Errorf("failed to init posix backend: %w", err)
	}

	// HSM: build a shared queue when a state directory is configured.
	// RestoreObject requires it; when unset, posix-hsm still serves data
	// but restore requests are reported as not implemented.
	var q *queue.Queue
	if PosixHsmStateDir != "" {
		q, err = queue.New(PosixHsmStateDir)
		if err != nil {
			be.Shutdown()
			return fmt.Errorf("failed to init hsm queue: %w", err)
		}
	}

	h, err := posixhsm.New(be, ms, q, posixhsm.PosixHsmOpts{
		StateDir: PosixHsmStateDir,
		Glacier:  hsmGlacier || true,
	})
	if err != nil {
		be.Shutdown()
		return fmt.Errorf("failed to init posix-hsm backend: %w", err)
	}

	return RunGateway(ctx.Context, h)
}
