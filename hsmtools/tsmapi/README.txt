tsmapi — operator CLI and NDJSON bridge for IBM Storage Protect (TSM) 8.1
============================================================================

WHAT THIS IS
  A C helper that links the TSM Data API (libApiTSM64.so). It has two
  faces:

  1. NDJSON protocol (no arguments): used by the `vgwtaped --driver tsm`
     daemon. One flat JSON command per line on stdin, one flat JSON
     response per line on stdout; DAPI diagnostics go to stderr.
     Ops: ping | version | signon | send | get | delete | query | quit

  2. Operator CLI (one-shot commands): used by humans / scripts to inspect
     and restore tiered objects without the daemon:
       tsmapi ls       list active backup objects (JSON lines on stdout)
       tsmapi restore  restore objects + metadata by ERE pattern (see below)
       tsmapi meta     print the deterministic companion name for (HL, LL)

BUILD
  make            build ./tsmapi (needs the TSM SDK, default
                  /opt/tivoli/tsm/client/api/bin64; IBM GSK8 libs)
  make test       protocol self-test (no server required)
  make install    install to $(DESTDIR)/usr/local/bin (default /usr/local)

  The versitygw Go build stays pure-Go; only this helper needs the SDK.

USAGE
  Without arguments          NDJSON protocol (daemon uses this)
  tsmapi -h | --help         print usage

  tsmapi ls     -n NODE [-c CLIENTDIR] [-o DSMOPT] [-M]
  tsmapi restore -n NODE [-c CLIENTDIR] [-o DSMOPT] -d DEST
                  [-m xattr|sidecar|raw|none] [--sidecar DIR] <ERE>...
  tsmapi meta HL LL

  -n NODE       TSM client node name (required for ls / restore)
  -c CLIENTDIR  client config dir holding dsm.sys/dsm.opt/NLS
                (default: /opt/tivoli/tsm/client/ba/bin — must be
                writable; tsmapi.log is written there)
  -o DSMOPT     extra dsm.opt path / inline options
  -M            ls: include ".hsm-meta" companion objects
  -d DEST       restore: destination root (required)
  -m MODE       restore: metadata replay mode (default: xattr)
  --sidecar DIR restore: sidecar root (required for -m sidecar)

  CLI stdout is data only (ls: JSON lines); progress, per-object lines,
  errors and the summary go to stderr.

restore — WHAT IS RESTORED (the important part)
================================================

  Data is restored in ALL modes. `-m` does NOT choose between "data" and
  "metadata" — it only decides where (or if) the captured S3 metadata
  companion is replayed. Per matched object:

    1. data      -> DEST/<hl>/<ll>            (always; newest active
                                               version; an already-present
                                               regular file is skipped,
                                               so re-runs are idempotent)
    2. metadata  -> per -m, and only if a companion object
                    MetaName(HL,LL) exists for that object; absence is
                    not an error — data still restores

  -m xattr    (default)  data -> DEST/<hl>/<ll>
                         metadata -> xattrs on that same file:
                         one setxattr("user.<attr>") per attribute
                         (Linux only)
  -m sidecar  data       -> DEST/<hl>/<ll>                    (DEST, not DIR!)
                         metadata -> --sidecar DIR/<hl>/<ll>/meta/<attr>
                         (one file per attribute — the meta.SideCar
                         layout. Use DEST=rootdir and DIR=<sidecar dir>
                         to refill a running --sidecar gateway.)
  -m raw      data       -> DEST/<hl>/<ll>
                         metadata -> DEST/<hl>/<ll>.hsm-meta
                         (the whole companion JSON verbatim)
  -m none     data       -> DEST/<hl>/<ll>
                         metadata -> not replayed ("data only")

  So: -m xattr  = data AND metadata (as xattrs on the data file).
      -m sidecar = data AND metadata, but in two trees: data under
      -d, metadata under --sidecar.
      -m raw    = data AND metadata file (both under -d).
      -m none   = data only.

  MATCHING:  each object's "hl/ll" path is tested against every ERE
  (POSIX extended, case-sensitive); ANY match restores the object.
  Quote patterns so the shell does not glob them. "hl" is the TSM
  object's directory part — run `tsmapi ls -n NODE` first if you are
  unsure of the names.

  EXIT STATUS:
    0  all matched objects' data restored (metadata may be absent/-m none)
    1  at least one object's data could not be restored
    2  bad invocation (missing -n or -d, bad -m, invalid ERE,
       --sidecar missing for -m sidecar, >32 patterns)

  EXAMPLES:
    # restore a handful of reports with default (xattr) metadata
    tsmapi restore -n MYNODE -d /restore 'reports/2026/.*\.pdf'

    # refill a sidecar-mode gateway: data to rootdir, meta to its sidecar dir
    tsmapi restore -n MYNODE -d /data --sidecar /meta -m sidecar '^docs/'

    # data only
    tsmapi restore -n MYNODE -d /restore -m none '^cache/'

    # keep the raw payload next to the data
    tsmapi restore -n MYNODE -d /restore -m raw '^cache/'

    # inspect the catalog first (companions visible with -M)
    tsmapi ls -n MYNODE -M

  METADATA COMPANION: when `vgwtaped --driver tsm` tiers an object it
  archives an extra object next to the data, named MetaName(HL,LL)
  (e.g. "hello.txt-251ad6ddd6b6346a.hsm-meta"), containing:
    {"src":"<live path>","attrs":{"<attr>":"<base64>",...}}
  `tsmapi meta HL LL` prints that name without touching the server;
  Go and C compute it identically.

SOURCE
  tsmapi.c contains the full specification as comments (search for the
  "RESTORE" / "CLI" section headers) — this file is the short form.
