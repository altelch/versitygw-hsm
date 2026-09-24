/*
 * tsmapi — NDJSON-over-stdio bridge from the vgwtaped Go driver to the IBM
 * Storage Protect (TSM) 8.1 Data API (libApiTSM64.so).
 *
 * Protocol: one flat JSON object per line on stdin, one flat JSON object per
 * line on stdout (protocol channel; the DAPI's own diagnostics are routed to
 * stderr, see main()). Ops:
 *
 *   ping     -> liveness probe, no session required
 *   version  -> DAPI library version, no session required
 *   signon   -> dsmSetUp + dsmInitEx (operator keyring; node/owner/clientdir
 *               from the command), then dsmRegisterFS of the filespace
 *   send     -> archive one object (own transaction, backup copy-group)
 *   get      -> restore one object to <path>.tsmpartial (driver renames)
 *   delete   -> remove all active backup versions of one object name
 *   query    -> list active versions of one object name (debugging)
 *   quit     -> dsmTerminate + dsmCleanUp + exit
 *
 * Field rules: strings may carry \" \\ \n \t \r escapes and \uXXXX; numbers
 * are plain decimals. A name that is not on the server is NOT an error:
 * get -> {"ok":true,"found":false}, delete -> {"ok":true,"deleted":0} — the
 * Go side maps that to its contract (restore failure vs idempotent purge).
 *
 * Concurrency: the Go driver serializes calls (one in flight at a time), and
 * the DAPI is used single-thread (dsmSetUp DSM_SINGLETHREAD), which IBM
 * requires for one-process one-handle usage.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dsmapitd.h"
#include "dsmapifp.h"
#include "dsmrc.h"
#include "release.h"

#define TAPI_BUF_SZ (64 * 1024)   /* DAPI chunk size; classic dsmc buffsize  */
#define TAPI_LINE_SZ (256 * 1024) /* command/response line limit             */
#define TAPI_MAX_FIELDS 24
#define TAPI_MAX_VER 512

static int      gProtoFd = -1;             /* protocol channel (orig stdout) */
static char *   gArgv0;                    /* dsmSetUp argv[0]               */
static dsUint32_t gHandle = 0;
static int      gSetUpDone = 0;
static char     gBuf[TAPI_BUF_SZ];         /* DAPI DataBlk buffer            */
static char     gRcMsg[2048];

/* ------------------------------------------------------------------ JSON */

typedef struct {
    const char *key;
    int         isStr;
    char *      str;      /* malloc'd NUL-terminated */
    long long   num;
} tapiField;

static int      gNFields = 0;
static tapiField gFields[TAPI_MAX_FIELDS];

static const char *fStr(const char *key, const char *def)
{
    for (int i = 0; i < gNFields; i++)
        if (gFields[i].isStr && gFields[i].str && !strcmp(gFields[i].key, key))
            return gFields[i].str;
    return def;
}

static void fFree(void)
{
    for (int i = 0; i < gNFields; i++) { free(gFields[i].str); gFields[i].str = NULL; }
    gNFields = 0;
}

static const char *skipWs(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

/* Parse one flat JSON object. Values: strings (with escapes) and decimal
 * numbers. Returns 0 on success. Key/value memory is owned by the caller to
 * free via fFree(). */
static int jsonGet(const char *s, size_t len)
{
    const char *p = skipWs(s, s + len), *end = s + len;
    if (p >= end || *p != '{') return -1;
    p++;
    for (;;) {
        p = skipWs(p, end);
        if (p >= end) return -1;
        if (*p == '}') { p++; break; }
        if (*p != '"') return -1;
        if (gNFields >= TAPI_MAX_FIELDS) return -1;

        /* key */
        const char *ks = ++p;
        const char *ke = ks;
        while (ke < end && *ke != '"') { if (*ke == '\\' && ke + 1 < end) ke++; ke++; }
        if (ke >= end) return -1;
        size_t klen = ke - ks;
        if (klen >= 64) return -1;
        char key[64];
        for (size_t i = 0; i < klen; i++)
            key[i] = ks[i];   /* keys are simple identifiers; no escapes expected */
        key[klen > 63 ? 63 : klen] = 0;
        p = ke + 1;
        p = skipWs(p, end);
        if (p >= end || *p != ':') return -1;
        p = skipWs(++p, end);
        if (p >= end) return -1;

        tapiField *f = &gFields[gNFields];
        f->key = strdup(key);
        if (*p == '"') {
            /* string, decode escapes */
            const char *vs = ++p, *ve = vs;
            while (ve < end) {
                if (*ve == '\\') { if (ve + 1 < end) ve++; ve++; continue; }
                if (*ve == '"') break;
                ve++;
            }
            if (ve >= end) return -1;
            f->isStr = 1;
            size_t cap = ve - vs + 2;
            f->str = malloc(cap);
            if (!f->str) return -1;
            char *o = f->str;
            for (const char *c = vs; c < ve;) {
                if (*c != '\\') { *o++ = *c++; continue; }
                c++;
                if (c >= ve) return -1;
                switch (*c) {
                    case 'n': *o++ = '\n'; break;
                    case 't': *o++ = '\t'; break;
                    case 'r': *o++ = '\r'; break;
                    case '"': *o++ = '"'; break;
                    case '\\': *o++ = '\\'; break;
                    case '/': *o++ = '/'; break;
                    case 'u': {
                        if (c + 5 >= ve + 1 && c + 4 < ve) {
                            unsigned code = 0; int ok = 1;
                            for (int h = 0; h < 4; h++) {
                                char hc = c[1 + h];
                                int d = (hc >= '0' && hc <= '9') ? hc - '0' :
                                        (hc >= 'a' && hc <= 'f') ? hc - 'a' + 10 :
                                        (hc >= 'A' && hc <= 'F') ? hc - 'A' + 10 : -1;
                                if (d < 0) { ok = 0; break; }
                                code = code * 16 + (unsigned)d;
                            }
                            if (ok) {
                                if (code < 0x80) *o++ = (char)code;
                                else if (code < 0x800) { *o++ = (char)(0xC0 | (code >> 6)); *o++ = (char)(0x80 | (code & 63)); }
                                else { *o++ = (char)(0xE0 | (code >> 12)); *o++ = (char)(0x80 | ((code >> 6) & 63)); *o++ = (char)(0x80 | (code & 63)); }
                                c += 4;
                                break;
                            }
                        }
                        *o++ = '?'; break;  /* bad escape: neutralize */
                    }
                    default: *o++ = *c; break;
                }
                c++;
            }
            *o = 0;
            p = ve + 1;
        } else {
            /* number or bare token */
            f->isStr = 0;
            char *tend;
            f->num = strtoll(p, &tend, 10);
            p = tend;
        }
        gNFields++;
        p = skipWs(p, end);
        if (p >= end) return -1;
        if (*p == '}') { p++; break; }
        if (*p != ',') return -1;
        p++;
    }
    return 0;
}

static void jsonEscW(char *out, size_t outsz, const char *s)
{
    size_t o = 0;
    for (const unsigned char *c = (const unsigned char *)s; *c && o + 7 < outsz; c++) {
        char t[8];
        switch (*c) {
            case '"':  strcpy(t, "\\\""); break;
            case '\\': strcpy(t, "\\\\"); break;
            case '\n': strcpy(t, "\\n"); break;
            case '\t': strcpy(t, "\\t"); break;
            case '\r': strcpy(t, "\\r"); break;
            default:
                if (*c < 0x20) snprintf(t, sizeof(t), "\\u%04x", *c);
                else t[0] = (char)*c, t[1] = 0;
        }
        size_t tl = strlen(t);
        if (o + tl + 1 > outsz) break;
        memcpy(out + o, t, tl);
        o += tl;
    }
    out[o] = 0;
}

/* One protocol line on the protocol channel (fd gProtoFd).
 * Returns the rc value (positive TSM/DAPI rc, or negative local code) on
 * failure, or 0 on success — callers may `return rsend(...)` from their
 * int-returning wrappers. */
static int rsend(const char *op, int ok, int rc, const char *msg,
                 const char *extra) /* extra: pre-escaped "key":value pair or NULL */
{
    char line[TAPI_LINE_SZ];
    if (ok) {
        if (extra && *extra)
            snprintf(line, sizeof(line), "{\"ok\":true,\"op\":\"%s\",%s}\n", op, extra);
        else
            snprintf(line, sizeof(line), "{\"ok\":true,\"op\":\"%s\"}\n", op);
    } else {
        char esc[2048];
        jsonEscW(esc, sizeof(esc), msg);
        snprintf(line, sizeof(line), "{\"ok\":false,\"op\":\"%s\",\"rc\":%d,\"msg\":\"%s\"}\n", op, rc, esc);
    }
    write(gProtoFd, line, strlen(line));
    fflush(stdout);
    return ok ? 0 : rc;
}

static void dsmMsg(int rc)
{
    gRcMsg[0] = 0;
    if (gHandle) (void)dsmRCMsg(gHandle, rc, gRcMsg);
    if (!gRcMsg[0]) snprintf(gRcMsg, sizeof(gRcMsg), "TSM RC %d", rc);
}

static int nameOK(const char **fs, const char **hl, const char **ll)
{
    const char *f = fStr("fs", "");
    const char *h = fStr("hl", "");
    const char *l = fStr("ll", "");
    size_t fl = strlen(f), hl_ = strlen(h), ll_ = strlen(l);
    if (fl == 0 || fl >= DSM_MAX_FSNAME_LENGTH) return -1;
    if (hl_ >= DSM_MAX_HL_LENGTH) return -1;
    if (ll_ == 0 || ll_ >= DSM_MAX_LL_LENGTH) return -1;
    *fs = f; *hl = h; *ll = l;
    return 0;
}

/* TSM object names require the high- and low-level qualifiers to be
   directory-delimiter-qualified (ANS0283E/ANS0225E if not). The driver
   passes bare hl/ll (no leading '/'); this prepends exactly one '/' when
   absent. An empty hl (top-of-filespace object) stays empty — the ll
   qualifier then carries the whole path ('/leaf'). */
static void qualCopy(char *dst, size_t dn, const char *src)
{
    if (!*src) { if (dn) dst[0] = '\0'; return; }
    if (src[0] == '/') { snprintf(dst, dn, "%s", src); return; }
    snprintf(dst, dn, "/%s", src);
}

/* ------------------------------------------------------------- signon */

static int cmdSignon(const char *op)
{
    const char *node      = fStr("node", "");
    const char *owner     = fStr("owner", "");
    const char *clientdir = fStr("clientdir", "");
    const char *dsmopt    = fStr("dsmopt", "");
    const char *options   = fStr("options", "");
    const char *filespace = fStr("fs", "");
    (void)node;

    if (gHandle) return rsend(op, 0, -1, "already signed on", NULL);
    if (!*node) return rsend(op, 0, -1, "node is required", NULL);
    if (!*clientdir) return rsend(op, 0, -1, "clientdir is required (holds dsm.sys/dsm.opt/dsmkey)", NULL);

    if (!gSetUpDone) {
        envSetUp env;
        memset(&env, 0, sizeof(env));
        env.stVersion = envSetUpVersion;
        snprintf(env.dsmiDir, sizeof(env.dsmiDir), "%s", clientdir);
        snprintf(env.dsmiConfig, sizeof(env.dsmiConfig), "%s", *dsmopt ? dsmopt : "");
        snprintf(env.dsmiLog, sizeof(env.dsmiLog), "%s", clientdir);
        snprintf(env.logName, sizeof(env.logName), "tsmapi.log");
        char *argvec[2] = { gArgv0, NULL };
        env.argv = argvec;
        int rc = dsmSetUp(DSM_SINGLETHREAD, &env);
        if (rc != DSM_RC_OK) { dsmMsg(rc); snprintf(gRcMsg, sizeof(gRcMsg), "dsmSetUp failed"); return rsend(op, 0, rc, gRcMsg, NULL); }
        gSetUpDone = 1;
    }

    dsmApiVersionEx apiV = {0};
    apiV.stVersion = apiVersionExVer;
    apiV.version = DSM_API_VERSION;
    apiV.release = DSM_API_RELEASE;
    apiV.level = DSM_API_LEVEL;
    apiV.subLevel = DSM_API_SUBLEVEL;

    dsmAppVersion appV = {0};
    appV.stVersion = appVersionVer;
    appV.applicationVersion = DSM_API_VERSION;
    appV.applicationRelease = DSM_API_RELEASE;
    appV.applicationLevel = DSM_API_LEVEL;
    appV.applicationSubLevel = DSM_API_SUBLEVEL;

    dsmInitExIn_t in = {0};
    dsmInitExOut_t out = {0};
    in.stVersion = dsmInitExInVersion;
    in.apiVersionExP = &apiV;
    in.clientNodeNameP = (char *)node;
    in.clientOwnerNameP = *owner ? (char *)owner : (char *)node;
    in.clientPasswordP = NULL;      /* keyring lookup (operator-provisioned) */
    in.applicationTypeP = "Unix";
    in.configfile = *dsmopt ? (char *)dsmopt : NULL;
    in.options = *options ? (char *)options : NULL;
    in.dirDelimiter = '/';
    in.useUnicode = bFalse;
    in.appVersionP = &appV;
    out.stVersion = dsmInitExOutVersion;

    int rc = dsmInitEx(&gHandle, &in, &out);
    if (rc != DSM_RC_OK) {
        dsmMsg(rc);
        if (gHandle) dsmTerminate(gHandle);
        gHandle = 0;
return rsend(op, 0, rc, gRcMsg, NULL);
    }

    /* Register the filespace we'll write under. Tolerate "already
     * registered"; a hard failure is NOT fatal here — the send will
     * surface it with the server-side reason. */
    if (*filespace) {
        regFSData regfs;
        memset(&regfs, 0, sizeof(regfs));
        regfs.stVersion = regFSDataVersion;
        regfs.fsName = (char *)filespace;
        regfs.fsType = "VERSITYGW";
        regfs.capacity.hi = regfs.capacity.lo = 0;
        regfs.occupancy.hi = regfs.occupancy.lo = 0;
        int r2 = dsmRegisterFS(gHandle, &regfs);
        if (r2 != DSM_RC_OK && r2 != DSM_RC_FS_ALREADY_REGED) {
            dsmMsg(r2);
            /* log-and-continue; dsmSendObj will report the real cause */
        }
    }

    char extra[256];
    snprintf(extra, sizeof(extra), "\"server\":\"%s\",\"sv\":\"%u.%u.%u.%u\"",
             out.adsmServerName, out.serverVer, out.serverRel, out.serverLev, out.serverSubLev);
return rsend(op, 1, 0, NULL, extra);
}

/* ------------------------------------------------------- query / state */

typedef struct {
    dsUint32_t hi, lo;
    long long  size;
    int        active;
    long       ins;      /* insDate encoded for "latest wins" comparison */
} tapiObj;

static tapiObj gObjs[TAPI_MAX_VER];
static int     gNobj = 0;

static int queryName(const char *fs, const char *hl, const char *ll)
{
    if (!gHandle) return -1;
    dsmObjName objName;
    memset(&objName, 0, sizeof(objName));
    snprintf(objName.fs, sizeof(objName.fs), "%s", fs);
    qualCopy(objName.hl, sizeof(objName.hl), hl);
    qualCopy(objName.ll, sizeof(objName.ll), ll);
    objName.objType = DSM_OBJ_FILE;

    static char anyOwner[1] = {0};
    qryBackupData qBuf;
    memset(&qBuf, 0, sizeof(qBuf));
    qBuf.stVersion = qryBackupDataVersion;
    qBuf.objName = &objName;
    qBuf.owner = anyOwner;
    qBuf.objState = DSM_ACTIVE;

    int rc = dsmBeginQuery(gHandle, qtBackup, (dsmQueryBuff *)&qBuf);
    if (rc != DSM_RC_OK) { dsmMsg(rc); return rc; }

    DataBlk blk;
    memset(&blk, 0, sizeof(blk));
    blk.stVersion = DataBlkVersion;
    blk.bufferLen = sizeof(qryRespBackupData);
    blk.bufferPtr = (char *)calloc(1, sizeof(qryRespBackupData));
    if (!blk.bufferPtr) { dsmEndQuery(gHandle); return -1; }
    /* The response buffer must carry the matching version, or the library
     * returns ANS0245E (RC2065) "caller's structure version differs". */
    ((qryRespBackupData *)blk.bufferPtr)->stVersion = qryRespBackupDataVersion;
    gNobj = 0;
    while ((rc = dsmGetNextQObj(gHandle, &blk)) == DSM_RC_MORE_DATA && gNobj < TAPI_MAX_VER) {
        qryRespBackupData *r = (qryRespBackupData *)blk.bufferPtr;
        gObjs[gNobj].hi = r->objId.hi;
        gObjs[gNobj].lo = r->objId.lo;
        gObjs[gNobj].size = (long long)r->sizeEstimate.lo +
                            ((long long)r->sizeEstimate.hi << 32);
        gObjs[gNobj].active = (r->objState == DSM_ACTIVE) ? 1 : 0;
        dsmDate *d = &r->insDate;
        long ins = ((long)d->year << 26) | ((long)d->month << 22) | ((long)d->day << 17)
                 | ((long)d->hour << 10) | ((long)d->minute << 4) | (long)d->second;
        gObjs[gNobj].ins = ins;
        gNobj++;
    }
    free(blk.bufferPtr);
    blk.bufferPtr = NULL;
    if (rc != DSM_RC_OK && rc != DSM_RC_FINISHED) { dsmMsg(rc); dsmEndQuery(gHandle); return rc; }
    dsmEndQuery(gHandle);
    return 0;
}

/* index of the latest version (max insertion date, then objId), -1 if none */
static int latestIdx(void)
{
    int best = -1;
    for (int i = 0; i < gNobj; i++) {
        if (best < 0) { best = i; continue; }
        if (gObjs[i].ins > gObjs[best].ins ||
            (gObjs[i].ins == gObjs[best].ins &&
             ((long long)gObjs[i].hi > (long long)gObjs[best].hi ||
              ((long long)gObjs[i].hi == (long long)gObjs[best].hi && gObjs[i].lo > gObjs[best].lo))))
            best = i;
    }
    return best;
}

/* ------------------------------------------------------------- send */

static int cmdSend(const char *op)
{
    const char *fs, *hl, *ll;
    if (nameOK(&fs, &hl, &ll)) return rsend(op, 0, -1, "bad fs/hl/ll (len or empty ll)", NULL);
    if (!gHandle) return rsend(op, 0, -1, "not signed on", NULL);
    const char *path = fStr("path", "");
    if (!*path) return rsend(op, 0, -2, "path is required", NULL);

    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return rsend(op, 0, -2, "not a regular file", NULL);
    unsigned long long size = (unsigned long long)st.st_size;

    /* The DAPI transaction path invalidates file descriptors: once
     * dsmBeginTxn/dsmSendObj have run, read() on any open fd returns EOF
     * (verified live). The IBM reference pattern (callret.c, dsmgrp.c)
     * therefore stages file data in memory BEFORE the txn and feeds
     * dsmSendData from a buffer rather than from an app-managed file.
     * We mirror that: pre-read the whole object, then close, then txn. */
    char *data = NULL;
    if (size > 0) {
        data = malloc((size_t)size);
        if (!data) return rsend(op, 0, -2, "alloc(data) failed", NULL);
        int fd = open(path, O_RDONLY);
        if (fd < 0) { free(data); return rsend(op, 0, -2, "open(path) failed", NULL); }
        size_t got = 0;
        while (got < (size_t)size) {
            ssize_t n = read(fd, data + got, (size_t)size - got);
            if (n < 0) { if (errno == EINTR) continue; break; }
            if (n == 0) break;
            got += (size_t)n;
        }
        close(fd);
        if (got != (size_t)size) { free(data); return rsend(op, 0, -3, "short read of source file (file may have vanished)", NULL); }
    }

    dsmObjName objName;
    memset(&objName, 0, sizeof(objName));
    snprintf(objName.fs, sizeof(objName.fs), "%s", fs);
    qualCopy(objName.hl, sizeof(objName.hl), hl);
    qualCopy(objName.ll, sizeof(objName.ll), ll);
    objName.objType = DSM_OBJ_FILE;

    ObjAttr attr;
    memset(&attr, 0, sizeof(attr));
    attr.stVersion = ObjAttrVersion;
    attr.sizeEstimate.hi = (dsUint32_t)(size >> 32);
    attr.sizeEstimate.lo = (dsUint32_t)(size & 0xFFFFFFFFuL);

    int rc = dsmBeginTxn(gHandle);
    if (rc != DSM_RC_OK) { dsmMsg(rc); free(data); return rsend(op, 0, rc, gRcMsg, NULL); }

    /* Bind the default mgmt class. dsmSendObj without this fails with
     * ANS0238E (DSM_RC_BAD_CALL_SEQUENCE). */
    mcBindKey bindKey;
    memset(&bindKey, 0, sizeof(bindKey));
    bindKey.stVersion = mcBindKeyVersion;
    rc = dsmBindMC(gHandle, &objName, stBackup, &bindKey);
    if (rc != DSM_RC_OK) {
        dsUint16_t rsn = 0;
        dsmMsg(rc); dsmEndTxn(gHandle, DSM_VOTE_ABORT, &rsn);
        free(data); return rsend(op, 0, rc, gRcMsg, NULL);
    }

    int fail = -1;
    rc = dsmSendObj(gHandle, stBackup, NULL, &objName, &attr, NULL);
    if (rc != DSM_RC_OK) fail = rc;

    /* Feed dsmSendData from the pre-read buffer in TAPI_BUF_SZ chunks. */
    unsigned long long left = size;
    while (fail == -1 && left > 0) {
        size_t want = left > TAPI_BUF_SZ ? TAPI_BUF_SZ : (size_t)left;
        DataBlk blk;
        memset(&blk, 0, sizeof(blk));
        blk.stVersion = DataBlkVersion;
        blk.bufferLen = (dsUint32_t)want;
        blk.bufferPtr = data + ((unsigned long long)size - left);
        rc = dsmSendData(gHandle, &blk);
        if (rc != DSM_RC_OK) { dsmMsg(rc); fail = rc; }
        else left -= (unsigned long long)want;
    }

    if (fail == -1) {
        rc = dsmEndSendObj(gHandle);
        if (rc != DSM_RC_OK) fail = rc;
    }
    free(data);

    dsUint16_t reason = 0;
    int rc2 = dsmEndTxn(gHandle, fail == -1 ? DSM_VOTE_COMMIT : DSM_VOTE_ABORT, &reason);
    if (fail != -1 || rc2 != DSM_RC_OK) {
        if (fail > 0) dsmMsg(fail);
        else dsmMsg(rc2);
 return rsend(op, 0, fail < 0 ? fail : (fail > 0 ? fail : rc2), gRcMsg, NULL);
    }
 return rsend(op, 1, 0, NULL, NULL);
}

/* ------------------------------------------------------------- get */

static unsigned long long writeFull(int fd, const char *buf, unsigned long long n)
{
    unsigned long long off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) { if (errno == EINTR) continue; return ~0ULL; }
        off += (unsigned long long)w;
    }
    return off;
}

static int cmdGet(const char *op)
{
    const char *fs, *hl, *ll;
    if (nameOK(&fs, &hl, &ll)) return rsend(op, 0, -1, "bad fs/hl/ll", NULL);
    if (!gHandle) return rsend(op, 0, -1, "not signed on", NULL);
    const char *path = fStr("path", "");
    if (!*path) return rsend(op, 0, -1, "path is required", NULL);

    if (queryName(fs, hl, ll) != 0) return rsend(op, 0, -1, gRcMsg, NULL);
    int li = latestIdx();
    if (li < 0) return rsend(op, 1, 0, NULL, "\"found\":false");

    ObjID id;
    id.hi = gObjs[li].hi;
    id.lo = gObjs[li].lo;

    dsmGetList list;
    memset(&list, 0, sizeof(list));
    list.stVersion = dsmGetListVersion;
    list.numObjId = 1;
    ObjID *ids = malloc(sizeof(ObjID));
    if (!ids) return rsend(op, 0, -2, "alloc", NULL);
    ids[0] = id;
    list.objId = ids;

    int rc = dsmBeginGetData(gHandle, bTrue /*mountWait*/, gtBackup, &list);
    free(ids);
    if (rc != DSM_RC_OK) { dsmMsg(rc); return rsend(op, 0, rc, gRcMsg, NULL); }

    char tmpPath[TAPI_LINE_SZ];
    if (snprintf(tmpPath, sizeof(tmpPath), "%s.tsmpartial", path) >= (int)sizeof(tmpPath)) {
        dsmEndGetData(gHandle);
return rsend(op, 0, -2, "path too long", NULL);
    }
    int fd = open(tmpPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { dsmEndGetData(gHandle); return rsend(op, 0, -2, "open(.tsmpartial) failed", NULL); }

    DataBlk blk;
    memset(&blk, 0, sizeof(blk));
    blk.stVersion = DataBlkVersion;
    blk.bufferLen = TAPI_BUF_SZ;
    blk.bufferPtr = gBuf;

    unsigned long long got = 0;
    int fail = 0;
    /* Reference (callmt1.c): dsmGetObj(handle, objId, &blk) with a
     * pre-initialized DataBlk. Depending on payload size it may
     * (a) fill blk and return DSM_RC_MORE_DATA (loop dsmGetData for more), or
     * (b) fill blk and return DSM_RC_FINISHED (small object — write it,
     *     call dsmEndGetObj, done). We handle both. */
    rc = dsmGetObj(gHandle, &id, &blk);
    if (rc == DSM_RC_OK || rc == DSM_RC_FINISHED || rc == DSM_RC_MORE_DATA) {
        if (blk.numBytes) {
            unsigned long long w = writeFull(fd, gBuf, (unsigned long long)blk.numBytes);
            if (w == ~0ULL) fail = -5;
            else got += w;
        }
        if (rc == DSM_RC_MORE_DATA) {
            while (rc == DSM_RC_MORE_DATA) {
                rc = dsmGetData(gHandle, &blk);
                if (rc == DSM_RC_MORE_DATA && blk.numBytes) {
                    unsigned long long w = writeFull(fd, gBuf, (unsigned long long)blk.numBytes);
                    if (w == ~0ULL) { fail = -5; break; }
                    got += w;
                }
            }
            if (rc == DSM_RC_FINISHED) (void)dsmEndGetObj(gHandle);
            if (!fail && rc != DSM_RC_FINISHED) fail = rc;
        } else {
            /* FINISHED from dsmGetObj directly */
            (void)dsmEndGetObj(gHandle);
        }
    } else {
        fail = rc;   /* dsmGetObj error */
    }
    (void)dsmEndGetData(gHandle);
    close(fd);

    if (fail) {
        unlink(tmpPath);
        if (fail < 0) snprintf(gRcMsg, sizeof(gRcMsg), "local io error %d", fail);
        else dsmMsg(fail);
return rsend(op, 0, fail, gRcMsg, NULL);
    }

    char line[TAPI_LINE_SZ];
    char esc[2048];
    jsonEscW(esc, sizeof(esc), tmpPath);
    int n = snprintf(line, sizeof(line),
                     "{\"ok\":true,\"op\":\"%s\",\"found\":true,\"bytes\":%llu,\"tmp\":\"%s\"}\n",
                     op, got, esc);
    if ((size_t)n < sizeof(line)) write(gProtoFd, line, (size_t)n);
    return 0;
}

/* ----------------------------------------------------------- delete */

static int cmdDelete(const char *op)
{
    const char *fs, *hl, *ll;
    if (nameOK(&fs, &hl, &ll)) return rsend(op, 0, -1, "bad fs/hl/ll", NULL);
    if (!gHandle) return rsend(op, 0, -1, "not signed on", NULL);
    if (queryName(fs, hl, ll) != 0) return rsend(op, 0, -1, gRcMsg, NULL);
    if (gNobj == 0) return rsend(op, 1, 0, NULL, "\"deleted\":0");

    int rc = dsmBeginTxn(gHandle);
    if (rc != DSM_RC_OK) { dsmMsg(rc); return rsend(op, 0, rc, gRcMsg, NULL); }

    int deleted = 0, fail = -1;
    for (int i = 0; i < gNobj; i++) {
        dsmDelInfo di;
        memset(&di, 0, sizeof(di));
        di.backIDInfo.stVersion = delBackIDVersion;
        di.backIDInfo.objId.hi = gObjs[i].hi;
        di.backIDInfo.objId.lo = gObjs[i].lo;
        rc = dsmDeleteObj(gHandle, dtBackupID, di);
        if (rc != DSM_RC_OK && fail == -1) { fail = rc; dsmMsg(rc); }
        else if (rc == DSM_RC_OK) deleted++;
    }

    dsUint16_t reason = 0;
    int rc2 = dsmEndTxn(gHandle, fail == -1 ? DSM_VOTE_COMMIT : DSM_VOTE_ABORT, &reason);
    if (fail != -1 || rc2 != DSM_RC_OK) {
        dsmMsg(fail > 0 ? fail : rc2);
return rsend(op, 0, fail > 0 ? fail : rc2, gRcMsg, NULL);
    }
    char extra[64];
    snprintf(extra, sizeof(extra), "\"deleted\":%d", deleted);
return rsend(op, 1, 0, NULL, extra);
}

/* --------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    (void)argc;
    gArgv0 = strdup(argv[0]);

    /* Protocol channel = original stdout (fd 1); C/DPI diagnostics go to
     * stderr afterwards. */
    gProtoFd = dup(1);
    if (gProtoFd < 0) { perror("dup"); return 70; }
    if (dup2(2, 1) < 0) { perror("dup2"); return 70; }
    signal(SIGPIPE, SIG_IGN);

    static char line[TAPI_LINE_SZ];
    while (fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = 0;
        if (!*line) continue;
        gNFields = 0;
        if (jsonGet(line, len) != 0) continue;   /* not a recognizable command */
        const char *op = fStr("op", "");
        int quit = 0;
        if (!strcmp(op, "ping")) rsend(op, 1, 0, NULL, NULL);
        else if (!strcmp(op, "version")) {
            char extra[128];
            snprintf(extra, sizeof(extra), "\"sdk\":\"%s\"", COMMON_VERSIONTXT);
            rsend(op, 1, 0, NULL, extra);
        }
        else if (!strcmp(op, "signon")) (void)cmdSignon(op);
        else if (!strcmp(op, "send")) (void)cmdSend(op);
        else if (!strcmp(op, "get")) (void)cmdGet(op);
        else if (!strcmp(op, "delete")) (void)cmdDelete(op);
        else if (!strcmp(op, "query")) {
            const char *fs, *hl, *ll;
            char outb[TAPI_LINE_SZ];
            int o = 0;
            if (nameOK(&fs, &hl, &ll) != 0)
                rsend(op, 0, -1, "bad fs/hl/ll", NULL);
            else if (queryName(fs, hl, ll) != 0)
                rsend(op, 0, -1, gRcMsg, NULL);
            else {
                for (int i = 0; i < gNobj && o < TAPI_LINE_SZ - 128; i++)
                    o += snprintf(outb + o, TAPI_LINE_SZ - (size_t)o,
                                 "%s{\"hi\":%u,\"lo\":%u,\"size\":%lld,\"active\":%d}",
                                 i ? "," : "", gObjs[i].hi, gObjs[i].lo, gObjs[i].size, gObjs[i].active);
                char lineout[TAPI_LINE_SZ];
                int n = snprintf(lineout, sizeof(lineout),
                                 "{\"ok\":true,\"op\":\"query\",\"objs\":[%s]}\n", outb);
                write(gProtoFd, lineout, (size_t)n);
            }
        }
        else if (!strcmp(op, "quit")) {
            rsend(op, 1, 0, NULL, NULL);
            quit = 1;
        }
        else {
            rsend(op, 0, -1, "unknown op", NULL);
        }
        (void)fflush(NULL);
        fFree();
        if (quit) break;
    }
    if (gHandle) dsmTerminate(gHandle);
    if (gSetUpDone) dsmCleanUp(DSM_SINGLETHREAD);
    return 0;
}
