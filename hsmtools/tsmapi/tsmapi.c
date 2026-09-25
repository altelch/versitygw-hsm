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
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
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

/* ------------------------------------------------- SHA-256 (self-contained)
 * The host glibc predates <crypto/sha.h>, so a compact public-domain-style
 * SHA-256 lives here. Used ONLY to compute the metadata-companion object
 * name (metaName), so the CLI agrees with the Go driver without new
 * dependencies. */

typedef struct { unsigned int h[8]; unsigned char buf[64]; unsigned long long len; } sha256t;

static void sha256_init(sha256t *s)
{
    s->h[0] = 0x6a09e667; s->h[1] = 0xbb67ae85; s->h[2] = 0x3c6ef372; s->h[3] = 0xa54ff53a;
    s->h[4] = 0x510e527f; s->h[5] = 0x9b05688c; s->h[6] = 0x1f83d9ab; s->h[7] = 0x5be0cd19;
    s->len = 0;
}

#define ROR32(x, b) (((x) >> (b)) | ((x) << (32 - (b))))

static void sha256_block(sha256t *s, const unsigned char *p)
{
    static const int K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    unsigned int w[64], a, b, c, d, e, f, g, h;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (unsigned int)((p[i*4] << 24) | (p[i*4+1] << 16) | (p[i*4+2] << 8) | p[i*4+3]);
    for (i = 16; i < 64; i++) {
        unsigned int s0 = ROR32(w[i-15], 7) ^ ROR32(w[i-15], 18) ^ (w[i-15] >> 3);
        unsigned int s1 = ROR32(w[i-2], 17) ^ ROR32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
    e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (i = 0; i < 64; i++) {
        unsigned int S1  = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        unsigned int ch  = (e & f) ^ (~e & g);
        unsigned int t1 = h + S1 + ch + K[i] + w[i];
        unsigned int S0  = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        unsigned int mj  = (a & b) ^ (a & c) ^ (b & c);
        unsigned int t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha256_update(sha256t *s, const unsigned char *p, size_t n)
{
    while (n > 0) {
        size_t take = 64 - (size_t)(s->len & 63);
        if (take == 0) take = 64;
        if (take > n) take = n;
        memcpy(s->buf + (size_t)(s->len & 63), p, take);
        s->len += (unsigned long long)take;
        p += take; n -= take;
        if ((s->len & 63) == 0) sha256_block(s, s->buf);
    }
}

static void sha256_final(unsigned char out[32], sha256t *s)
{
    unsigned long long bits = s->len << 3;
    unsigned char pad = 0x80, z = 0;
    sha256_update(s, &pad, 1);
    while ((s->len & 63) != 56) sha256_update(s, &z, 1);
    unsigned char lenb[8];
    for (int i = 0; i < 8; i++)
        lenb[i] = (unsigned char)(bits >> (56 - 8*i));
    sha256_update(s, lenb, 8);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 4; j++)
            out[i*4 + j] = (unsigned char)(s->h[i] >> (24 - 8*j));
}

static const char META_SUFFIX_STR[] = ".hsm-meta";

/* metaName: deterministic metadata-companion object name, mirroring the Go
 * driver (backend/posixhsm MetaName):
 *
 *   <ll>-<first 8 hex bytes of sha256("<hl>:<ll>")>.hsm-meta   (<=255 bytes)
 *   <same 16 hex>.hsm-meta                                      (long leaf)
 *
 * hl/ll may carry a leading '/' (TSM response form); it is stripped first
 * so the digest matches what the Go side hashes.
 */
static void metaName(const char *hl, const char *ll, char *out /* >= 256 */)
{
    const char *h = hl, *l = ll;
    if (*h == '/') h++;
    if (*l == '/') l++;
    sha256t s;
    unsigned char d[32];
    unsigned char colon = ':';
    sha256_init(&s);
    if (*h) sha256_update(&s, (const unsigned char *)h, strlen(h));
    sha256_update(&s, &colon, 1);
    if (*l) sha256_update(&s, (const unsigned char *)l, strlen(l));
    sha256_final(d, &s);
    char hexh[17];
    for (int i = 0; i < 8; i++)
        sprintf(hexh + i*2, "%02x", d[i]);
    /* "<ll>-<h16>.hsm-meta" fits in the 256-byte out buffer only when
     * strlen(l) + 1 + 16 + 9 <= 255 — otherwise take the hash-only form,
     * exactly like the Go MetaName fallback. */
    if (strlen(l) + 26 <= 255)
        snprintf(out, 256, "%s-%s%s", l, hexh, META_SUFFIX_STR);
    else
        snprintf(out, 256, "%s%s", hexh, META_SUFFIX_STR);
}

static int isMetaName(const char *name)
{
    size_t ln = strlen(name), sn = strlen(META_SUFFIX_STR);
    return ln >= sn && !memcmp(name + ln - sn, META_SUFFIX_STR, sn);
}

/* isMetaName is also the filter for `ls`: companion objects are hidden by
 * default (passed to the CLI as an ll qualifier). */

/* jdec: decode one JSON string. p points at the opening '"'; returns a
 * malloc'd decoded string and advances *next past the closing quote.
 * Handles the same escape set as the flat protocol parser (jsonGet).
 * NULL on malformed input. */
static char *jdec(const char *p, const char *end, const char **next)
{
    if (p >= end || *p != '"') return NULL;
    const char *vs = p + 1, *ve = vs;
    while (ve < end) {
        if (*ve == '\\') { if (ve + 1 < end) ve++; ve++; continue; }
        if (*ve == '"') break;
        ve++;
    }
    if (ve >= end) return NULL;
    char *o = malloc(ve - vs + 2);
    if (!o) return NULL;
    for (const char *c = vs; c < ve;) {
        if (*c != '\\') { *o++ = *c++; continue; }
        c++;
        if (c >= ve) { free(o); return NULL; }
        switch (*c) {
            case 'n':  *o++ = '\n'; break;
            case 't':  *o++ = '\t'; break;
            case 'r':  *o++ = '\r'; break;
            case '"':  *o++ = '"';  break;
            case '\\': *o++ = '\\'; break;
            case '/':  *o++ = '/';  break;
            case 'u': {
                if (c + 4 < ve) {
                    unsigned code = 0;
                    int ok = 1;
                    for (int h = 0; h < 4; h++) {
                        char hc = c[1 + h];
                        int dv = (hc >= '0' && hc <= '9') ? hc - '0' :
                                 (hc >= 'a' && hc <= 'f') ? hc - 'a' + 10 :
                                 (hc >= 'A' && hc <= 'F') ? hc - 'A' + 10 : -1;
                        if (dv < 0) { ok = 0; break; }
                        code = code * 16 + (unsigned)dv;
                    }
                    if (ok) {
                        if (code < 0x80) *o++ = (char)code;
                        else if (code < 0x800) { *o++ = (char)(0xC0 | (code >> 6)); *o++ = (char)(0x80 | (code & 63)); }
                        else { *o++ = (char)(0xE0 | (code >> 12)); *o++ = (char)(0x80 | ((code >> 6) & 63)); *o++ = (char)(0x80 | (code & 63)); }
                        c += 4;
                        break;
                    }
                }
                *o++ = '?';
                break;
            }
            default: *o++ = *c; break;
        }
        c++;
    }
    *o = 0;
    if (next) *next = ve + 1;
    return o;
}

/* b64dec: base64 (standard alphabet) decode into a malloc'd buffer.
 * Whitespace and a trailing '=' are tolerated. -1 on invalid input. */
static int b64dec(const char *s, unsigned char **out, size_t *olen)
{
    size_t cap = strlen(s) * 3 / 4 + 4;
    unsigned char *buf = malloc(cap ? cap : 1);
    if (!buf) return -1;
    size_t o = 0;
    int acc = 0, bits = 0;
    for (const char *p = s; *p; p++) {
        int v;
        if (*p >= 'A' && *p <= 'Z')       v = *p - 'A';
        else if (*p >= 'a' && *p <= 'z')  v = *p - 'a' + 26;
        else if (*p >= '0' && *p <= '9')  v = *p - '0' + 52;
        else if (*p == '+')  v = 62;
        else if (*p == '/')  v = 63;
        else if (*p == '=')  break;
        else if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') continue;
        else { free(buf); return -1; }
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            buf[o++] = (unsigned char)((acc >> bits) & 0xff);
        }
    }
    *out = buf;
    *olen = o;
    return 0;
}

/* makeDirsFor: mkdir -p every directory component of a file path. */
static int makeDirsFor(const char *file)
{
    char *tmp = strdup(file);
    if (!tmp) return -1;
    int err = 0;
    for (char *p = tmp + 1; *p && !err; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) err = 1;
            *p = '/';
        }
    }
    free(tmp);
    return err ? -1 : 0;
}

/* writeAllFile: create/truncate path and write the whole buffer. */
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
static int writeAllFile(const char *path, const char *buf, size_t n)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    unsigned long long w = writeFull(fd, buf, (unsigned long long)n);
    int err = (w == ~0ULL) ? -1 : 0;
    close(fd);
    return err;
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

/*
 * Version policy — why we do NOT need adsmpipe-style multi-version skip.
 *
 * The classic IBM references (callmt1.c, dsmgrp.c) and especially the adsmpipe
 * reference tool support fetching an *arbitrary* numbered version: they loop
 * dsmGetNextQObj, feeding a dummy DataBlk until they reach the requested
 * version_index, and use that single objId as the restore target.
 *
 * Our lifecycle model is simpler, so we skip that:
 *
 *   - The driver owns exactly ONE live copy of a name at any time:
 *       `send`  creates a *new* backup copy (new objId, newest insDate).
 *       `delete` purges *every* active backup version of the name (see
 *       cmdDelete — we iterate all gNobj entries), which is the semantic
 *       the Go side wants (locator is "gone" => all physical copies go).
 *   - There is no user-visible "version N" to select. The only read path is
 *       `get`, and it always wants the content that is *now* the current
 *       object, i.e. the newest-insDate copy.
 *
 * So "skip to version N" would be dead code: either we restore the newest
 * one (get) or we delete them all (delete).  Keeping the single `latestIdx`
 * selection below is both correct for that model and cheaper than the
 * dummy-Blk loop adsmpipe uses (one less dsmGetNextQObj round-trip per
 * version we do not need).
 */
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

/* fetchLatest: restore the newest active backup version of (fs,hl,ll) into
 * the already-open file descriptor outFd. Returns 0 on success (bytesOut =
 * bytes written), 1 if the object has no active backup version, or a
 * negative value on failure (gRcMsg set via dsmMsg for DAPI errors). */
static int fetchLatest(const char *fs, const char *hl, const char *ll,
                       int outFd, unsigned long long *bytesOut)
{
    *bytesOut = 0;
    if (queryName(fs, hl, ll) != 0) return -1;
    int li = latestIdx();
    if (li < 0) return 1;

    ObjID id;
    id.hi = gObjs[li].hi;
    id.lo = gObjs[li].lo;

    dsmGetList list;
    memset(&list, 0, sizeof(list));
    list.stVersion = dsmGetListVersion;
    list.numObjId = 1;
    ObjID *ids = malloc(sizeof(ObjID));
    if (!ids) return -1;
    ids[0] = id;
    list.objId = ids;

    int rc = dsmBeginGetData(gHandle, bTrue /*mountWait*/, gtBackup, &list);
    free(ids);
    if (rc != DSM_RC_OK) { dsmMsg(rc); return rc; }

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
            unsigned long long w = writeFull(outFd, gBuf, (unsigned long long)blk.numBytes);
            if (w == ~0ULL) fail = -5;
            else got += w;
        }
        if (rc == DSM_RC_MORE_DATA) {
            while (rc == DSM_RC_MORE_DATA) {
                rc = dsmGetData(gHandle, &blk);
                if (rc == DSM_RC_MORE_DATA && blk.numBytes) {
                    unsigned long long w = writeFull(outFd, gBuf, (unsigned long long)blk.numBytes);
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

    if (fail) {
        if (fail < 0) snprintf(gRcMsg, sizeof(gRcMsg), "local io error %d", fail);
        else dsmMsg(fail);
        return fail;
    }
    *bytesOut = got;
    return 0;
}

static int cmdGet(const char *op)
{
    const char *fs, *hl, *ll;
    if (nameOK(&fs, &hl, &ll)) return rsend(op, 0, -1, "bad fs/hl/ll", NULL);
    if (!gHandle) return rsend(op, 0, -1, "not signed on", NULL);
    const char *path = fStr("path", "");
    if (!*path) return rsend(op, 0, -1, "path is required", NULL);

    char tmpPath[TAPI_LINE_SZ];
    if (snprintf(tmpPath, sizeof(tmpPath), "%s.tsmpartial", path) >= (int)sizeof(tmpPath))
        return rsend(op, 0, -2, "path too long", NULL);
    if (makeDirsFor(tmpPath)) return rsend(op, 0, -2, "mkdir parent of .tsmpartial failed", NULL);
    int fd = open(tmpPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return rsend(op, 0, -2, "open(.tsmpartial) failed", NULL);

    unsigned long long got = 0;
    int r = fetchLatest(fs, hl, ll, fd, &got);
    close(fd);

    if (r == 1) {
        unlink(tmpPath);
        return rsend(op, 1, 0, NULL, "\"found\":false");
    }
    if (r) {
        unlink(tmpPath);
        if (r > 0) dsmMsg(r);
        return rsend(op, 0, r, gRcMsg, NULL);
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


/* =============================================================== CLI =====
 * One-shot operator modes, separate from the NDJSON protocol:
 *
 *   tsmapi ls     -n NODE [-c CLIENTDIR] [-o DSMOPT] [-M]
 *       list the active backup objects of the node, one JSON object per
 *       line on stdout:
 *         {"fs":"...","hl":"...","ll":"...","size":N,"latest":true,
 *          "ins":"YYYY-MM-DD hh:mm:ss"}
 *       Companion metadata objects ("ll" ending in ".hsm-meta") are hidden
 *       by default; -M shows them. "latest" marks the newest copy of each
 *       name. hl/ll are shown without the leading '/' qualifier.
 *
 *   tsmapi restore -n NODE [-c CLIENTDIR] [-o DSMOPT] -d DEST
 *                  [-m xattr|sidecar|raw|none] [--sidecar DIR] <ERE>...
 *       restore every active backup object whose "hl/ll" path matches any of
 *       the POSIX EREs (search semantics, case-sensitive), plus its metadata
 *       companion if one exists. The destination layout is
 *       DEST/<hl>/<ll>. Companion replay follows -m:
 *         xattr    (default): setxattr("user.<attr>") onto DEST/<hl>/<ll>
 *         sidecar : one file per attribute at DIR/<hl>/<ll>/meta/<attr>
 *         raw     : the companion JSON payload at DEST/<hl>/<ll>.hsm-meta
 *         none    : data only
 *
 * Shared: -c defaults to /opt/tivoli/tsm/client/ba/bin (matching the Go
 * driver), -o is an extra dsm.opt path/option string.
 */

static int cliDsmSignon(const char *node, const char *clientdir,
                        const char *dsmopt, const char *options)
{
    if (gHandle) { snprintf(gRcMsg, sizeof gRcMsg, "already signed on"); return 1; }
    if (!node || !*node)      { snprintf(gRcMsg, sizeof gRcMsg, "node is required"); return 1; }
    if (!clientdir || !*clientdir) { snprintf(gRcMsg, sizeof gRcMsg, "clientdir is required"); return 1; }

    if (!gSetUpDone) {
        envSetUp env;
        memset(&env, 0, sizeof(env));
        env.stVersion = envSetUpVersion;
        snprintf(env.dsmiDir, sizeof(env.dsmiDir), "%s", clientdir);
        snprintf(env.dsmiConfig, sizeof(env.dsmiConfig), "%s", dsmopt ? dsmopt : "");
        snprintf(env.dsmiLog, sizeof(env.dsmiLog), "%s", clientdir);
        snprintf(env.logName, sizeof(env.logName), "tsmapi.log");
        char *argvec[2] = { gArgv0, NULL };
        env.argv = argvec;
        int rc = dsmSetUp(DSM_SINGLETHREAD, &env);
        if (rc != DSM_RC_OK) { dsmMsg(rc); snprintf(gRcMsg, sizeof gRcMsg, "dsmSetUp failed"); return 1; }
        gSetUpDone = 1;
    }

    dsmApiVersionEx apiV = {0};
    apiV.stVersion = apiVersionExVer;
    apiV.version   = DSM_API_VERSION;
    apiV.release   = DSM_API_RELEASE;
    apiV.level     = DSM_API_LEVEL;
    apiV.subLevel  = DSM_API_SUBLEVEL;

    dsmAppVersion appV = {0};
    appV.stVersion          = appVersionVer;
    appV.applicationVersion = DSM_API_VERSION;
    appV.applicationRelease = DSM_API_RELEASE;
    appV.applicationLevel   = DSM_API_LEVEL;
    appV.applicationSubLevel= DSM_API_SUBLEVEL;

    dsmInitExIn_t  in  = {0};
    dsmInitExOut_t out = {0};
    in.stVersion        = dsmInitExInVersion;
    in.apiVersionExP    = &apiV;
    in.clientNodeNameP  = (char *)node;
    in.clientOwnerNameP = (char *)node;
    in.clientPasswordP  = NULL;          /* keyring lookup (operator-provisioned) */
    in.applicationTypeP = "Unix";
    in.configfile       = dsmopt ? (char *)dsmopt : NULL;
    in.options          = options ? (char *)options : NULL;
    in.dirDelimiter     = '/';
    in.useUnicode       = bFalse;
    in.appVersionP      = &appV;
    out.stVersion       = dsmInitExOutVersion;

    int rc = dsmInitEx(&gHandle, &in, &out);
    if (rc != DSM_RC_OK) {
        dsmMsg(rc);
        if (gHandle) dsmTerminate(gHandle);
        gHandle = 0;
        return 1;
    }
    return 0;
}

/* --- enumeration ------------------------------------------------------------
 * Wildcard "all objects" query (the reference tool dapiqry.c uses exactly
 * this: hl="*", ll=slash-star, fs empty = all). Results go into a local table.
 */
typedef struct cliEnt {
    struct cliEnt *next;
    char           *fs, *hl, *ll;
    unsigned        hi, lo;
    long long       size;
    long            insKey;   /* sortable date key from dsmDate */
    dsmDate         ins;
    int             latest;   /* filled by cliMarkLatest */
} cliEnt;

static unsigned dateKey(const dsmDate *d)
{
    return ((unsigned)d->year * 10000u + (unsigned)d->month * 100u + (unsigned)d->day) * 10000u
         + (unsigned)d->hour * 100u + (unsigned)d->minute;
}

static int cliEnumAll(cliEnt **out, int *count)
{
    *out = NULL;
    *count = 0;
    if (!gHandle) { snprintf(gRcMsg, sizeof gRcMsg, "not signed on"); return 1; }

    dsmObjName objName;
    memset(&objName, 0, sizeof(objName));
    objName.fs[0] = 0;
    objName.hl[0] = '*';
    snprintf(objName.ll, sizeof(objName.ll), "/*");
    objName.objType = DSM_OBJ_FILE;

    static char anyOwner[1];
    qryBackupData qBuf;
    memset(&qBuf, 0, sizeof(qBuf));
    qBuf.stVersion = qryBackupDataVersion;
    qBuf.objName   = &objName;
    qBuf.owner     = anyOwner;
    qBuf.objState  = DSM_ACTIVE;

    int rc = dsmBeginQuery(gHandle, qtBackup, (dsmQueryBuff *)&qBuf);
    if (rc != DSM_RC_OK) { dsmMsg(rc); return 1; }

    DataBlk blk;
    memset(&blk, 0, sizeof(blk));
    blk.stVersion = DataBlkVersion;
    blk.bufferLen = sizeof(qryRespBackupData);
    blk.bufferPtr = (char *)calloc(1, sizeof(qryRespBackupData));
    if (!blk.bufferPtr) { dsmEndQuery(gHandle); return 1; }
    ((qryRespBackupData *)blk.bufferPtr)->stVersion = qryRespBackupDataVersion;

    int guard = 0;
    while ((rc = dsmGetNextQObj(gHandle, &blk)) == DSM_RC_MORE_DATA && guard++ < 10000000) {
        qryRespBackupData *r = (qryRespBackupData *)blk.bufferPtr;
        cliEnt *e = calloc(1, sizeof *e);
        if (!e) break;
        e->fs = strdup(r->objName.fs);
        e->hl = strdup(r->objName.hl);
        e->ll = strdup(r->objName.ll);
        e->hi = r->objId.hi;
        e->lo = r->objId.lo;
        e->size = (long long)r->sizeEstimate.lo + ((long long)r->sizeEstimate.hi << 32);
        e->ins = r->insDate;
        e->insKey = dateKey(&r->insDate);
        e->next = *out;
        *out = e;
        (*count)++;
    }
    free(blk.bufferPtr);
    if (rc != DSM_RC_OK && rc != DSM_RC_FINISHED) { dsmMsg(rc); dsmEndQuery(gHandle); return 1; }
    dsmEndQuery(gHandle);
    return 0;
}

static void cliFreeEnum(cliEnt *list)
{
    while (list) {
        cliEnt *n = list->next;
        free(list->fs); free(list->hl); free(list->ll); free(list);
        list = n;
    }
}

static void cliMarkLatest(cliEnt *list, int count)
{
    (void)count;
    for (cliEnt *o = list; o; o = o->next) {
        o->latest = 1;
        for (cliEnt *c = list; c; c = c->next) {
            if (c == o) continue;
            if (strcmp(c->hl, o->hl) || strcmp(c->ll, o->ll) || strcmp(c->fs, o->fs))
                continue;
            if (c->insKey > o->insKey ||
                (c->insKey == o->insKey &&
                 ((long long)c->hi > (long long)o->hi ||
                  ((long long)c->hi == (long long)o->hi && c->lo > o->lo)))) {
                o->latest = 0;
                break;
            }
        }
    }
}

/* unq: the TSM qualifier form may carry a leading '/' — strip it for the
 * local "hl/ll" read-out and path building. */
static const char *unq(const char *s)
{
    return (s && s[0] == '/') ? s + 1 : s;
}

/* --- ls ---------------------------------------------------------------------- */

static int cmdCliLs(int showMeta)
{
    cliEnt *list = NULL;
    int count = 0;
    if (cliEnumAll(&list, &count) != 0) {
        fprintf(stderr, "tsmapi: enumeration failed: %s\n", gRcMsg);
        return 1;
    }
    cliMarkLatest(list, count);

    int emitted = 0;
    for (cliEnt *e = list; e; e = e->next) {
        const char *hl = unq(e->hl), *ll = unq(e->ll);
        int isMeta = isMetaName(ll);
        if (isMeta && !showMeta) continue;
        char ehl[2048], ell[512], efs[2048];
        jsonEscW(ehl, sizeof ehl, hl);
        jsonEscW(ell, sizeof ell, ll);
        jsonEscW(efs, sizeof efs, e->fs);
        char date[32];
        snprintf(date, sizeof date, "%05u-%02u-%02u %02u:%02u:%02u",
                 e->ins.year, e->ins.month, e->ins.day, e->ins.hour, e->ins.minute, e->ins.second);
        char line[8192];
        int n = snprintf(line, sizeof line,
                         "{\"fs\":\"%s\",\"hl\":\"%s\",\"ll\":\"%s\",\"size\":%lld,"
                         "\"hi\":%u,\"lo\":%u,\"latest\":%s,\"ins\":\"%s\"}\n",
                         efs, ehl, ell, e->size, e->hi, e->lo,
                         e->latest ? "true" : "false", date);
        if (n > 0 && (size_t)n < sizeof line)
            fputs(line, stdout);
        else
            fprintf(stderr, "tsmapi: ls: line truncated (skipped %s/%s)\n", e->hl, e->ll);
        emitted++;
    }
    fprintf(stderr, "tsmapi: ls: %d of %d objects (meta shown: %s)\n",
            emitted, count, showMeta ? "yes" : "no");
    fflush(stdout);
    cliFreeEnum(list);
    return 0;
}

/* --- restore ------------------------------------------------------------------ */

/* cliReplayAttrs: apply one attribute of a capturedMeta payload to the
 * destination, per the selected mode. Returns 0 on success. */
static int cliReplayAttr(const char *destPath, const char *hl, const char *ll,
                         const char *attr, unsigned char *val, size_t vlen,
                         int mode, const char *sidecarDir,
                         const char *rawPayload, size_t rawLen)
{
    char path[8192];
    int n;
    if (mode == 0) {          /* xattr */
#if defined(__linux__)
        static const char XP[] = "user.";
        if (setxattr(destPath, XP, val, vlen, 0) != 0)
            return -1; /* strerror in caller */
        return 0;
#else
        fprintf(stderr, "tsmapi: -m xattr is only supported on Linux\n");
        return -1;
#endif
    }
    if (mode == 1) {          /* sidecar: DIR/<hl>/<ll>/meta/<attr> */
        char path[8192];
        if (hl && hl[0])
            n = snprintf(path, sizeof path, "%s/%s/%s/meta/%s", sidecarDir, hl, ll, attr);
        else
            n = snprintf(path, sizeof path, "%s/%s/meta/%s", sidecarDir, ll, attr);
        if (n <= 0 || (size_t)n >= sizeof path) {
            fprintf(stderr, "tsmapi: sidecar path too long: %s\n", attr);
            return -1;
        }
        if (makeDirsFor(path) != 0) return -1;
        if (writeAllFile(path, (const char *)val, vlen) != 0) return -1;
        return 0;
    }
    /* mode 2: raw payload file, independent of the attribute (called once) */
    (void)attr; (void)val; (void)vlen;
    n = snprintf(path, sizeof path, "%s.hsm-meta", destPath);
    if (n <= 0 || (size_t)n >= sizeof path) {
        fprintf(stderr, "tsmapi: raw meta path too long for %s\n", destPath);
        return -1;
    }
    if (writeAllFile(path, rawPayload, rawLen) != 0) return -1;
    return 0;
}

/* Walk the "attrs" object of a capturedMeta payload. For every entry call
 * cb(name, b64, cbArg). Returns 0 on success, -1 if the payload is not a
 * recognizable capturedMeta document. */
typedef int (*cliAttrCb)(const char *name, const char *b64, void *cbArg);

static int cliWalkAttrs(const char *json, size_t len, cliAttrCb cb, void *arg)
{
    const char *end = json + len;
    const char *ap;
    for (ap = json; ap < end - 7; ap++) {
        if (ap[0] == '"' && ap[1] == 'a' && ap[2] == 't' && ap[3] == 't' &&
            ap[4] == 'r' && ap[5] == 's' && ap[6] == '"' &&
            (ap[7] == ' ' || ap[7] == ':')) {
            break;
        }
    }
    if (ap >= end) return -1;
    /* skip to the opening '{' of the attrs object */
    const char *q = ap + 7;
    while (q < end && *q != '{') q++;
    if (q >= end) return -1;
    q++;
    int any = 0;
    while (q < end && *q != '}') {
        const char *c = q;
        while (c < end && (*c == ' ' || *c == '\t' || *c == '\n' || *c == '\r' || *c == ',')) c++;
        if (c >= end || *c != '"') return -1;
        const char *next;
        char *name = jdec(c, end, &next);
        if (!name) return -1;
        c = next;
        while (c < end && *c != ':') c++;
        if (c >= end) { free(name); return -1; }
        c++;
        while (c < end && (*c == ' ' || *c == '\t' || *c == '\n' || *c == '\r')) c++;
        if (c >= end || *c != '"') { free(name); return -1; }
        char *b64 = jdec(c, end, &next);
        if (!b64) { free(name); return -1; }
        c = next;
        any = 1;
        if (cb(name, b64, arg) != 0) { free(name); free(b64); return -1; }
        free(name);
        free(b64);
        q = c;
    }
    if (q >= end || *q != '}') return -1;
    return any ? 0 : 0;
}

/* fetch object (fs,hl,ll) — newest version — into a malloc'd buffer. */
static int cliFetchBuffer(const char *fs, const char *hl, const char *ll,
                          char **out, size_t *outLen)
{
    *out = NULL;
    *outLen = 0;
    char tmp[512];
    int ok = snprintf(tmp, sizeof tmp, "/tmp/.tsmapi-meta.%d.%u", getpid(), gHandle);
    if (ok <= 0 || (size_t)ok >= sizeof tmp) return -1;

    if (makeDirsFor(tmp)) { unlink(tmp); return -1; }
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { unlink(tmp); return -1; }
    unsigned long long n = 0;
    int r = fetchLatest(fs, hl, ll, fd, &n);
    close(fd);
    if (r != 0) { unlink(tmp); return r; }

    /* read back */
    int rd = open(tmp, O_RDONLY);
    unlink(tmp);
    if (rd < 0) return -1;
    size_t cap = (size_t)n + 1;
    if (cap > (size_t)64 * 1024 * 1024) { close(rd); return -1; }
    char *buf = (char *)malloc(cap ? cap : 1);
    if (!buf) { close(rd); return -1; }
    size_t got = 0;
    for (;;) {
        ssize_t t = read(rd, buf + got, (cap - got > (1u << 20)) ? (1u << 20) : (cap - got));
        if (t < 0) { if (errno == EINTR) continue; free(buf); close(rd); return -1; }
        if (t == 0) break;
        got += (size_t)t;
    }
    close(rd);
    buf[got] = 0;
    *out = buf;
    *outLen = got;
    return 0;
}

/* --- restore (CLI) ------------------------------------------------------------ */

typedef struct {
    char     *expr;
    regex_t   re;
} cliRe;

/* Per-attribute context handed to attrCbReplay via cliWalkAttrs. */
typedef struct {
    const char *destPath;
    const char *hl;
    const char *ll;
    int         mode;
    const char *sidecarDir;
    const char *raw;
    size_t      rawLen;
    int        *okCount;
} cliAttrCtx;

static int attrCbReplay(const char *name, const char *b64, void *arg)
{
    cliAttrCtx *r = arg;
    unsigned char *val;
    size_t vlen;
    if (b64dec(b64, &val, &vlen) != 0) {
        fprintf(stderr, "tsmapi: bad base64 for attribute %s\n", name);
        return -1;
    }
    int e = cliReplayAttr(r->destPath, r->hl, r->ll, name, val, vlen,
                          r->mode, r->sidecarDir, r->raw, r->rawLen);
    if (e) fprintf(stderr, "tsmapi: replay attr %s to %s: %s\n", name, r->destPath, strerror(errno));
    else (r->okCount)++;
    free(val);
    return e;
}

static int cmdCliRestore(const char *node, const char *clientdir, const char *dsmopt,
                         const char *options, const char *dest, const char *metaMode,
                         const char *sidecarDir, int nRe, cliRe *res)
{
    if (!dest || !*dest) { fprintf(stderr, "tsmapi: restore requires -d DEST\n"); return 2; }
    int mode = 0;          /* 0=xattr 1=sidecar 2=raw 3=none */
    if      (!strcmp(metaMode, "xattr"))   mode = 0;
    else if (!strcmp(metaMode, "sidecar")) mode = 1;
    else if (!strcmp(metaMode, "raw"))     mode = 2;
    else if (!strcmp(metaMode, "none"))    mode = 3;
    else { fprintf(stderr, "tsmapi: -m must be xattr|sidecar|raw|none\n"); return 2; }
    if (mode == 1 && (!sidecarDir || !*sidecarDir)) {
        fprintf(stderr, "tsmapi: -m sidecar requires --sidecar DIR\n");
        return 2;
    }
    for (int i = 0; i < nRe; i++)
        if (regcomp(&res[i].re, res[i].expr, REG_EXTENDED | REG_NOSUB) != 0) {
            fprintf(stderr, "tsmapi: ERE %s: invalid\n", res[i].expr);
            return 2;
        }

    if (cliDsmSignon(node, clientdir, dsmopt, options) != 0) {
        fprintf(stderr, "tsmapi: signon failed: %s\n", gRcMsg);
        return 1;
    }

    cliEnt *list = NULL;
    int count = 0;
    if (cliEnumAll(&list, &count) != 0) {
        fprintf(stderr, "tsmapi: enumeration failed: %s\n", gRcMsg);
        return 1;
    }

    int restored = 0, dataFail = 0, metaFail = 0, metaOk = 0;
    for (cliEnt *e = list; e; e = e->next) {
        const char *hl = unq(e->hl), *ll = unq(e->ll);
        if (isMetaName(ll)) continue;     /* companions are replayed, not restored as data */
        /* match? */
        char *path;
        int matched = 0, ok = (hl && hl[0]) ? asprintf(&path, "%s/%s", hl, ll) : asprintf(&path, "%s", ll);
        if (ok < 0) continue;
        for (int i = 0; i < nRe; i++)
            if (regexec(&res[i].re, path, 0, NULL, 0) == 0) { matched = 1; break; }
        free(path);
        if (!matched) continue;

        char destPath[8192];
        int dl = (hl && hl[0])
            ? snprintf(destPath, sizeof destPath, "%s/%s/%s", dest, hl, ll)
            : snprintf(destPath, sizeof destPath, "%s/%s", dest, ll);
        if (dl <= 0 || (size_t)dl >= sizeof destPath) {
            fprintf(stderr, "tsmapi: destination path too long for %s/%s\n", hl, ll);
            dataFail++;
            continue;
        }

        /* 1. data (skip if destination already has a regular file) */
        struct stat st;
        if (stat(destPath, &st) == 0 && S_ISREG(st.st_mode)) {
            fprintf(stderr, "tsmapi: data already present, skipped: %s\n", destPath);
            restored++;
            continue;
        }
        if (makeDirsFor(destPath) != 0) {
            fprintf(stderr, "tsmapi: mkdir for %s: %s\n", destPath, strerror(errno));
            dataFail++;
            continue;
        }
        int fd = open(destPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            fprintf(stderr, "tsmapi: open %s: %s\n", destPath, strerror(errno));
            dataFail++;
            continue;
        }
        unsigned long long bytes = 0;
        int r = fetchLatest(e->fs, e->hl, e->ll, fd, &bytes);
        close(fd);
        if (r != 0) {
            fprintf(stderr, "tsmapi: data fetch %s/%s failed: rc=%d %s\n", e->hl, e->ll, r, gRcMsg);
            dataFail++;
            continue;
        }
        restored++;
        fprintf(stderr, "tsmapi: restored %s/%s -> %s (%llu bytes)\n", e->hl, e->ll, destPath, bytes);

        /* 2. companion metadata, if any exists */
        char metaLl[256];
        metaName(e->hl, e->ll, metaLl);
        int haveMeta = 0;
        for (cliEnt *c = list; c; c = c->next)
            if (strcmp(c->hl, e->hl) == 0 && strcmp(c->ll, metaLl) == 0) { haveMeta = 1; break; }
        if (!haveMeta || mode == 3) continue;

        char *payload = NULL;
        size_t plen = 0;
        if (cliFetchBuffer(e->fs, e->hl, metaLl, &payload, &plen) != 0) {
            fprintf(stderr, "tsmapi: meta fetch %s: %s\n", metaLl, gRcMsg);
            free(payload);
            metaFail++;
            continue;
        }
        if (mode == 2) {
            int e2 = cliReplayAttr(destPath, hl, ll, NULL, NULL, 0, mode, sidecarDir, payload, plen);
            if (e2) { fprintf(stderr, "tsmapi: raw meta for %s: %s\n", destPath, strerror(errno)); metaFail++; }
            else metaOk++;
        } else {
            cliAttrCtx ctx = { destPath, hl, ll, mode, sidecarDir, payload, plen, &metaOk };
            if (cliWalkAttrs(payload, plen, attrCbReplay, &ctx) != 0) {
                fprintf(stderr, "tsmapi: meta payload of %s/%s not a capturedMeta document\n", e->hl, e->ll);
                metaFail++;
            }
        }
        free(payload);
    }

    for (int i = 0; i < nRe; i++) regfree(&res[i].re);
    cliFreeEnum(list);

    fprintf(stderr, "tsmapi: restore summary: restored=%d dataFailed=%d metaApplied=%d metaFailed=%d (meta-%s)\n",
            restored, dataFail, metaOk, metaFail, metaMode);
    return dataFail ? 1 : 0;
}

/* =================================================================== main */

static int tapiNdjsonMain(void)
{
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

static void usage(int err)
{
    FILE *o = err ? stderr : stdout;
    fprintf(o,
"tsmapi — NDJSON/DaPA helper and operator CLI for IBM Storage Protect 8.1.\n\n"
"NDJSON protocol (stdin/stdout, used by vgwtaped):\n"
"  ping | version | signon | send | get | delete | query | quit\n\n"
"Operator CLI modes (stdout = data, stderr = progress):\n"
"  tsmapi ls      -n NODE [-c CLIENTDIR] [-o DSMOPT] [-M]\n"
"  tsmapi restore -n NODE [-c CLIENTDIR] [-o DSMOPT] -d DEST\n"
"                 [-m xattr|sidecar|raw|none] [--sidecar DIR] <ERE>...\n"
"  tsmapi meta HL LL        (debug: print the companion object name)\n"
"Common:\n"
"  -n NODE        TSM client node (required)\n"
"  -c CLIENTDIR   client config dir (default /opt/tivoli/tsm/client/ba/bin)\n"
"  -o DSMOPT      extra dsm.opt path / inline options\n"
"  -M             ls: include metadata companion objects\n"
"  -d DEST        restore: destination root for restored files\n"
"  -m MODE        restore: metadata replay mode (default xattr)\n"
"  --sidecar DIR  restore: sidecar dir (required for -m sidecar)\n"
);
}

int main(int argc, char **argv)
{
    gArgv0 = strdup(argv[0]);
    if (!gArgv0) return 70;

    if (argc < 2) {
        /* No arguments: the Go driver's NDJSON protocol over stdin/stdout. */
        return tapiNdjsonMain();
    }
    if (!strcmp(argv[1], "meta")) {
        /* meta HL LL -> deterministic companion name for (hl, ll).
         * Debug/parity helper: lets shell scripts verify the name the
         * Go driver computes (posixhsm MetaName). */
        const char *hl = (argc > 2 && argv[2][0] != '-') ? argv[2] : "";
        const char *ll = (argc > 3 && argv[3][0] != '-') ? argv[3] : "";
        char name[256];
        metaName(hl, ll, name);
        printf("%s\n", name);
        return 0;
    }
    if (!strcmp(argv[1], "ls")) {
        const char *node = NULL, *clientdir = "/opt/tivoli/tsm/client/ba/bin", *dsmopt = NULL;
        int showMeta = 0;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "-n") && i + 1 < argc)              node = argv[++i];
            else if (!strcmp(argv[i], "-c") && i + 1 < argc)        clientdir = argv[++i];
            else if (!strcmp(argv[i], "-o") && i + 1 < argc)        dsmopt = argv[++i];
            else if (!strcmp(argv[i], "-M"))                        showMeta = 1;
            else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(0); return 0; }
            else { usage(1); return 2; }
        }
        if (!node || !*node) { fprintf(stderr, "tsmapi: ls requires -n NODE\n"); return 2; }
        gProtoFd = 2;   /* keep stdout clean for JSON */
        if (cliDsmSignon(node, clientdir, dsmopt, NULL) != 0) {
            fprintf(stderr, "tsmapi: signon failed: %s\n", gRcMsg);
            return 1;
        }
        int rc = cmdCliLs(showMeta);
        if (gHandle) dsmTerminate(gHandle);
        if (gSetUpDone) dsmCleanUp(DSM_SINGLETHREAD);
        return rc;
    }
    if (!strcmp(argv[1], "restore")) {
        const char *node = NULL, *clientdir = "/opt/tivoli/tsm/client/ba/bin", *dsmopt = NULL;
        const char *dest = NULL, *metaMode = "xattr", *sidecarDir = NULL;
        cliRe res[32];
        int nRe = 0, i = 2;
        for (; i < argc; i++) {
            if (!strcmp(argv[i], "-n") && i + 1 < argc)              node = argv[++i];
            else if (!strcmp(argv[i], "-c") && i + 1 < argc)        clientdir = argv[++i];
            else if (!strcmp(argv[i], "-o") && i + 1 < argc)        dsmopt = argv[++i];
            else if (!strcmp(argv[i], "-d") && i + 1 < argc)        dest = argv[++i];
            else if (!strcmp(argv[i], "-m") && i + 1 < argc)        metaMode = argv[++i];
            else if (!strcmp(argv[i], "--sidecar") && i + 1 < argc) sidecarDir = argv[++i];
            else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(0); return 0; }
            else if (argv[i][0] != '-' && i > 1) {
                if (nRe >= (int)(sizeof res / sizeof res[0])) { fprintf(stderr, "tsmapi: too many patterns\n"); return 2; }
                res[nRe].expr = argv[i];
                nRe++;
            }
            else { usage(1); return 2; }
        }
        if (!node || !*node) { fprintf(stderr, "tsmapi: restore requires -n NODE\n"); return 2; }
        if (nRe == 0)        { fprintf(stderr, "tsmapi: restore requires at least one ERE pattern\n"); return 2; }
        gProtoFd = 2;
        int rc = cmdCliRestore(node, clientdir, dsmopt, NULL, dest, metaMode, sidecarDir, nRe, res);
        if (gHandle) dsmTerminate(gHandle);
        if (gSetUpDone) dsmCleanUp(DSM_SINGLETHREAD);
        return rc;
    }
    if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "help")) {
        usage(0);
        return 0;
    }
    /* no recognized CLI verb => NDJSON protocol */
    return tapiNdjsonMain();
}
