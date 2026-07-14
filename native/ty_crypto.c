// Tachyon crypto shim: SHA-256, HMAC-SHA256, base64, constant-time compare,
// and CSPRNG bytes. Self-contained (no OpenSSL dependency).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- SHA-256 ---- */
typedef struct { uint32_t s[8]; uint64_t n; uint8_t buf[64]; size_t len; } sha256;

static uint32_t rr(uint32_t x, int c) { return (x >> c) | (x << (32 - c)); }

static void sha256_block(sha256* h, const uint8_t* p) {
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
    uint32_t w[64], a, b, c, d, e, f, g, hh;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rr(w[i-15],7) ^ rr(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = rr(w[i-2],17) ^ rr(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h->s[0]; b=h->s[1]; c=h->s[2]; d=h->s[3];
    e=h->s[4]; f=h->s[5]; g=h->s[6]; hh=h->s[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rr(e,6) ^ rr(e,11) ^ rr(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        uint32_t S0 = rr(a,2) ^ rr(a,13) ^ rr(a,22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h->s[0]+=a; h->s[1]+=b; h->s[2]+=c; h->s[3]+=d;
    h->s[4]+=e; h->s[5]+=f; h->s[6]+=g; h->s[7]+=hh;
}

static void sha256_init(sha256* h) {
    h->s[0]=0x6a09e667; h->s[1]=0xbb67ae85; h->s[2]=0x3c6ef372; h->s[3]=0xa54ff53a;
    h->s[4]=0x510e527f; h->s[5]=0x9b05688c; h->s[6]=0x1f83d9ab; h->s[7]=0x5be0cd19;
    h->n = 0; h->len = 0;
}
static void sha256_update(sha256* h, const uint8_t* p, size_t n) {
    h->n += n;
    while (n) {
        size_t take = 64 - h->len;
        if (take > n) take = n;
        memcpy(h->buf + h->len, p, take);
        h->len += take; p += take; n -= take;
        if (h->len == 64) { sha256_block(h, h->buf); h->len = 0; }
    }
}
static void sha256_final(sha256* h, uint8_t out[32]) {
    uint64_t bits = h->n * 8;
    uint8_t pad = 0x80;
    sha256_update(h, &pad, 1);
    uint8_t z = 0;
    while (h->len != 56) sha256_update(h, &z, 1);
    uint8_t len[8];
    for (int i = 0; i < 8; i++) len[7-i] = (uint8_t)(bits >> (i * 8));
    sha256_update(h, len, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(h->s[i] >> 24);
        out[i*4+1] = (uint8_t)(h->s[i] >> 16);
        out[i*4+2] = (uint8_t)(h->s[i] >> 8);
        out[i*4+3] = (uint8_t)(h->s[i]);
    }
}

static char ty_hexbuf[128];
static const char* hexify(const uint8_t* p, size_t n) {
    static const char* H = "0123456789abcdef";
    for (size_t i = 0; i < n && i * 2 + 1 < sizeof ty_hexbuf; i++) {
        ty_hexbuf[i*2]   = H[p[i] >> 4];
        ty_hexbuf[i*2+1] = H[p[i] & 15];
    }
    ty_hexbuf[n * 2] = 0;
    return ty_hexbuf;
}

const char* ty_sha256_hex(const char* s) {
    sha256 h;
    sha256_init(&h);
    sha256_update(&h, (const uint8_t*)s, strlen(s));
    uint8_t out[32];
    sha256_final(&h, out);
    return hexify(out, 32);
}

const char* ty_hmac_sha256_hex(const char* key, const char* msg) {
    uint8_t k[64] = {0};
    size_t kn = strlen(key);
    if (kn > 64) {
        sha256 h; sha256_init(&h);
        sha256_update(&h, (const uint8_t*)key, kn);
        uint8_t d[32]; sha256_final(&h, d);
        memcpy(k, d, 32);
    } else {
        memcpy(k, key, kn);
    }
    uint8_t ip[64], op[64];
    for (int i = 0; i < 64; i++) { ip[i] = k[i] ^ 0x36; op[i] = k[i] ^ 0x5c; }
    sha256 h1; sha256_init(&h1);
    sha256_update(&h1, ip, 64);
    sha256_update(&h1, (const uint8_t*)msg, strlen(msg));
    uint8_t inner[32]; sha256_final(&h1, inner);
    sha256 h2; sha256_init(&h2);
    sha256_update(&h2, op, 64);
    sha256_update(&h2, inner, 32);
    uint8_t out[32]; sha256_final(&h2, out);
    return hexify(out, 32);
}

/* ---- base64 ---- */
static char* ty_b64_buf = 0;
static const char* B64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const char* ty_b64_encode(const char* s) {
    free(ty_b64_buf);
    size_t n = strlen(s);
    size_t out = 4 * ((n + 2) / 3);
    ty_b64_buf = (char*)malloc(out + 1);
    size_t j = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)(unsigned char)s[i] << 16;
        if (i + 1 < n) v |= (uint32_t)(unsigned char)s[i+1] << 8;
        if (i + 2 < n) v |= (uint32_t)(unsigned char)s[i+2];
        ty_b64_buf[j++] = B64[(v >> 18) & 63];
        ty_b64_buf[j++] = B64[(v >> 12) & 63];
        ty_b64_buf[j++] = i + 1 < n ? B64[(v >> 6) & 63] : '=';
        ty_b64_buf[j++] = i + 2 < n ? B64[v & 63] : '=';
    }
    ty_b64_buf[j] = 0;
    return ty_b64_buf;
}

const char* ty_b64_decode(const char* s) {
    free(ty_b64_buf);
    size_t n = strlen(s);
    ty_b64_buf = (char*)malloc(n + 1);
    int8_t rev[256];
    memset(rev, -1, sizeof rev);
    for (int i = 0; i < 64; i++) rev[(unsigned char)B64[i]] = (int8_t)i;
    size_t j = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        int8_t v = rev[(unsigned char)s[i]];
        if (v < 0) continue;                       /* skip '=' and whitespace */
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            ty_b64_buf[j++] = (char)((acc >> bits) & 0xFF);
        }
    }
    ty_b64_buf[j] = 0;
    return ty_b64_buf;
}

/* ---- misc ---- */
int ty_ct_equal(const char* a, const char* b) {    /* constant-time compare */
    size_t na = strlen(a), nb = strlen(b);
    unsigned diff = (unsigned)(na ^ nb);
    size_t n = na < nb ? na : nb;
    for (size_t i = 0; i < n; i++)
        diff |= (unsigned)((unsigned char)a[i] ^ (unsigned char)b[i]);
    return diff == 0 ? 1 : 0;
}

const char* ty_random_hex(long long nbytes) {      /* CSPRNG bytes, hex-encoded */
    if (nbytes < 1) nbytes = 1;
    if (nbytes > 32) nbytes = 32;
    uint8_t buf[32];
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t rd = fread(buf, 1, (size_t)nbytes, f);
        fclose(f);
        if (rd != (size_t)nbytes) memset(buf, 0, (size_t)nbytes);
    } else {
        memset(buf, 0, (size_t)nbytes);
    }
    return hexify(buf, (size_t)nbytes);
}

/* =====================================================================
   Password hashing (PBKDF2-HMAC-SHA256) and JWT (HS256).

   These take binary data (raw salt, raw MACs), so unlike the text helpers
   above they never pass raw bytes across the Tachyon boundary — everything
   that crosses is text (the password, or a base64/encoded string). The
   returned C strings live in _Thread_local buffers so concurrent request
   workers do not collide.
   ===================================================================== */

/* HMAC-SHA256 over arbitrary bytes -> raw 32-byte MAC */
static void hmac_raw(const uint8_t* key, size_t kn,
                     const uint8_t* msg, size_t mn, uint8_t out[32]) {
    uint8_t k[64] = {0};
    if (kn > 64) {
        sha256 h; sha256_init(&h);
        sha256_update(&h, key, kn);
        uint8_t d[32]; sha256_final(&h, d);
        memcpy(k, d, 32);
    } else {
        memcpy(k, key, kn);
    }
    uint8_t ip[64], op[64];
    for (int i = 0; i < 64; i++) { ip[i] = k[i] ^ 0x36; op[i] = k[i] ^ 0x5c; }
    sha256 h1; sha256_init(&h1);
    sha256_update(&h1, ip, 64);
    sha256_update(&h1, msg, mn);
    uint8_t inner[32]; sha256_final(&h1, inner);
    sha256 h2; sha256_init(&h2);
    sha256_update(&h2, op, 64);
    sha256_update(&h2, inner, 32);
    sha256_final(&h2, out);
}

/* PBKDF2-HMAC-SHA256 (RFC 2898) -> dk (dklen bytes) */
static void pbkdf2_sha256(const uint8_t* pw, size_t pwn,
                          const uint8_t* salt, size_t sn,
                          uint32_t iters, uint8_t* dk, size_t dklen) {
    uint32_t blocks = (uint32_t)((dklen + 31) / 32);
    uint8_t* saltblock = (uint8_t*)malloc(sn + 4);
    memcpy(saltblock, salt, sn);
    size_t done = 0;
    for (uint32_t b = 1; b <= blocks; b++) {
        saltblock[sn]   = (uint8_t)(b >> 24);
        saltblock[sn+1] = (uint8_t)(b >> 16);
        saltblock[sn+2] = (uint8_t)(b >> 8);
        saltblock[sn+3] = (uint8_t)b;
        uint8_t u[32], t[32];
        hmac_raw(pw, pwn, saltblock, sn + 4, u);
        memcpy(t, u, 32);
        for (uint32_t i = 1; i < iters; i++) {
            hmac_raw(pw, pwn, u, 32, u);
            for (int j = 0; j < 32; j++) t[j] ^= u[j];
        }
        size_t take = dklen - done < 32 ? dklen - done : 32;
        memcpy(dk + done, t, take);
        done += take;
    }
    free(saltblock);
}

/* base64 of raw bytes into caller buffer (standard alphabet, padded) */
static size_t b64_raw(const uint8_t* in, size_t n, char* out) {
    size_t j = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n) v |= (uint32_t)in[i+1] << 8;
        if (i + 2 < n) v |= (uint32_t)in[i+2];
        out[j++] = B64[(v >> 18) & 63];
        out[j++] = B64[(v >> 12) & 63];
        out[j++] = i + 1 < n ? B64[(v >> 6) & 63] : '=';
        out[j++] = i + 2 < n ? B64[v & 63] : '=';
    }
    out[j] = 0;
    return j;
}

/* CSPRNG raw bytes; returns 1 on success */
static int random_raw(uint8_t* buf, size_t n) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t rd = fread(buf, 1, n, f);
    fclose(f);
    return rd == n;
}

#define TY_PW_ITERS 210000

/* passwordHash(password) -> "pbkdf2_sha256$<iters>$<salt_b64>$<hash_b64>" */
const char* ty_pw_hash(const char* password) {
    static _Thread_local char buf[160];
    uint8_t salt[16], dk[32];
    if (!random_raw(salt, sizeof salt)) { buf[0] = 0; return buf; }
    pbkdf2_sha256((const uint8_t*)password, strlen(password),
                  salt, sizeof salt, TY_PW_ITERS, dk, sizeof dk);
    char sb[32], hb[48];
    b64_raw(salt, sizeof salt, sb);
    b64_raw(dk, sizeof dk, hb);
    snprintf(buf, sizeof buf, "pbkdf2_sha256$%d$%s$%s", TY_PW_ITERS, sb, hb);
    return buf;
}

/* decode standard base64 into out (caller-sized); returns byte count */
static size_t b64_decode_raw(const char* s, size_t n, uint8_t* out) {
    int8_t rev[256];
    memset(rev, -1, sizeof rev);
    for (int i = 0; i < 64; i++) rev[(unsigned char)B64[i]] = (int8_t)i;
    size_t j = 0; uint32_t acc = 0; int bits = 0;
    for (size_t i = 0; i < n; i++) {
        int8_t v = rev[(unsigned char)s[i]];
        if (v < 0) continue;
        acc = (acc << 6) | (uint32_t)v; bits += 6;
        if (bits >= 8) { bits -= 8; out[j++] = (uint8_t)((acc >> bits) & 0xFF); }
    }
    return j;
}

/* passwordVerify(password, encoded) -> 1 if it matches, 0 otherwise */
int ty_pw_verify(const char* password, const char* encoded) {
    if (strncmp(encoded, "pbkdf2_sha256$", 14) != 0) return 0;
    const char* p = encoded + 14;
    uint32_t iters = (uint32_t)strtoul(p, 0, 10);
    if (iters < 1 || iters > 10000000) return 0;
    const char* s1 = strchr(p, '$');       if (!s1) return 0; s1++;
    const char* s2 = strchr(s1, '$');      if (!s2) return 0;
    size_t saltlen = (size_t)(s2 - s1);
    const char* hashb = s2 + 1;
    uint8_t salt[64], want[64], dk[64];
    size_t sn = b64_decode_raw(s1, saltlen, salt);
    size_t wn = b64_decode_raw(hashb, strlen(hashb), want);
    if (sn == 0 || wn == 0 || wn > sizeof dk) return 0;
    pbkdf2_sha256((const uint8_t*)password, strlen(password),
                  salt, sn, iters, dk, wn);
    unsigned diff = 0;                      /* constant-time over the digest */
    for (size_t i = 0; i < wn; i++) diff |= (unsigned)(dk[i] ^ want[i]);
    return diff == 0 ? 1 : 0;
}

/* ---- JWT HS256 ---- */
static size_t b64url_raw(const uint8_t* in, size_t n, char* out) {
    size_t j = b64_raw(in, n, out);
    size_t k = 0;
    for (size_t i = 0; i < j; i++) {        /* url-safe, strip padding */
        if (out[i] == '=') break;
        out[k++] = out[i] == '+' ? '-' : (out[i] == '/' ? '_' : out[i]);
    }
    out[k] = 0;
    return k;
}
static size_t b64url_decode(const char* s, size_t n, uint8_t* out) {
    char tmp[512];
    size_t k = 0;
    for (size_t i = 0; i < n && k < sizeof tmp - 4; i++)
        tmp[k++] = s[i] == '-' ? '+' : (s[i] == '_' ? '/' : s[i]);
    while (k % 4) tmp[k++] = '=';
    return b64_decode_raw(tmp, k, out);
}

/* jwtSign(payloadJson, secret) -> "<h>.<p>.<sig>" (HS256) */
const char* ty_jwt_sign(const char* payload, const char* secret) {
    static _Thread_local char buf[2048];
    /* header {"alg":"HS256","typ":"JWT"} base64url'd is constant */
    static const char* H = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    char pb[1024];
    size_t pn = b64url_raw((const uint8_t*)payload, strlen(payload), pb);
    if (pn == 0 && payload[0]) { buf[0] = 0; return buf; }
    char signing[1200];
    int sl = snprintf(signing, sizeof signing, "%s.%s", H, pb);
    uint8_t mac[32];
    hmac_raw((const uint8_t*)secret, strlen(secret),
             (const uint8_t*)signing, (size_t)sl, mac);
    char sig[48];
    b64url_raw(mac, 32, sig);
    snprintf(buf, sizeof buf, "%s.%s", signing, sig);
    return buf;
}

/* jwtVerify(token, secret) -> the payload JSON if the signature is valid and
   (if present) the exp claim is in the future; "" otherwise */
const char* ty_jwt_verify(const char* token, const char* secret) {
    static _Thread_local char buf[1024];
    buf[0] = 0;
    const char* dot1 = strchr(token, '.');       if (!dot1) return buf;
    const char* dot2 = strchr(dot1 + 1, '.');    if (!dot2) return buf;
    size_t signlen = (size_t)(dot2 - token);
    uint8_t mac[32];
    hmac_raw((const uint8_t*)secret, strlen(secret),
             (const uint8_t*)token, signlen, mac);
    char want[48];
    b64url_raw(mac, 32, want);
    const char* got = dot2 + 1;
    /* constant-time compare of the signature */
    size_t wn = strlen(want), gn = strlen(got);
    unsigned diff = (unsigned)(wn ^ gn);
    size_t m = wn < gn ? wn : gn;
    for (size_t i = 0; i < m; i++) diff |= (unsigned)(want[i] ^ got[i]);
    if (diff != 0) return buf;
    /* decode payload */
    uint8_t pl[1024];
    size_t pn = b64url_decode(dot1 + 1, (size_t)(dot2 - dot1 - 1), pl);
    if (pn >= sizeof buf) pn = sizeof buf - 1;
    memcpy(buf, pl, pn);
    buf[pn] = 0;
    /* honour exp if present: "exp":<seconds> */
    const char* e = strstr(buf, "\"exp\"");
    if (e) {
        e = strchr(e, ':');
        if (e) {
            long long exp = strtoll(e + 1, 0, 10);
            long long now = (long long)time(0);
            if (exp > 0 && now >= exp) { buf[0] = 0; return buf; }   /* expired */
        }
    }
    return buf;
}
