#include "digestauth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/time.h>
#include <openssl/md5.h>

#include "proxytunnel.h"

void message( char *s, ... );

static const size_t DIGEST_SZ_LIM = 1024;

// Implemented by recommendations from:
// https://datatracker.ietf.org/doc/html/rfc7616

static int scan_for_tokens(DIGEST_AUTH_CTX *pctx, const char *pchunk, char* buff)
{
    if (!pctx->realm)
    {
        if (1 == sscanf(pchunk, "realm=\"%[^\"]", buff))
        {
            pctx->realm = strdup(buff);

            return 1;
        }
    }

    if (!pctx->qop)
    {
        if (1 == sscanf(pchunk, "qop=\"%[^\"]", buff))
        {
            pctx->qop = strdup(buff);

            return 1;
        }
    }

    if (!pctx->nonce)
    {
        if (1 == sscanf(pchunk, "nonce=\"%[^\"]", buff))
        {
            pctx->nonce = strdup(buff);

            return 1;
        }
    }

    if (!pctx->opaque)
    {
        if (1 == sscanf(pchunk, "opaque=\"%[^\"]", buff))
        {
            pctx->opaque = strdup(buff);

            return 1;
        }
    }

    if (-1 == pctx->stale)
    {
        if (1 == sscanf(pchunk, "stale=%s", buff))
        {
            if (!strncmp(buff, "true", 4))
                pctx->stale = 1;
            else if (!strncmp(buff, "false", 5))
                pctx->stale = 0;

            // Support only handshake state
            if (pctx->stale != 0)
            {
                message("parse_digest: Invalid digest behavior ('stale' has invalid value for handshake) from server\n");

                return 0;
            }

            return 1;
        }
    }

    if (1 == sscanf(pchunk, "algorithm=%s", buff))
    {
        const char *algorithm = buff;

        // Support only default MD5 hash
        if (strncmp(algorithm, "MD5", 3))
        {
            message("parse_digest: Unsupported algorithm '%s'from server\n", algorithm);

            return 0;
        }
    }

    return 1;
}

DIGEST_AUTH_CTX *create_digest_auth(const char* http_uri, unsigned char *server_digest)
{
    // Sanitize input
    if (!http_uri || !strnlen(http_uri, DIGEST_SZ_LIM))
    {
        message("parse_digest: Invalid URI string\n");

        return NULL;
    }

    char *pserver_digest = (char *)server_digest;
    size_t input_sz =strnlen(pserver_digest, DIGEST_SZ_LIM);
    if (input_sz > DIGEST_SZ_LIM - 1)
    {
        message("parse_digest: Invalid digest string (too large) from server\n");

        return NULL;
    }

    char *pvar_buf = alloca(DIGEST_SZ_LIM);

    // Construct authentication context
    DIGEST_AUTH_CTX *pctx = malloc(sizeof(DIGEST_AUTH_CTX));
    pctx->http_method = strdup("CONNECT");
    pctx->http_uri = strdup(http_uri);
    pctx->realm = NULL;
    pctx->nonce = NULL;
    pctx->qop = NULL;
    pctx->stale = -1;
    pctx->opaque = NULL;
    pctx->cnonce = NULL;
    pctx->secret = NULL;
    pctx->identity = NULL;
    pctx->response = NULL;

    // Extract protocol tokens
    const char*const VARS_DELIMS=" ,";
    char *pchunk = strtok(pserver_digest, VARS_DELIMS);
    while (pchunk != NULL)
    {
        if (1 != scan_for_tokens(pctx, pchunk, pvar_buf))
        {
            cleanup_digest_auth(&pctx);
            return NULL;
        }

        pchunk = strtok (NULL, VARS_DELIMS);
    }

    // Check extraction result

    if (!pctx->realm)
    {
        message("parse_digest: Invalid digest string (failed 'realm') from server\n");
        cleanup_digest_auth(&pctx);
        return NULL;
    }

    if (!pctx->qop)
    {
        message("parse_digest: Invalid digest string (failed 'qop') from server\n");
        cleanup_digest_auth(&pctx);
        return NULL;
    }

    if (!pctx->nonce)
    {
        message("parse_digest: Invalid digest string (failed 'nonce') from server\n");
        cleanup_digest_auth(&pctx);
        return NULL;
    }

    if (-1 == pctx->stale)
    {
        message("parse_digest: Invalid digest string (failed 'stale') from server\n");
        cleanup_digest_auth(&pctx);
        return NULL;
    }

    return pctx;
}

static size_t to_hex(const unsigned char* p_input, const size_t input_sz, char* buff, const size_t buff_sz)
{
    if (!p_input || !input_sz || !buff || !buff_sz)
        return -1;

    const char hex_abc[] = "0123456789abcdef";

    char* out_pos = buff;
    char* out_end = out_pos + buff_sz;

    size_t i = 0;
    for (; i < input_sz && out_pos != out_end && ++out_pos != out_end; ++i, ++out_pos)
    {
        *out_pos-- = hex_abc[(p_input[i] & 0x0f)];
        *out_pos++ = hex_abc[(p_input[i] >> 4)];
    }

    if (out_pos != out_end)
        *out_pos = 0;

    return i;
}

static char* digest_hash(size_t strings, ... )
{
    if (!strings)
        return NULL;

    va_list pargs;
    va_start( pargs, strings );

    MD5_CTX ctx;

    unsigned char digest[16];

    MD5_Init(&ctx);

    for(size_t ci = 0; ci < strings; ++ci)
    {
        char* pstr = va_arg(pargs, char*);
        if (pstr)
        {
            size_t ln = strnlen(pstr, DIGEST_SZ_LIM);
            if (ln > 0)
            {
                MD5_Update(&ctx, pstr, ln);
            }
        }
    }
    MD5_Final(digest, &ctx);

    va_end( pargs );

    size_t hex_sz = sizeof(digest) * 2;
    char *presult = alloca(hex_sz + 1);

    if (sizeof(digest) != to_hex(digest, sizeof(digest), presult, hex_sz))
        return NULL;

    presult[hex_sz] = 0;

    return strdup(presult);
}

char *create_cnonce()
{
    char acc[512], host[256];
    struct timeval tv;
    static int count = 0;

    gethostname(host, 256); /* ignore failures */
    host[255] = 0;
    gettimeofday(&tv, NULL); /* ignore failures */
    sprintf(acc, "%s,%ld,%ld,%ld,%d", host, (long)tv.tv_sec, (long)tv.tv_usec,
            (long)getpid(), count++);
    return digest_hash(1, acc);
}

char* build_digest_response(DIGEST_AUTH_CTX *pctx, const char* username, const char* password)
{
    if (!pctx || !username || !password)
    {
        message("parse_digest: Invalid data to build digest respoinse\n");

        return NULL;
    }

    char *presponse_buf = alloca(DIGEST_SZ_LIM);
    memset(presponse_buf, 0, DIGEST_SZ_LIM);

    const char *const DELIM = ":";
    const char *qop = "auth";
    const char *nc = "00000001";
    pctx->cnonce = create_cnonce();
    pctx->secret = digest_hash(5, username, DELIM, pctx->realm, DELIM, password);
    pctx->identity = digest_hash(3, pctx->http_method, DELIM, pctx->http_uri);
    pctx->response = digest_hash(11, pctx->secret, DELIM, pctx->nonce, DELIM, nc, DELIM, pctx->cnonce, DELIM, qop, DELIM, pctx->identity);

    snprintf(presponse_buf, DIGEST_SZ_LIM,
             "username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", cnonce=\"%s\", nc=%s, qop=%s, response=\"%s\"",
             username, pctx->realm, pctx->nonce, pctx->http_uri, pctx->cnonce, nc, qop, pctx->response);

    if (pctx->opaque)
    {
        strzcat(presponse_buf, ", opaque=\"%s\"", pctx->opaque);
    }

    return strdup(presponse_buf);
}

void cleanup_digest_auth(DIGEST_AUTH_CTX **ppctx)
{
    if (ppctx)
    {
        DIGEST_AUTH_CTX *pctx = *ppctx;
        if (pctx->http_method)
        {
            free(pctx->http_method);
        }
        if (pctx->http_uri)
        {
            free(pctx->http_uri);
        }
        if (pctx->realm)
        {
            free(pctx->realm);
        }
        if (pctx->qop)
        {
            free(pctx->qop);
        }
        if (pctx->nonce)
        {
            free(pctx->nonce);
        }
        if (pctx->opaque)
        {
            free(pctx->opaque);
        }
        if (pctx->cnonce)
        {
            free(pctx->cnonce);
        }
        if (pctx->secret)
        {
            free(pctx->secret);
        }
        if (pctx->identity)
        {
            free(pctx->identity);
        }
        if (pctx->response)
        {
            free(pctx->response);
        }
        memset(pctx, 0, sizeof(DIGEST_AUTH_CTX));
        free(pctx);
        *ppctx = NULL;
    }
}
