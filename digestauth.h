
typedef struct digest_auth_ctx {
  char *http_method;
  char *http_uri;

  char *realm;
  char *nonce;
  char *qop;
  int stale;
  char *opaque;

  char *cnonce;
  char *secret;
  char *identity;
  char *response;
} DIGEST_AUTH_CTX;

DIGEST_AUTH_CTX *create_digest_auth(const char *http_uri,
                                    unsigned char *server_digest);
char *build_digest_response(DIGEST_AUTH_CTX *, const char *username,
                            const char *password);
void cleanup_digest_auth(DIGEST_AUTH_CTX **);
