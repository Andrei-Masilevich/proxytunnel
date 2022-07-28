#include "digestauth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void message( char *s, ... );

int digest_challenge = 0;

void build_digest()
{
    // TODO
}

int parse_digest(unsigned char *buf)
{
    // TODO

    message("parse_digest: Sorry, Digest HTTP Authentication is not supported at this time\n");

    return -1;
}

void build_digest_response()
{
    // TODO
}