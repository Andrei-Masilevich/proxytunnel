/* Proxytunnel - (C) 2001-2020 Jos Visser / Mark Janssen    */
/* Contact:                  josv@osp.nl / maniac@maniac.nl */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* http.c */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "proxytunnel.h"
#include "io.h"
#include "basicauth.h"
#include "ntlm.h"
#include "digestauth.h"

static DIGEST_AUTH_CTX *pdigest_challenge_ctx = NULL;
size_t global_proxy_number = 0;

const char* get_uri()
{
    size_t proxy_number = global_proxy_number;

    if (args_info.host_arg)
        return args_info.host_arg;

    if (args_info.remproxy_given )
    {
        if (1 >= proxy_number)
        {
            return args_info.remproxy_arg;
        }
    }

    return args_info.dest_arg;
}

/*
 * Analyze the proxy's HTTP response. This must be a HTTP/1.? 200 OK type
 * header
 */
void analyze_HTTP(PTSTREAM *pts) {
    char *p = strtok( buf, " ");

    /* Strip html error pages for faulty proxies (Stephane Engel <steph[at]macchiati.org>) */
    while (strncmp( p, "HTTP/", 5) != 0 ) {
        if ( readline(pts) ) {
            p = strtok( buf, " ");
        } else {
            message( "analyze_HTTP: readline failed: Connection closed by remote host\n" );
            exit(2);
        }
    }

    if (strcmp( p, "HTTP/1.0" ) != 0 && strcmp( p, "HTTP/1.1" ) != 0) {
        message( "Unsupported HTTP version number %s\n", p );
        exit( 1 );
    }

    p = strtok( NULL, " ");

    if( strcmp( p, "200" ) != 0 ) {
        if( ! args_info.quiet_flag )
            message( "HTTP return code: %s ", p );

        int is_407 = strcmp( p, "407" ) == 0;

        p += strlen( p ) + 1;

        if( ! args_info.quiet_flag )
            message( "%s", p );

        if (is_407)
        {
            do {
                readline(pts);
                if (strncmp( buf, "Proxy-Authenticate: Digest ", 27 ) == 0 &&
                        !pdigest_challenge_ctx) {
                    pdigest_challenge_ctx = create_digest_auth(get_uri(), (unsigned char *)&buf[27]);
                    if (!pdigest_challenge_ctx)
                    {
                        message( "FAILED Digest Authentication\n" );
                        exit(1);
                    }
                }
            } while ( strcmp( buf, "\r\n" ) != 0 );
        }
        else if (!ntlm_challenge) {
            do {
                readline(pts);
                if (strncmp( buf, "Proxy-Authenticate: NTLM ", 25) == 0) {
                    if (parse_type2((unsigned char *)&buf[25]) < 0)
                    {
                        message( "FAILED NTLM Authentication\n" );
                        exit(1);
                    }
                }
            } while ( strcmp( buf, "\r\n" ) != 0 );
        }

        if (ntlm_challenge == 1 || pdigest_challenge_ctx) {

            // Will be resent for current proxy number
            --global_proxy_number;

            proxy_protocol(pts);
            return;
        }
        exit( 1 );
    }
}

/*
 * Prints lines from a buffer prepended with a prefix
 */
void print_line_prefix(char *buf, char *prefix) {
    buf = strdup(buf);
    char *cur = strtok(buf, "\r\n");
    while ( cur != NULL) {
        message( "%s%s\n", prefix, cur );
        cur = strtok(NULL, "\r\n");
    }
//	message( "%s: '%s\n", prefix, buf );
}

/*
 * Execute the basic proxy protocol of CONNECT and response, until the
 * last line of the response has been read. The tunnel is then open.
 */
void proxy_protocol(PTSTREAM *pts) {

    ++global_proxy_number;

    /* Create the proxy CONNECT command into buf */
    if (args_info.remproxy_given ) {
        if( args_info.verbose_flag )
            message( "\nTunneling to %s (remote proxy)\n", args_info.remproxy_arg );
        sprintf( buf, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", args_info.remproxy_arg, get_uri() );
    } else {
        if( args_info.verbose_flag )
            message( "\nTunneling to %s (destination)\n", args_info.dest_arg );
        sprintf( buf, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", args_info.dest_arg, get_uri() );
    }

    if ( args_info.user_given && args_info.pass_given ) {
        /* Create connect string including the authorization part */
        if (args_info.auth_ntlm_flag) {
            if (ntlm_challenge == 1) {
                build_type3_response();
                strzcat( buf, "Proxy-Authorization: NTLM %s\r\n", ntlm_type3_buf );
            } else if (ntlm_challenge == 0) {
                strzcat( buf, "Proxy-Authorization: NTLM %s\r\n", ntlm_type1_buf );
            }
        } else if (args_info.auth_digest_flag) {
            if (pdigest_challenge_ctx) {
                char *digest = build_digest_response(pdigest_challenge_ctx, args_info.user_arg, args_info.pass_arg);
                strzcat( buf, "Proxy-Authorization: Digest %s\r\n", digest );
                free(digest);
                cleanup_digest_auth(&pdigest_challenge_ctx);
            }
        } else {
            strzcat( buf, "Proxy-Authorization: Basic %s\r\n", basicauth(args_info.user_arg, args_info.pass_arg ) );
        }
    }

    strzcat( buf, "Proxy-Connection: Keep-Alive\r\n");
    /* Add extra header(s), headers are already \r\n terminated */
    if ( args_info.header_given )
        strzcat( buf, "%s", args_info.header_arg );

    // Finalize client request by making "\r\n\r\n"
    strzcat( buf, "\r\n" );

    /* Print the CONNECT instruction before sending to proxy */
    if( args_info.verbose_flag ) {
        message( "Communication with local proxy:\n");
        print_line_prefix(buf, " -> ");
    }

    /* Send the CONNECT instruction to the proxy */
    if( stream_write( pts, buf, strlen( buf )) < 0 ) {
        my_perror( "Socket write error" );
        exit( 1 );
    }

    if( args_info.wa_bug_29744_flag && !args_info.encryptremproxy_flag && pts->ssl ) {
        message( "Switching to non-SSL communication (local proxy)\n");
        pts->ssl = 0;
    }

    /* Read the first line of the response and analyze it */
    analyze_HTTP(pts);

    if (args_info.remproxy_given ) {

        ++global_proxy_number;

        /* Clean buffer for next analysis */
        while ( strcmp( buf, "\r\n" ) != 0 )
        {
            readline(pts);
        }

        /* If --encrypt-remproxy is specified, connect to the remote proxy using SSL */
        if ( args_info.encryptremproxy_flag )
            stream_enable_ssl(stunnel, args_info.remproxy_arg);

        if( args_info.verbose_flag )
            message( "\nTunneling to %s (destination)\n", args_info.dest_arg );
        sprintf( buf, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", args_info.dest_arg, get_uri());

        if ( args_info.remuser_given && args_info.rempass_given )
            strzcat( buf, "Proxy-Authorization: Basic %s\r\n", basicauth(args_info.remuser_arg, args_info.rempass_arg ));

        strzcat( buf, "Proxy-Connection: Keep-Alive\r\n");

        /* Add extra header(s), headers are already \r\n terminated */
        if ( args_info.header_given )
            strzcat( buf, "%s", args_info.header_arg );

        // Finalize client request by making "\r\n\r\n"
        strzcat( buf, "\r\n" );

        /* Print the CONNECT instruction before sending to proxy */
        if( args_info.verbose_flag ) {
            message( "Communication with remote proxy:\n");
            print_line_prefix(buf, " -> ");
        }

        /* Send the CONNECT instruction to the proxy */
        if( stream_write( pts, buf, strlen( buf )) < 0 ) {
            my_perror( "Socket write error" );
            exit( 1 );
        }

        if( args_info.wa_bug_29744_flag && pts->ssl ) {
            message( "Switching to non-SSL communication (remote proxy)\n");
            pts->ssl = 0;
        }

        /* Read the first line of the response and analyze it */
        analyze_HTTP(pts);
    }

    /*
     * Then, repeat reading lines of the responses until a blank line
     * (which signifies the end of the response) is encountered.
     */
    if (ntlm_challenge == 1) {
        ntlm_challenge = 2;
    } else {
        while ( strcmp( buf, "\r\n" ) != 0 )
        {
            readline(pts);
        }
    }
}

// vim:noexpandtab:ts=4
