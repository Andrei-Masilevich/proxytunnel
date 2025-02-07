/* Proxytunnel - (C) 2001-2008 Jos Visser / Mark Janssen    */
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

/* globals.c */

#include "proxytunnel.h"

/* Globals */
char *program_name;             /* Guess what? */
int i_am_daemon;                /* Also... */

PTSTREAM *stunnel;	/* stream representing the socket from us to proxy */
PTSTREAM *std;		/* stream representing stdin/stdout */

/*
 * All the command line options
 */
struct gengetopt_args_info args_info;

char buf[SIZE];         /* Data transfer buffer */

char ntlm_type1_buf[160];
char ntlm_type3_buf[4096];
char digest_auth_http_buf[1024];

// vim:noexpandtab:ts=4
