/*
 * -----------------------------------------------------------------------------
 *
 * Author: Markus Moeller (markus_moeller at compuserve.com)
 *
 * Copyright (C) 2007 Markus Moeller. All rights reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * -----------------------------------------------------------------------------
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "config.h"

#define LDAP_DEPRECATED 1
#ifdef HAVE_LDAP_REBIND_FUNCTION
#define LDAP_REFERRALS
#endif
#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif

struct gdstruct {
  char *group;
  char *domain;
  struct gdstruct *next;
};
struct ndstruct {
  char *netbios;
  char *domain;
  struct ndstruct *next;
};
struct lsstruct {
  char *lserver;
  char *domain;
  struct lsstruct *next;
};

struct main_args {
  char* glist;
  char* ulist;
  char* tlist;
  char* nlist;
  char* llist;
  char* luser;
  char* lpass;
  char* lbind;
  char* lurl;
  char* ssl;
  int   rc_allow;
  int   debug;
  int   log;
  int   AD;
  int   mdepth;
  char* ddomain;
  char* pname;
  struct gdstruct *groups;
  struct ndstruct *ndoms;
  struct lsstruct *lservs;
}; 

struct kstruct {
  krb5_context context;
  char* mem_cache_env;
  krb5_ccache cc;
} kparam;

struct hstruct {
  char *host;
  int  port;
  int  priority;
  int  weight;
};

struct ldap_creds {
    char *dn;
    char *pw;
};


void init_args(struct main_args *margs);
void clean_args(struct main_args *margs);
static const char *LogTime(void);

int check_memberof(struct main_args *margs,char *user, char *domain);
int get_memberof(struct main_args *margs,char *user,char *domain,char *group);

char *get_netbios_name(struct main_args *margs,char *netbios);

int create_gd(struct main_args *margs);
int create_nd(struct main_args *margs);
int create_ls(struct main_args *margs);

int krb5_create_cache(struct main_args *margs, char *domain);
void krb5_cleanup(void);

int get_ldap_hostname_list(struct main_args *margs, struct hstruct **hlist,int nhosts, char *domain);
int get_hostname_list(struct main_args *margs, struct hstruct **hlist,int nhosts, char *name);
int free_hostname_list(struct hstruct **hlist, int nhosts);

#if defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H) || defined(HAVE_SASL_DARWIN)
int tool_sasl_bind( LDAP *ld , char *binddn, char* ssl);
#endif

#define PROGRAM "squid_kerb_ldap"

static const char *LogTime()
{
    struct tm *tm;
    struct timeval now;
    static time_t last_t = 0;
    static char buf[128];

    gettimeofday(&now, NULL);
    if (now.tv_sec != last_t) {
        tm = localtime(&now.tv_sec);
        strftime(buf, 127, "%Y/%m/%d %H:%M:%S", tm);
        last_t = now.tv_sec;
    }
    return buf;
}

