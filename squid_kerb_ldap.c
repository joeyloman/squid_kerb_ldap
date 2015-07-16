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
 *   As a special exemption, M Moeller gives permission to link this program
 *   with MIT, Heimdal or other GSS/Kerberos libraries, and distribute
 *   the resulting executable, without including the source code for
 *   the Libraries in the source distribution.
 *
 * -----------------------------------------------------------------------------
 */
/*
 * Hosted at http://sourceforge.net/projects/squidkerbauth
 */
#include <unistd.h>
#include <ctype.h>

#include "support.h"

void init_args(struct main_args *margs) {
  margs->nlist=NULL;
  margs->glist=NULL;
  margs->llist=NULL;
  margs->ulist=NULL;
  margs->tlist=NULL;
  margs->luser=NULL;
  margs->lpass=NULL;
  margs->lbind=NULL;
  margs->lurl=NULL;
  margs->ssl=NULL;
  margs->rc_allow=0;
  margs->debug=0;
  margs->log=0;
  margs->AD=0;
  margs->mdepth=5;
  margs->ddomain=NULL;
  margs->pname=NULL;
  margs->groups=NULL;
  margs->ndoms=NULL;
  margs->lservs=NULL;
}

void  clean_gd(struct gdstruct *gdsp);
void  clean_nd(struct ndstruct *ndsp);
void  clean_ls(struct lsstruct *lssp);

void  clean_gd(struct gdstruct *gdsp) {
  struct gdstruct *p=NULL,*pp=NULL;

start:
  p=gdsp; 
  if (!p) return;
  while (p->next) {
    pp=p; 
    p=p->next; 
  }
  if (p->group) {
      free(p->group);
      p->group=NULL;
  }
  if (p->domain) {
      free(p->domain);
      p->domain=NULL;
  }
  if (pp && pp->next) {
    free(pp->next);
    pp->next=NULL;
  }
  if (p == gdsp) {
     free(gdsp);
     gdsp=NULL;
  } 
  goto start;
}

void  clean_nd(struct ndstruct *ndsp) {
  struct ndstruct *p=NULL,*pp=NULL;

start:
  p=ndsp;
  if (!p) return;
  while (p->next) {
    pp=p;
    p=p->next;
  }
  if (p->netbios) {
      free(p->netbios);
      p->netbios=NULL;
  }
  if (p->domain) {
      free(p->domain);
      p->domain=NULL;
  }
  if (pp && pp->next) {
    free(pp->next);
    pp->next=NULL;
  }
  if (p == ndsp) {
     free(ndsp);
     ndsp=NULL;
  }
  goto start;
}

void  clean_ls(struct lsstruct *lssp) {
  struct lsstruct *p=NULL,*pp=NULL;

start:
  p=lssp;
  if (!p) return;
  while (p->next) {
    pp=p;
    p=p->next;
  }
  if (p->lserver) {
      free(p->lserver);
      p->lserver=NULL;
  }
  if (p->domain) {
      free(p->domain);
      p->domain=NULL;
  }
  if (pp && pp->next) {
    free(pp->next);
    pp->next=NULL;
  }
  if (p == lssp) {
     free(lssp);
     lssp=NULL;
  }
  goto start;
}

void clean_args(struct main_args *margs) {
  if (margs->glist) {
      free(margs->glist);
      margs->glist=NULL;
  }
  if (margs->ulist) {
      free(margs->ulist);
      margs->ulist=NULL;
  }
  if (margs->tlist) {
      free(margs->tlist);
      margs->tlist=NULL;
  }
  if (margs->nlist) {
      free(margs->nlist);
      margs->nlist=NULL;
  }
  if (margs->llist) {
      free(margs->llist);
      margs->llist=NULL;
  }
  if (margs->luser) {
      free(margs->luser);
      margs->luser=NULL;
  }
  if (margs->lpass) {
      free(margs->lpass);
      margs->lpass=NULL;
  }
  if (margs->lbind) {
      free(margs->lbind);
      margs->lbind=NULL;
  }
  if (margs->lurl) {
      free(margs->lurl);
      margs->lurl=NULL;
  }
  if (margs->ssl) {
      free(margs->ssl);
      margs->ssl=NULL;
  }
  if (margs->ddomain) {
      free(margs->ddomain);
      margs->ddomain=NULL;
  }
  if (margs->pname) {
      free(margs->pname);
      margs->pname=NULL;
  }
  if (margs->groups) {
      clean_gd(margs->groups);
      margs->groups=NULL;
  }
  if (margs->ndoms) {
      clean_nd(margs->ndoms);
      margs->ndoms=NULL;
  }
  if (margs->lservs) {
      clean_ls(margs->lservs);
      margs->lservs=NULL;
  }

}

void strup(char *s);

int main (int argc, char * const argv[]) {
  char buf[6400];
  char *user,*domain;
  char *nuser,*nuser8=NULL,*netbios;
  char *c;
  int opt;
  struct main_args margs;

  setbuf(stdout,NULL);
  setbuf(stdin,NULL);
  
  init_args(&margs);

  while (-1 != (opt = getopt(argc, argv, "diasg:D:P:N:S:u:U:t:T:p:l:b:m:h"))) {
    switch (opt) {
    case 'd':
      margs.debug = 1;
      break;
    case 'i':
      margs.log= 1;
      break;
    case 'a':
      margs.rc_allow= 1;
      break;
    case 's':
      margs.ssl= (char *)"yes";
      break;
    case 'g':
      margs.glist = strdup(optarg);
      break;
    case 'D':
      margs.ddomain = strdup(optarg);
      break;
    case 'P':
      margs.pname = strdup(optarg);
      break;
    case 'N':
      margs.nlist = strdup(optarg);
      break;
    case 'u':
      margs.luser = strdup(optarg);
      break;
    case 'U':
      margs.ulist = strdup(optarg);
      break;
    case 't':
      margs.ulist = strdup(optarg);
      break;
    case 'T':
      margs.tlist = strdup(optarg);
      break;
    case 'p':
      margs.lpass = strdup(optarg);
      /* Hide Password */
      memset (optarg, 'X', strlen (optarg));
      break;
    case 'l':
      margs.lurl = strdup(optarg);
      break;
    case 'b':
      margs.lbind = strdup(optarg);
      break;
    case 'm':
      margs.mdepth = atoi(optarg);
      break;
    case 'S':
      margs.llist = strdup(optarg);
      break;
    case 'h':
      fprintf(stderr, "Usage: \n");
      fprintf(stderr, "squid_kerb_ldap [-d] [-i] -g group list [-D domain] [-N netbios domain map] [-P principal name] [-s] [-u ldap user] [-p ldap user password] [-l ldap url] [-b ldap bind path] [-a] [-m max depth] [-h]\n");
      fprintf(stderr, "-d full debug\n");
      fprintf(stderr, "-i informational messages\n");
      fprintf(stderr, "-g group list\n");
      fprintf(stderr, "-t group list (only group name hex UTF-8 format)\n");
      fprintf(stderr, "-T group list (all in hex UTF-8 format - except seperator @)\n");
      fprintf(stderr, "-D default domain\n");
      fprintf(stderr, "-N netbios to dns domain map\n");
      fprintf(stderr, "-P principal name for authentication\n");
      fprintf(stderr, "-S ldap server to dns domain map\n");
      fprintf(stderr, "-u ldap user\n");
      fprintf(stderr, "-p ldap user password\n");
      fprintf(stderr, "-l ldap url\n");
      fprintf(stderr, "-b ldap bind path\n");
      fprintf(stderr, "-s use SSL encryption with Kerberos authentication\n"); 
      fprintf(stderr, "-a allow SSL without cert verification\n");
      fprintf(stderr, "-m maximal depth for recursive searches\n");
      fprintf(stderr, "-h help\n");
      fprintf(stderr, "The ldap url, ldap user and ldap user password details are only used if the kerberised\n");
      fprintf(stderr, "access fails(e.g. unknown domain) or if the username does not contain a domain part\n");
      fprintf(stderr, "and no default domain is provided.\n");
      fprintf(stderr, "If the ldap url starts with ldaps:// it is either start_tls or simple SSL\n");
      fprintf(stderr, "The group list can be:\n");
      fprintf(stderr, "group   - In this case group can be used for all kerberised and non kerberised ldap servers\n");
      fprintf(stderr, "group@  - In this case group can be used for all keberised ldap servers\n");
      fprintf(stderr, "group@domain  - In this case group can be used for ldap servers of domain domain\n");
      fprintf(stderr, "group1@domain1:group2@domain2:group3@:group4  - A list is build with a colon as seperator\n");
      fprintf(stderr, "Group membership is determined with AD servers through the users memberof attribute which\n");
      fprintf(stderr, "is followed to the top (e.g. if the group is a member of a group)\n");
      fprintf(stderr, "Group membership is determined with non AD servers through the users memberuid (assuming\n");
      fprintf(stderr, "PosixGroup) or primary group membership (assuming PosixAccount)\n");
      fprintf(stderr, "The ldap server list can be:\n");
      fprintf(stderr, "server - In this case server can be used for all Kerberos domains\n");
      fprintf(stderr, "server@  - In this case server can be used for all Kerberos domains\n");
      fprintf(stderr, "server@domain  - In this case server can be used for Kerberos domain domain\n");
      fprintf(stderr, "server1a@domain1:server1b@domain1:server2@domain2:server3@:server4 - A list is build with a colon as seperator\n");
      clean_args(&margs);
      exit(0);
    default:
      fprintf(stderr, "%s| %s: unknown option: -%c.\n", LogTime(), PROGRAM, opt);
    }
  }

  if (margs.debug)
    fprintf(stderr, "%s| %s: Starting version %s\n", LogTime(), PROGRAM, VERSION);
  if (create_gd(&margs)) {
    if (margs.debug)
      fprintf(stderr, "%s| %s: Error in group list: %s\n",LogTime(), PROGRAM,margs.glist?margs.glist:"NULL");
    fprintf(stdout, "ERR\n");
    clean_args(&margs);
    exit(1);
  }
  if (create_nd(&margs)) {
    if (margs.debug)
      fprintf(stderr, "%s| %s: Error in netbios list: %s\n",LogTime(), PROGRAM,margs.nlist?margs.nlist:"NULL");
    fprintf(stdout, "ERR\n");
    clean_args(&margs);
    exit(1);
  }

  if (create_ls(&margs)) {
    if (margs.debug)
      fprintf(stderr, "%s| %s: Error in ldap server list: %s\n",LogTime(), PROGRAM,margs.llist?margs.llist:"NULL");
    fprintf(stdout, "ERR\n");
    clean_args(&margs);
    exit(1);
  }
  
  while (1) {
    if (fgets(buf, sizeof(buf)-1, stdin) == NULL) {
      if (ferror(stdin)) {
        if (margs.debug)
          fprintf(stderr, "%s| %s: fgets() failed! dying..... errno=%d (%s)\n", LogTime(), PROGRAM, ferror(stdin),
		  strerror(ferror(stdin)));

        fprintf(stdout, "ERR\n");
        clean_args(&margs);
        exit(1);    /* BIIG buffer */
      }
      fprintf(stdout, "ERR\n");
      clean_args(&margs);
      exit(0);
    }
    c=memchr(buf,'\n',sizeof(buf)-1);
    if (c) {
      *c = '\0';
    } else {
      fprintf(stdout, "ERR\n");
      if (margs.debug)
        fprintf(stderr, "%s| %s: ERR\n",LogTime(), PROGRAM);
      continue;
    }

    user = buf;
    nuser = strchr(user, '\\');
    if (!nuser)
    	nuser8 = strstr(user, "%5C");
    if (!nuser && !nuser8) 
    	nuser8 = strstr(user, "%5c");
    domain = strrchr(user, '@');
    if (nuser || nuser8) {
      if (nuser) {
        *nuser = '\0';
        nuser++;
      } else {
        *nuser8 = '\0';
      	nuser=nuser8+3;
      }
      netbios=user;
      if (margs.debug || margs.log)
        fprintf(stderr, "%s| %s: Got User: %s Netbios Name: %s\n",LogTime(), PROGRAM,nuser,netbios);
      domain=get_netbios_name(&margs,netbios);
      user=nuser;
    } else if (domain) {
      strup(domain);
      *domain = '\0';
      domain++;
    } 
    if (!domain && margs.ddomain) {
      domain=strdup(margs.ddomain);
      if (margs.debug || margs.log)
        fprintf(stderr, "%s| %s: Got User: %s set default domain: %s\n",LogTime(), PROGRAM,user,domain);
    }
    if (margs.pname) {
      if (margs.debug || margs.log)
        fprintf(stderr, "%s| %s: Got Principal: %s\n",LogTime(), PROGRAM,margs.pname);
    }
    if (margs.debug || margs.log)
      fprintf(stderr, "%s| %s: Got User: %s Domain: %s\n",LogTime(), PROGRAM,user,domain?domain:"NULL");

    if (!strcmp(user,"QQ") && domain && !strcmp(domain,"QQ")){
        clean_args(&margs);
        exit(-1);
    }
    if (check_memberof(&margs,user,domain)) {
      fprintf(stdout, "OK\n");
      if (margs.debug)
        fprintf(stderr, "%s| %s: OK\n",LogTime(), PROGRAM);
    } else {
      fprintf(stdout, "ERR\n");
      if (margs.debug)
        fprintf(stderr, "%s| %s: ERR\n",LogTime(), PROGRAM);
    }
  } 


}

void strup(char *s)
{
   while (*s) {
          *s = toupper((unsigned char)*s);
          s++;
   }
}
