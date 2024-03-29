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

#include "support.h"
struct ndstruct *init_nd(void);

struct ndstruct *init_nd(void) {
  struct ndstruct *ndsp;
  ndsp=(struct ndstruct *)malloc(sizeof(struct ndstruct));
  ndsp->netbios=NULL;
  ndsp->domain=NULL;
  ndsp->next=NULL;
  return ndsp;
}

int create_nd(struct main_args *margs) {
  char *np,*dp;
  char *p;
  struct ndstruct *ndsp=NULL,*ndspn=NULL;
  /*
   *  netbios list format:
   *
   *     nlist=Pattern1[:Pattern2]
   *
   *     Pattern=NetbiosName@Domain    Netbios Name for a specific Kerberos domain
   *                             ndstruct.domain=Domain, ndstruct.netbios=NetbiosName
   *
   *
   */
  p=margs->nlist;
  np=margs->nlist;
  if (margs->debug)
    fprintf(stderr, "%s| %s: Netbios list %s\n",LogTime(), PROGRAM,margs->nlist?margs->nlist:"NULL");
  dp=NULL;

  if (!p) {
    if (margs->debug)
      fprintf(stderr, "%s| %s: No netbios names defined.\n",LogTime(), PROGRAM);
    return(0);
  }
  while (*p) { /* loop over group list */
    if ( *p == '\n' || *p == '\r' ) { /* Ignore CR and LF if exist */
      p++;
      continue;
    }
    if ( *p == '@' ) { /* end of group name - start of domain name */
      if (p == np) { /* empty group name not allowed */
	if (margs->debug)
	  fprintf(stderr, "%s| %s: No netbios name defined for domain %s\n",LogTime(), PROGRAM,p);
	return(1);
      }
      *p = '\0';
      p++; 
      ndsp=init_nd();
      ndsp->netbios=strdup(np);
      if (ndspn) /* Have already an existing structure */
	ndsp->next=ndspn;
      dp=p; /* after @ starts new domain name */ 
    } else if ( *p == ':' ) { /* end of group name or end of domain name */
      if (p == np) { /* empty group name not allowed */
	if (margs->debug)
	  fprintf(stderr, "%s| %s: No netbios name defined for domain %s\n",LogTime(), PROGRAM,p);
	return(1);
      }
      *p = '\0';
      p++;
      if (dp) {  /* end of domain name */
	ndsp->domain=strdup(dp);
	dp=NULL;
      } else { /* end of group name and no domain name */
	ndsp=init_nd();
	ndsp->netbios=strdup(np);
	if (ndspn) /* Have already an existing structure */
	  ndsp->next=ndspn;
      }
      ndspn=ndsp; 
      np=p; /* after : starts new group name */ 
      if (!ndsp->domain || !strcmp(ndsp->domain,"")) {
        if (margs->debug)
          fprintf(stderr, "%s| %s: No domain defined for netbios name %s\n",LogTime(), PROGRAM,ndsp->netbios);
        return(1);
      }
      if (margs->debug) 
	fprintf(stderr, "%s| %s: Netbios name %s  Domain %s\n",LogTime(), PROGRAM,ndsp->netbios,ndsp->domain);
    } else 
      p++;
  }
  if (p == np) { /* empty group name not allowed */
    if (margs->debug)
      fprintf(stderr, "%s| %s: No netbios name defined for domain %s\n",LogTime(), PROGRAM,p);
    return(1);
  }
  if (dp) {  /* end of domain name */
    ndsp->domain=strdup(dp);
  } else { /* end of group name and no domain name */
    ndsp=init_nd();
    ndsp->netbios=strdup(np);
    if (ndspn) /* Have already an existing structure */
      ndsp->next=ndspn;
  }
  if (!ndsp->domain || !strcmp(ndsp->domain,"")) {
    if (margs->debug)
      fprintf(stderr, "%s| %s: No domain defined for netbios name %s\n",LogTime(), PROGRAM,ndsp->netbios);
    return(1);
  }
  if (margs->debug) 
    fprintf(stderr, "%s| %s: Netbios name %s  Domain %s\n",LogTime(), PROGRAM,ndsp->netbios,ndsp->domain);

  margs->ndoms=ndsp; 
  return(0);
}

char *get_netbios_name(struct main_args *margs,char *netbios) {
  struct ndstruct *nd;

  nd = margs->ndoms;
  while(nd && netbios) {
    if (margs->debug)
      fprintf(stderr,"%s| %s: Netbios domain loop: netbios@domain %s@%s\n",LogTime(), PROGRAM,nd->netbios,nd->domain);
    if (nd->netbios && !strcasecmp(nd->netbios,netbios)) {
      if (margs->debug)
        fprintf(stderr,"%s| %s: Found netbios@domain %s@%s\n",LogTime(), PROGRAM,nd->netbios,nd->domain);
      return(nd->domain);
    }
    nd = nd->next;
  }

  return NULL;
}

