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

int check_memberof(struct main_args *margs,char *user,char *domain) {

  /* 
   *  Check order:
   *
   *  1.  Check domain against list of groups per domain
   *  1a. If domain does not exist in list try default domain
   *  1b. If default domain does not exist use default group against ldap url with user/password 
   *  1c. If default group does not exist exit with error.
   *  2.  Query ldap membership 
   *  2a. Use GSSAPI/SASL with HTTP/fqdn@DOMAIN credentials from keytab
   *  2b. Use username/password with TLS
   *
   */
  struct gdstruct* gr;
  int found=0;


  /* Check users domain */

  gr = margs->groups;
  while(gr && domain) {
    if (margs->debug)
      fprintf(stderr,"%s| %s: User domain loop: group@domain %s@%s\n",LogTime(), PROGRAM,gr->group,gr->domain?gr->domain:"NULL");
    if (gr->domain && !strcasecmp(gr->domain,domain)) {
      if (margs->debug)
	fprintf(stderr,"%s| %s: Found group@domain %s@%s\n",LogTime(), PROGRAM,gr->group,gr->domain);
      /* query ldap */
      if (get_memberof(margs,user,domain,gr->group)) {
        if (margs->debug || margs->log)
	  fprintf(stderr,"%s| %s: User %s is member of group@domain %s@%s\n",LogTime(), PROGRAM,user,gr->group,gr->domain);
	found++;
	break;
      } else {
        if (margs->debug || margs->log)
	  fprintf(stderr,"%s| %s: User %s is not member of group@domain %s@%s\n",LogTime(), PROGRAM,user,gr->group,gr->domain);
      }
    }
    gr = gr->next;
  }

  if (found)
    return(1);

  /* Check default domain */

  gr = margs->groups;
  while(gr && domain) {
    if (margs->debug)
      fprintf(stderr,"%s| %s: Default domain loop: group@domain %s@%s\n",LogTime(), PROGRAM,gr->group,gr->domain?gr->domain:"NULL");
    if (gr->domain && !strcasecmp(gr->domain,"")) {
      if (margs->debug)
	fprintf(stderr,"%s| %s: Found group@domain %s@%s\n",LogTime(), PROGRAM,gr->group,gr->domain);
      /* query ldap */
      if (get_memberof(margs,user,domain,gr->group)) {
        if (margs->debug || margs->log)
	  fprintf(stderr,"%s| %s: User %s is member of group@domain %s@%s\n",LogTime(), PROGRAM,user,gr->group,gr->domain);
	found++;
	break;
      } else {
        if (margs->debug || margs->log)
	  fprintf(stderr,"%s| %s: User %s is not member of group@domain %s@%s\n",LogTime(), PROGRAM,user,gr->group,gr->domain);
      }
    }
    gr = gr->next;
  }

  if (found)
    return(1);

  /* Check default group with ldap url */

  gr = margs->groups;
  while(gr) {
    if (margs->debug)
      fprintf(stderr,"%s| %s: Default group loop: group@domain %s@%s\n",LogTime(), PROGRAM,gr->group,gr->domain?gr->domain:"NULL");
    if (!gr->domain) {
      if (margs->debug)
	fprintf(stderr,"%s| %s: Found group@domain %s@%s\n",LogTime(), PROGRAM,gr->group,gr->domain?gr->domain:"NULL");
      /* query ldap */
      if (get_memberof(margs,user,domain,gr->group)) {
        if (margs->debug || margs->log)
	  fprintf(stderr,"%s| %s: User %s is member of group@domain %s@%s\n",LogTime(), PROGRAM,user,gr->group,gr->domain?gr->domain:"NULL");
	found++;
	break;
      } else {
        if (margs->debug || margs->log)
	  fprintf(stderr,"%s| %s: User %s is not member of group@domain %s@%s\n",LogTime(), PROGRAM,user,gr->group,gr->domain?gr->domain:"NULL");
      }
    }
    gr = gr->next;
  }
 
  if (found)
    return(1);

  return(0);
}

