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

#ifdef HAVE_SASL_H
#include <sasl.h>
#elif defined(HAVE_SASL_SASL_H)
#include <sasl/sasl.h>
#elif defined(HAVE_SASL_DARWIN)
typedef struct sasl_interact {
    unsigned long id;           /* same as client/user callback ID */
    const char *challenge;      /* presented to user (e.g. OTP challenge) */
    const char *prompt;         /* presented to user (e.g. "Username: ") */
    const char *defresult;      /* default result string */
    const void *result;         /* set to point to result */
    unsigned len;               /* set to length of result */
} sasl_interact_t;
#define SASL_CB_USER         0x4001  /* client user identity to login as */
#define SASL_CB_AUTHNAME     0x4002  /* client authentication name */
#define SASL_CB_PASS         0x4004  /* client passphrase-based secret */
#define SASL_CB_ECHOPROMPT   0x4005 /* challenge and client enterred result */
#define SASL_CB_NOECHOPROMPT 0x4006 /* challenge and client enterred result */
#define SASL_CB_GETREALM     0x4008  /* realm to attempt authentication in */
#define SASL_CB_LIST_END   0  /* end of list */
#endif

#if defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H) || defined(HAVE_SASL_DARWIN)
void *lutil_sasl_defaults(
			  LDAP *ld,
			  char *mech,
			  char *realm,
			  char *authcid,
			  char *passwd,
			  char *authzid );

int lutil_sasl_interact(
			LDAP *ld,
			unsigned flags,
			void *defaults,
			void *in );

void lutil_sasl_freedefs(
			 void *defaults );


/*
 * SASL definitions for openldap support
 */


typedef struct lutil_sasl_defaults_s {
  char *mech;
  char *realm;
  char *authcid;
  char *passwd;
  char *authzid;
  char **resps;
  int nresps;
} lutilSASLdefaults;

void *
lutil_sasl_defaults(
		    LDAP *ld,
		    char *mech,
		    char *realm,
		    char *authcid,
		    char *passwd,
		    char *authzid )
{
  lutilSASLdefaults *defaults;

  defaults = (lutilSASLdefaults *)malloc( sizeof( lutilSASLdefaults ) );

  if( defaults == NULL ) return NULL;

  defaults->mech = mech ? strdup(mech) : NULL;
  defaults->realm = realm ? strdup(realm) : NULL;
  defaults->authcid = authcid ? strdup(authcid) : NULL;
  defaults->passwd = passwd ? strdup(passwd) : NULL;
  defaults->authzid = authzid ? strdup(authzid) : NULL;

  if( defaults->mech == NULL ) {
    ldap_get_option( ld, LDAP_OPT_X_SASL_MECH, &defaults->mech );
  }
  if( defaults->realm == NULL ) {
    ldap_get_option( ld, LDAP_OPT_X_SASL_REALM, &defaults->realm );
  }
  if( defaults->authcid == NULL ) {
    ldap_get_option( ld, LDAP_OPT_X_SASL_AUTHCID, &defaults->authcid );
  }
  if( defaults->authzid == NULL ) {
    ldap_get_option( ld, LDAP_OPT_X_SASL_AUTHZID, &defaults->authzid );
  }
  defaults->resps = NULL;
  defaults->nresps = 0;

  return defaults;
}

static int interaction(
		       unsigned flags,
		       sasl_interact_t *interact,
		       lutilSASLdefaults *defaults )
{
  const char *dflt = interact->defresult;

  flags = flags;
  switch( interact->id ) {
  case SASL_CB_GETREALM:
    if( defaults ) dflt = defaults->realm;
    break;
  case SASL_CB_AUTHNAME:
    if( defaults ) dflt = defaults->authcid;
    break;
  case SASL_CB_PASS:
    if( defaults ) dflt = defaults->passwd;
    break;
  case SASL_CB_USER:
    if( defaults ) dflt = defaults->authzid;
    break;
  case SASL_CB_NOECHOPROMPT:
    break;
  case SASL_CB_ECHOPROMPT:
    break;
  }

  if( dflt && !*dflt ) dflt = NULL;

  /* input must be empty */
  interact->result = (dflt && *dflt) ? dflt : "";
  interact->len = strlen( interact->result );

  return LDAP_SUCCESS;
}

int lutil_sasl_interact(
			LDAP *ld,
			unsigned flags,
			void *defaults,
			void *in )
{
  sasl_interact_t *interact = in;

  if( ld == NULL ) return LDAP_PARAM_ERROR;

  while( interact->id != SASL_CB_LIST_END ) {
    int rc = interaction( flags, interact, defaults );

    if( rc )  return rc;
    interact++;
  }

  return LDAP_SUCCESS;
}

void
lutil_sasl_freedefs(
		    void *defaults )
{
  lutilSASLdefaults *defs = defaults;

  if (defs->mech) free(defs->mech);
  if (defs->realm) free(defs->realm);
  if (defs->authcid) free(defs->authcid);
  if (defs->passwd) free(defs->passwd);
  if (defs->authzid) free(defs->authzid);
  if (defs->resps) free(defs->resps);

  free(defs);
}

int tool_sasl_bind( LDAP *ld , char *binddn, char* ssl)
{
  /*
    unsigned sasl_flags = LDAP_SASL_AUTOMATIC;
    unsigned sasl_flags = LDAP_SASL_QUIET;
  */
  /* 
   * Avoid SASL messages
   */
#ifdef HAVE_SUN_LDAP_SDK
  unsigned sasl_flags = LDAP_SASL_INTERACTIVE;
#else
  unsigned sasl_flags = LDAP_SASL_QUIET;
#endif
  char  *sasl_realm = NULL;
  char  *sasl_authc_id = NULL;
  char  *sasl_authz_id = NULL;
#ifdef HAVE_SUN_LDAP_SDK
  char  *sasl_mech = (char *)"GSSAPI";
#else
  char  *sasl_mech = NULL;
#endif
  /* 
   * Force encryption
   */
  char  *sasl_secprops;
  /*
    char  *sasl_secprops = (char *)"maxssf=56";
    char  *sasl_secprops = NULL;
  */
  struct berval passwd = { 0, NULL };
  void  *defaults;
  int rc=LDAP_SUCCESS;

  if (ssl)
      sasl_secprops = (char *)"maxssf=0";
  else
      sasl_secprops = (char *)"maxssf=56";
/*      sasl_secprops = (char *)"maxssf=0"; */
/*      sasl_secprops = (char *)"maxssf=56"; */

  if( sasl_secprops != NULL ) {
    rc = ldap_set_option( ld, LDAP_OPT_X_SASL_SECPROPS,
			  (void *) sasl_secprops );
    if( rc != LDAP_SUCCESS) {
	fprintf(stderr,"%s| %s: Could not set LDAP_OPT_X_SASL_SECPROPS: %s: %s\n",LogTime(), PROGRAM, sasl_secprops,ldap_err2string(rc));
	return rc;
      }
    }

    defaults = lutil_sasl_defaults( ld,
				    sasl_mech,
				    sasl_realm,
				    sasl_authc_id,
				    passwd.bv_val,
				    sasl_authz_id );

    rc = ldap_sasl_interactive_bind_s( ld, binddn,
				       sasl_mech, NULL, NULL,
				       sasl_flags, lutil_sasl_interact, defaults );

    lutil_sasl_freedefs( defaults );
    if( rc != LDAP_SUCCESS ) {
      fprintf(stderr,"%s| %s: ldap_sasl_interactive_bind_s error: %s\n",LogTime(), PROGRAM, ldap_err2string(rc));
    }
    return rc;
  }
#else
void dummy(void);
void dummy(void) {
    fprintf(stderr,"%s| %s: Dummy function\n",LogTime(), PROGRAM);
}
#endif
    
    
  
