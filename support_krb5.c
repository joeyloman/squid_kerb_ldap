/*
 * ----------------------------------------------------------------------------
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
#include <unistd.h>
#include <netdb.h>
#include <ctype.h>
#include <errno.h>

#include "support.h"

#define KT_PATH_MAX 256

void krb5_cleanup() {
    if (kparam.context) {
        if (kparam.cc)
	    krb5_cc_destroy(kparam.context,kparam.cc);
	krb5_free_context(kparam.context);
    }
}
/*
 * create Kerberos memory cache
 */
int krb5_create_cache(struct main_args *margs,char *domain) {

    krb5_keytab	    keytab = 0;
    krb5_keytab_entry entry;
    krb5_kt_cursor cursor;
    krb5_creds	    *creds=NULL;
    krb5_creds	    *tgt_creds=NULL;
    krb5_principal  *principal_list = NULL;
    krb5_principal  principal = NULL;
    char  *service;
    char  *keytab_name=NULL,*principal_name=NULL,*mem_cache=NULL;
    char  buf[KT_PATH_MAX], *p;
    int nprinc=0;
    int i;
    int	retval=0; 
    int	found=0; 
    krb5_error_code 		code = 0;

    kparam.context=NULL;

    if (!domain || !strcmp(domain,"")) 
	return(1);

    /*
     * Initialise Kerberos
     */

    code = krb5_init_context(&kparam.context);
    if (code)
    {
	fprintf(stderr, "%s| %s: Error while initialising Kerberos library : %s\n",LogTime(), PROGRAM, error_message(code));
	retval=1;
	goto cleanup;
    }

    /*
     * getting default keytab name
     */

    if (margs->debug)
	fprintf(stderr, "%s| %s: Get default keytab file name\n",LogTime(), PROGRAM);
    krb5_kt_default_name(kparam.context, buf, KT_PATH_MAX);
    p = strchr(buf, ':');             /* Find the end if "FILE:" */
    if (p) p++;                       /* step past : */
    keytab_name = strdup(p ? p : buf);
    if (margs->debug)
	fprintf(stderr, "%s| %s: Got default keytab file name %s\n",LogTime(), PROGRAM, keytab_name);

    code = krb5_kt_resolve(kparam.context, keytab_name, &keytab);
    if (code)
    {
	fprintf(stderr, "%s| %s: Error while resolving keytab %s : %s\n", LogTime(), PROGRAM, keytab_name,error_message(code));
	retval=1;
	goto cleanup;
    }

    code = krb5_kt_start_seq_get(kparam.context, keytab, &cursor);
    if (code)
    {
	fprintf(stderr, "%s| %s: Error while starting keytab scan : %s\n", LogTime(), PROGRAM, error_message(code));
	retval=1;
	goto cleanup;
    }
    if (margs->debug)
	fprintf(stderr, "%s| %s: Get principal name from keytab %s\n",LogTime(), PROGRAM, keytab_name);

    nprinc=0;
    while ((code = krb5_kt_next_entry(kparam.context, keytab, &entry, &cursor)) == 0) 
    {

        principal_list=realloc(principal_list,sizeof(krb5_principal)*(nprinc+1));
        krb5_copy_principal(kparam.context,entry.principal,&principal_list[nprinc++]);
	if (margs->debug)
#ifdef HAVE_HEIMDAL_KERBEROS
	    fprintf(stderr, "%s| %s: Keytab entry has realm name: %s\n", LogTime(), PROGRAM, entry.principal->realm);
#else
	    fprintf(stderr, "%s| %s: Keytab entry has realm name: %s\n", LogTime(), PROGRAM, krb5_princ_realm(kparam.context, entry.principal)->data);
#endif

        if (margs->pname)
        {
            code = krb5_unparse_name(kparam.context, entry.principal, &principal_name);
            if (code)
            {
                fprintf(stderr, "%s| %s: Error while unparsing principal name : %s\n", LogTime(), PROGRAM, error_message(code));
            } else {
                if (margs->debug)
                    fprintf(stderr, "%s| %s: Found principal name: %s\n", LogTime(), PROGRAM, principal_name);
            }

            if(!strcmp(principal_name,margs->pname))
            {
                fprintf(stderr, "%s| %s: Principal match found, using: %s for authentication\n", LogTime(), PROGRAM, principal_name);
                found=1;
            }
        } else {
#ifdef HAVE_HEIMDAL_KERBEROS
	    if (!strcasecmp(domain, entry.principal->realm))
#else
	    if (!strcasecmp(domain,krb5_princ_realm(kparam.context, entry.principal)->data))
#endif
	    {
		code = krb5_unparse_name(kparam.context, entry.principal, &principal_name);
		if (code)
		{
		    fprintf(stderr, "%s| %s: Error while unparsing principal name : %s\n", LogTime(), PROGRAM, error_message(code));
		} else {
		    if (margs->debug)
			fprintf(stderr, "%s| %s: Found principal name: %s\n", LogTime(), PROGRAM, principal_name);
		    found=1;
                }
	    }
        }
#if defined(HAVE_HEIMDAL_KERBEROS) || ( defined(HAVE_KRB5_KT_FREE_ENTRY) && HAVE_DECL_KRB5_KT_FREE_ENTRY==1)
	code = krb5_kt_free_entry(kparam.context,&entry);
#else
	code = krb5_free_keytab_entry_contents(kparam.context,&entry);
#endif
	if (code)
        {
	    fprintf(stderr, "%s| %s: Error while freeing keytab entry : %s\n", LogTime(), PROGRAM, error_message(code));
	    retval=1;
	    break;
        }
        if (found) 
            break;
    }

    if (!found)
    {
        if (margs->pname)
            fprintf(stderr, "%s| %s: Error no principal name found matching principal name argument: %s!\n", LogTime(), PROGRAM, margs->pname);
        else
            fprintf(stderr, "%s| %s: Error no valid principal name found!\n", LogTime(), PROGRAM);

        retval=1;
        goto cleanup;
    }

    if (code && code != KRB5_KT_END) 
    {
	fprintf(stderr, "%s| %s: Error while scanning keytab : %s\n", LogTime(), PROGRAM, error_message(code));
	retval=1;
	goto cleanup;
    }

    code = krb5_kt_end_seq_get(kparam.context, keytab, &cursor);
    if (code)
    {
	fprintf(stderr, "%s| %s: Error while ending keytab scan : %s\n", LogTime(), PROGRAM, error_message(code));
	retval=1;
	goto cleanup;
    }

    /*
     * prepare memory credential cache
     */
#ifndef HAVE_KRB5_MEMORY_CACHE
    mem_cache=malloc(strlen("FILE:/tmp/squid_ldap_")+16);
    snprintf(mem_cache,strlen("FILE:/tmp/squid_ldap_")+16,"FILE:/tmp/squid_ldap_%d",(int)getpid());
#else    
    mem_cache=malloc(strlen("MEMORY:squid_ldap_")+16);
    snprintf(mem_cache,strlen("MEMORY:squid_ldap_")+16,"MEMORY:squid_ldap_%d",(int)getpid());
#endif    
    
    setenv("KRB5CCNAME",mem_cache,1);
    if (margs->debug)
	fprintf(stderr, "%s| %s: Set credential cache to %s\n",LogTime(), PROGRAM,mem_cache);
    code = krb5_cc_resolve(kparam.context, mem_cache , &kparam.cc);
    if (code) 
    {
	fprintf(stderr, "%s| %s: Error while resolving memory ccache : %s\n",LogTime(), PROGRAM, error_message(code));
	retval=1;
	goto cleanup;
    }

    /*
     * if no principal name found in keytab for domain use the prinipal name which can get a TGT
     */
    if (!principal_name)
    {
	if (margs->debug) {
	    fprintf(stderr, "%s| %s: Did not find a principal in keytab for domain %s.\n",LogTime(), PROGRAM,domain);
	    fprintf(stderr, "%s| %s: Try to get principal of trusted domain.\n",LogTime(), PROGRAM);
	}
	creds = malloc(sizeof(*creds));
	memset(creds, 0, sizeof(*creds));

        for (i=0;i<nprinc;i++) {	
            /*
             * get credentials
             */
            code = krb5_unparse_name(kparam.context, principal_list[i], &principal_name);
            if (code)
            {
                if (margs->debug)
                    fprintf(stderr, "%s| %s: Error while unparsing principal name : %s\n", LogTime(), PROGRAM, error_message(code));
		goto loop_end;
            }
	    if (margs->debug)
	        fprintf(stderr, "%s| %s: Keytab entry has principal: %s\n", LogTime(), PROGRAM, principal_name);

#if HAVE_GET_INIT_CREDS_KEYTAB
            code = krb5_get_init_creds_keytab(kparam.context, creds, principal_list[i], keytab, 0, NULL, NULL);
#else
            service=malloc(strlen("krbtgt")+2*strlen(domain)+3);
            snprintf(service,strlen("krbtgt")+2*strlen(domain)+3,"krbtgt/%s@%s",domain,domain);
            creds->client=principal_list[i];
            code = krb5_parse_name(kparam.context,service,&creds->server);
            if (service)
               free(service);
            code = krb5_get_in_tkt_with_keytab(kparam.context, 0, NULL, NULL, NULL, keytab, NULL, creds, 0);
#endif
            if (code)
            {
		if (margs->debug)
		    fprintf(stderr, "%s| %s: Error while initialising credentials from keytab : %s\n",LogTime(), PROGRAM, error_message(code));
		goto loop_end;
            }

            code = krb5_cc_initialize(kparam.context, kparam.cc, principal_list[i]);
            if (code)
            {
                fprintf(stderr, "%s| %s: Error while initializing memory caches : %s\n",LogTime(), PROGRAM, error_message(code));
		goto loop_end;
            }

	    code = krb5_cc_store_cred(kparam.context, kparam.cc, creds);
	    if (code)
	    {
	        if (margs->debug)
		    fprintf(stderr, "%s| %s: Error while storing credentials : %s\n",LogTime(), PROGRAM, error_message(code));
		goto loop_end;
    	    }

            if (creds->server)
               krb5_free_principal(kparam.context,creds->server);
#ifdef HAVE_HEIMDAL_KERBEROS
            service=malloc(strlen("krbtgt")+strlen(domain)+strlen(principal_list[i]->realm)+3);
            snprintf(service,strlen("krbtgt")+strlen(domain)+strlen(principal_list[i]->realm)+3,"krbtgt/%s@%s",domain,principal_list[i]->realm);
#else
            service=malloc(strlen("krbtgt")+strlen(domain)+strlen(krb5_princ_realm(kparam.context, principal_list[i])->data)+3);
            snprintf(service,strlen("krbtgt")+strlen(domain)+strlen(krb5_princ_realm(kparam.context, principal_list[i])->data)+3,"krbtgt/%s@%s",domain,krb5_princ_realm(kparam.context, principal_list[i])->data);
#endif
            code = krb5_parse_name(kparam.context,service,&creds->server);
            if (service)
               free(service);
	    if (code)
	    {
		fprintf(stderr, "%s| %s: Error while initialising TGT credentials : %s\n",LogTime(), PROGRAM, error_message(code));
		goto loop_end;
	    }

	    code = krb5_get_credentials(kparam.context, 0, kparam.cc, creds, &tgt_creds);
	    if (code) {
		if (margs->debug)
		    fprintf(stderr, "%s| %s: Error while getting tgt : %s\n",LogTime(), PROGRAM, error_message(code));
		goto loop_end;
	    } else {
		if (margs->debug)
		    fprintf(stderr, "%s| %s: Found trusted principal name: %s\n", LogTime(), PROGRAM, principal_name);
		break;
	    }

loop_end:
            if (principal_name) 
	        free(principal_name);
            principal_name=NULL;
	}
            
	if (tgt_creds)
	    krb5_free_creds(kparam.context,tgt_creds);
        tgt_creds=NULL;
	if (creds)
	    krb5_free_creds(kparam.context,creds);
        creds=NULL;
    }


    if (principal_name) {

	if (margs->debug)
	    fprintf(stderr, "%s| %s: Got principal name %s\n",LogTime(), PROGRAM, principal_name);
	/*
	 * build principal
	 */
	code = krb5_parse_name(kparam.context, principal_name, &principal);
	if (code)
	{
	    fprintf(stderr, "%s| %s: Error while parsing name %s : %s\n", LogTime(), PROGRAM, principal_name,error_message(code));
	    retval=1;
	    goto cleanup;
	}
  
	creds = malloc(sizeof(*creds));
	memset(creds, 0, sizeof(*creds));

	/*
	 * get credentials
	 */
#if HAVE_GET_INIT_CREDS_KEYTAB
        code = krb5_get_init_creds_keytab(kparam.context, creds, principal, keytab, 0, NULL, NULL);
#else
        service=malloc(strlen("krbtgt")+2*strlen(domain)+3);
        snprintf(service,strlen("krbtgt")+2*strlen(domain)+3,"krbtgt/%s@%s",domain,domain);
        creds->client=principal;
        code = krb5_parse_name(kparam.context,service,&creds->server);
        if (service)
           free(service);
        code = krb5_get_in_tkt_with_keytab(kparam.context, 0, NULL, NULL, NULL, keytab, NULL, creds, 0);
#endif
	if (code)
	{
	    fprintf(stderr, "%s| %s: Error while initialising credentials from keytab : %s\n",LogTime(), PROGRAM, error_message(code));
	    retval=1;
	    goto cleanup;
	}

        code = krb5_cc_initialize(kparam.context, kparam.cc, principal);
        if (code)
        {
            fprintf(stderr, "%s| %s: Error while initializing memory caches : %s\n",LogTime(), PROGRAM, error_message(code));
            retval=1;
            goto cleanup;
        }

	code = krb5_cc_store_cred(kparam.context, kparam.cc, creds);
	if (code) 
	{
	    fprintf(stderr, "%s| %s: Error while storing credentials : %s\n",LogTime(), PROGRAM, error_message(code));
	    retval=1;
	    goto cleanup;
	}
	if (margs->debug)
	    fprintf(stderr, "%s| %s: Stored credentials\n",LogTime(), PROGRAM);
    } else {
	if (margs->debug)
	    fprintf(stderr, "%s| %s: Got no principal name\n",LogTime(), PROGRAM);
	retval=1;
    }
 cleanup:
    if (keytab)
        krb5_kt_close(kparam.context, keytab);
    if (keytab_name)
	free(keytab_name);
    if (principal_name)
	free(principal_name);
    if (mem_cache)
	free(mem_cache);
    if (principal)
	krb5_free_principal(kparam.context,principal);
    for (i=0;i<nprinc;i++) {
        if (principal_list[i])
	    krb5_free_principal(kparam.context,principal_list[i]);
    }
    if (principal_list)
        free(principal_list);
    if (creds)
	krb5_free_creds(kparam.context,creds);

    return(retval);
}

