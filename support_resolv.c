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
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <arpa/nameser.h>

#include "support.h"

void nsError(int error, char* server);
static int compare_hosts(struct hstruct *h1, struct hstruct *h2);
static void swap(struct hstruct *a, struct hstruct *b );
static void sort(struct hstruct *array, int nitems, int (*cmp)(struct hstruct *,struct hstruct *),int begin, int end);
static void msort(struct hstruct *array, size_t nitems, int (*cmp)(struct hstruct *,struct hstruct *));

/*
  http://www.ietf.org/rfc/rfc1035.txt
*/
/*
  The header contains the following fields:

  1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      ID                       |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    QDCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    ANCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    NSCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    ARCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  where:

  ID              A 16 bit identifier assigned by the program that
  generates any kind of query.  This identifier is copied
  the corresponding reply and can be used by the requester
  to match up replies to outstanding queries.

  QR              A one bit field that specifies whether this message is a
  query (0), or a response (1).

  OPCODE          A four bit field that specifies kind of query in this
  message.  This value is set by the originator of a query
  and copied into the response.  The values are:

  0               a standard query (QUERY)

  1               an inverse query (IQUERY)

  2               a server status request (STATUS)

  3-15            reserved for future use

  AA              Authoritative Answer - this bit is valid in responses,
  and specifies that the responding name server is an
  authority for the domain name in question section.

  Note that the contents of the answer section may have
  multiple owner names because of aliases.  The AA bit
  corresponds to the name which matches the query name, or
  the first owner name in the answer section.

  TC              TrunCation - specifies that this message was truncated
  due to length greater than that permitted on the
  transmission channel.

  RD              Recursion Desired - this bit may be set in a query and
  is copied into the response.  If RD is set, it directs
  the name server to pursue the query recursively.
  Recursive query support is optional.

  RA              Recursion Available - this be is set or cleared in a
  response, and denotes whether recursive query support is
  available in the name server.

  Z               Reserved for future use.  Must be zero in all queries
  and responses.

  RCODE           Response code - this 4 bit field is set as part of
  responses.  The values have the following
  interpretation:

  0               No error condition

  1               Format error - The name server was
  unable to interpret the query.

  2               Server failure - The name server was
  unable to process this query due to a
  problem with the name server.

  3               Name Error - Meaningful only for
  responses from an authoritative name
  server, this code signifies that the
  domain name referenced in the query does
  not exist.

  4               Not Implemented - The name server does
  not support the requested kind of query.

  5               Refused - The name server refuses to
  perform the specified operation for
  policy reasons.  For example, a name
  server may not wish to provide the
  information to the particular requester,
  or a name server may not wish to perform
  a particular operation (e.g., zone
  transfer) for particular data.

  6-15            Reserved for future use.

  QDCOUNT         an unsigned 16 bit integer specifying the number of
  entries in the question section.

  ANCOUNT         an unsigned 16 bit integer specifying the number of
  resource records in the answer section.

  NSCOUNT         an unsigned 16 bit integer specifying the number of name
  server resource records in the authority records
  section.

  ARCOUNT         an unsigned 16 bit integer specifying the number of
  resource records in the additional records section.

  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                                               |
  /                    QNAME                      /
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
  |                    QTYPE                      |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
  |                    QCLASS                     | 
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
  QNAME is a variable length field to fit the hostname 
  QCLASS should be 1 since we are on internet 
  QTYPE determines what you want to know ; ipv4 address,mx etc. 

  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
  |                                               |
  /                                               / 
  /                     NAME                      / 
  |                                               | 
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     TYPE                      |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
  |                     CLASS                     | 
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
  |                     TTL                       |
  |                                               |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
  |                  RDLENGTH                     | 
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
  /                     RDATA                     /
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 

  NAME and RDATA are variable length field 
  Type field tells how RDATA relates to NAME. e.g. if TYPE is 1 then RDATA contains the ipv4 address of the NAME. 

*/
/*
  http://www.ietf.org/rfc/rfc2782.txt

  Here is the format of the SRV RR, whose DNS type code is 33:

  _Service._Proto.Name TTL Class SRV Priority Weight Port Target


  Service
  The symbolic name of the desired service, as defined in Assigned
  Numbers [STD 2] or locally.  An underscore (_) is prepended to
  the service identifier to avoid collisions with DNS labels that
  occur in nature.
  Some widely used services, notably POP, don't have a single
  universal name.  If Assigned Numbers names the service
  indicated, that name is the only name which is legal for SRV
  lookups.  The Service is case insensitive.

  Proto
  The symbolic name of the desired protocol, with an underscore
  (_) prepended to prevent collisions with DNS labels that occur
  in nature.  _TCP and _UDP are at present the most useful values
  for this field, though any name defined by Assigned Numbers or
  locally may be used (as for Service).  The Proto is case
  insensitive.

  Name
  The domain this RR refers to.  The SRV RR is unique in that the
  name one searches for is not this name; the example near the end
  shows this clearly.

  TTL
  Standard DNS meaning [RFC 1035].

  Class
  Standard DNS meaning [RFC 1035].   SRV records occur in the IN
  Class.

  Priority
  The priority of this target host.  A client MUST attempt to
  contact the target host with the lowest-numbered priority it can
  reach; target hosts with the same priority SHOULD be tried in an
  order defined by the weight field.  The range is 0-65535.  This
  is a 16 bit unsigned integer in network byte order.

  Weight
  A server selection mechanism.  The weight field specifies a
  relative weight for entries with the same priority. Larger
  weights SHOULD be given a proportionately higher probability of
  being selected. The range of this number is 0-65535.  This is a
  16 bit unsigned integer in network byte order.  Domain
  administrators SHOULD use Weight 0 when there isn't any server
  selection to do, to make the RR easier to read for humans (less
  noisy).  In the presence of records containing weights greater
  than 0, records with weight 0 should have a very small chance of
  being selected.

  In the absence of a protocol whose specification calls for the
  use of other weighting information, a client arranges the SRV
  RRs of the same Priority in the order in which target hosts,
  specified by the SRV RRs, will be contacted. The following
  algorithm SHOULD be used to order the SRV RRs of the same
  priority:

  To select a target to be contacted next, arrange all SRV RRs
  (that have not been ordered yet) in any order, except that all
  those with weight 0 are placed at the beginning of the list.

  Compute the sum of the weights of those RRs, and with each RR
  associate the running sum in the selected order. Then choose a
  uniform random number between 0 and the sum computed
  (inclusive), and select the RR whose running sum value is the
  first in the selected order which is greater than or equal to
  the random number selected. The target host specified in the
  selected SRV RR is the next one to be contacted by the client.
  Remove this SRV RR from the set of the unordered SRV RRs and
  apply the described algorithm to the unordered SRV RRs to select
  the next target host.  Continue the ordering process until there
  are no unordered SRV RRs.  This process is repeated for each
  Priority.

  Port
  The port on this target host of this service.  The range is 0-
  65535.  This is a 16 bit unsigned integer in network byte order.
  This is often as specified in Assigned Numbers but need not be.

  Target
  The domain name of the target host.  There MUST be one or more
  address records for this name, the name MUST NOT be an alias (in
  the sense of RFC 1034 or RFC 2181).  Implementors are urged, but
  not required, to return the address record(s) in the Additional
  Data section.  Unless and until permitted by future standards
  action, name compression is not to be used for this field.

  A Target of "." means that the service is decidedly not
  available at this domain.


*/
void nsError(int error, char* service) {
  switch (error) {
  case HOST_NOT_FOUND:
    fprintf(stderr,"%s| %s: res_search: Unknown service record: %s\n",LogTime(), PROGRAM,service);
    break;
  case NO_DATA:
    fprintf(stderr,"%s| %s: res_search: No SRV record for %s\n",LogTime(), PROGRAM,service);
    break;
  case TRY_AGAIN:
    fprintf(stderr,"%s| %s: res_search: No response for SRV query\n",LogTime(), PROGRAM);
    break;
  default:
    fprintf(stderr,"%s| %s: res_search: Unexpected error: %s\n",LogTime(), PROGRAM,strerror(error));
  }
}

static void swap(struct hstruct *a, struct hstruct *b ) {
  struct hstruct c;

  c.host=a->host;
  c.priority=a->priority;
  c.weight=a->weight;
  a->host=b->host;
  a->priority=b->priority;
  a->weight=b->weight;
  b->host=c.host;
  b->priority=c.priority;
  b->weight=c.weight;
}

static void sort(struct hstruct *array, int nitems, int (*cmp)(struct hstruct *,struct hstruct *),int begin, int end) {
  if (end > begin) {
    int pivot=begin;
    int l = begin+1;
    int r = end;
    while(l < r) {
      if (cmp(&array[l],&array[pivot]) <= 0) {
	l += 1;
      } else {
	r -= 1;
	swap(&array[l], &array[r]);
      }
    }
    l -= 1;
    swap(&array[begin], &array[l]);
    sort(array, nitems, cmp, begin, l);
    sort(array, nitems, cmp, r, end);
  }
}

static void msort(struct hstruct *array, size_t nitems, int (*cmp)(struct hstruct *,struct hstruct *)) {
  sort(array, nitems, cmp, 0, nitems-1);
}

static int compare_hosts(struct hstruct *host1, struct hstruct *host2) {
  /*

  The comparison function must return an integer less than,  equal  to,
  or  greater  than  zero  if  the  first  argument is considered to be
  respectively less than, equal to, or greater than the second.
  */
  if ( (host1->priority < host2->priority ) &&  (host1->priority != -1) ) 
    return -1;
  if ( (host1->priority < host2->priority ) &&  (host1->priority == -1) ) 
    return 1;
  if ( (host1->priority > host2->priority ) &&  (host2->priority != -1) ) 
    return 1;
  if ( (host1->priority > host2->priority ) &&  (host2->priority == -1) ) 
    return -1;
  if ( host1->priority == host2->priority ) {
    if ( host1->weight > host2->weight )
      return -1;
    if ( host1->weight < host2->weight )
      return 1;
  }
  return 0;
}

int free_hostname_list(struct hstruct **hlist,int nhosts) {
  struct hstruct *hp=NULL;
  int i;

  hp=*hlist;
  for (i=0;i<nhosts;i++) {
    if (hp[i].host)
      free(hp[i].host);
    hp[i].host=NULL;
  }


  if (hp)
    free(hp);
  hp=NULL;
  *hlist=hp;
  return 0;
}

int get_hostname_list(struct main_args *margs, struct hstruct **hlist, int nhosts, char *name) {
  char  host[sysconf(_SC_HOST_NAME_MAX)];
  struct addrinfo *hres=NULL, *hres_list;
  int rc,count;
  struct hstruct *hp=NULL;

  if (!name)
    return(nhosts);

  hp=*hlist;

  rc = getaddrinfo(name,NULL,NULL,&hres);
  if (rc != 0) {
    fprintf(stderr, "%s| %s: Error while resolving hostname with getaddrinfo: %s\n",LogTime(), PROGRAM,gai_strerror(rc));
    return(nhosts);
  }
  hres_list=hres;
  count=0;
  while (hres_list) {
    count++;
    hres_list=hres_list->ai_next;
  }
  hres_list=hres;
  count = 0;
  while (hres_list) {
    rc = getnameinfo (hres_list->ai_addr, hres_list->ai_addrlen,host, sizeof (host), NULL, 0, 0);
    if (rc != 0) {
      fprintf(stderr, "%s| %s: Error while resolving ip address with getnameinfo: %s\n",LogTime(), PROGRAM,gai_strerror(rc));
      freeaddrinfo(hres);
      *hlist=hp;
      return(nhosts);
    }
    count++;
    if (margs->debug)
      fprintf(stderr, "%s| %s: Resolved address %d of %s to %s\n",LogTime(), PROGRAM, count, name, host);

    hp=realloc(hp,sizeof(struct hstruct)*(nhosts+1));
    hp[nhosts].host=strdup(host);
    hp[nhosts].port=-1;
    hp[nhosts].priority=-1;
    hp[nhosts].weight=-1;
    nhosts++;
          
    hres_list=hres_list->ai_next;
  }

  freeaddrinfo(hres);
  *hlist=hp;
  return(nhosts);
}

int get_ldap_hostname_list(struct main_args *margs, struct hstruct **hlist, int nh, char* domain) {

  char name[sysconf(_SC_HOST_NAME_MAX)];
  char host[NS_MAXDNAME];
  char *service=NULL;
  struct hstruct *hp=NULL; 
  struct lsstruct *ls=NULL;
  int nhosts=0;
  int size; 
  int type, rdlength;
  int priority, weight, port;
  int len,olen;
  int i,j,k;
  u_char *buffer=NULL;
  u_char *p;

  ls = margs->lservs;
  while(ls) {
    if (margs->debug)
      fprintf(stderr,"%s| %s: Ldap server loop: lserver@domain %s@%s\n",LogTime(), PROGRAM,ls->lserver,ls->domain);
    if (ls->domain && !strcasecmp(ls->domain,domain)) {
      if (margs->debug)
        fprintf(stderr,"%s| %s: Found lserver@domain %s@%s\n",LogTime(), PROGRAM,ls->lserver,ls->domain);
       hp = realloc(hp, sizeof(struct hstruct) * (nhosts + 1));
       hp[nhosts].host      = strdup(ls->lserver);
       hp[nhosts].port      = -1;
       hp[nhosts].priority  = -2;
       hp[nhosts].weight    = -2;
       nhosts++;
    }
    ls = ls->next;
  }
  /* found ldap servers in predefined list -> exit */
  if (nhosts > 0) 
     goto cleanup;

  if (margs->ssl) {
    service=malloc(strlen("_ldaps._tcp.")+strlen(domain)+1);
    strcpy(service,"_ldaps._tcp.");
  } else {
    service=malloc(strlen("_ldap._tcp.")+strlen(domain)+1);
    strcpy(service,"_ldap._tcp.");
  }
  strcat(service,domain);

#ifndef PACKETSZ_MULT
/* 
 * It seems Solaris doesn't give back the real length back when res_search uses a to small buffer
 * Set a bigger one here
 */
#define PACKETSZ_MULT 10
#endif

  hp=*hlist;
  buffer=malloc(PACKETSZ_MULT*NS_PACKETSZ);
  if ((len = res_search(service, ns_c_in, ns_t_srv, (u_char *)buffer, PACKETSZ_MULT*NS_PACKETSZ))<0) {
    fprintf(stderr,"%s| %s: Error while resolving service record %s with res_search\n",LogTime(), PROGRAM,service); 
    nsError(h_errno,service);
    if (margs->ssl) {
      free(service);
      service=malloc(strlen("_ldap._tcp.")+strlen(domain)+1);
      strcpy(service,"_ldap._tcp.");
      strcat(service,domain);
      if ((len = res_search(service, ns_c_in, ns_t_srv, (u_char *)buffer, PACKETSZ_MULT*NS_PACKETSZ))<0) {
        fprintf(stderr,"%s| %s: Error while resolving service record %s with res_search\n",LogTime(), PROGRAM,service);
        nsError(h_errno,service);
        goto cleanup;
      }
    } else {
      goto cleanup;
    }
  }
  if (len > PACKETSZ_MULT*NS_PACKETSZ) {
    olen=len;
    buffer=realloc(buffer,len);
    if ((len = res_search(service, ns_c_in, ns_t_srv, (u_char *)buffer, len))<0) {
      fprintf(stderr,"%s| %s: Error while resolving service record %s with res_search\n",LogTime(), PROGRAM,service); 
      nsError(h_errno,service);
      goto cleanup;
    }
    if (len > olen) {
      fprintf(stderr,"%s| %s: Reply to big: buffer: %d reply length: %d\n",LogTime(), PROGRAM,olen,len); 
      goto cleanup;
    }
  }
    
  p = buffer;
  p += 6*NS_INT16SZ; /* Header(6*16bit) = id + flags + 4*section count */
  if ( p > buffer+len ) {
    fprintf(stderr,"%s| %s: Message to small: %d < header size\n",LogTime(), PROGRAM,len); 
    goto cleanup;
  }
    
  if ( (size=dn_expand(buffer,buffer+len,p,name,sysconf(_SC_HOST_NAME_MAX))) < 0) {
    fprintf(stderr,"%s| %s: Error while expanding query name with dn_expand:  %s\n",LogTime(), PROGRAM,strerror(errno));
    goto cleanup;
  } 
  p += size;                     /* Query name */
  p += 2*NS_INT16SZ;             /* Query type + class (2*16bit)*/ 
  if ( p > buffer+len ) {
    fprintf(stderr,"%s| %s: Message to small: %d < header + query name,type,class \n",LogTime(), PROGRAM,len); 
    goto cleanup;
  }

  while ( p < buffer+len ) {
    if ( (size=dn_expand(buffer,buffer+len,p,name,sysconf(_SC_HOST_NAME_MAX))) < 0) {
      fprintf(stderr,"%s| %s: Error while expanding answer name with dn_expand:  %s\n",LogTime(), PROGRAM,strerror(errno));
      goto cleanup;
    } 
    p += size;                /* Resource Record name */
    if ( p > buffer+len ) {
      fprintf(stderr,"%s| %s: Message to small: %d < header + query name,type,class + answer name\n",LogTime(), PROGRAM,len); 
      goto cleanup;
    }
    NS_GET16(type,p); /* RR type (16bit) */
    p += NS_INT16SZ + NS_INT32SZ; /* RR class + ttl (16bit+32bit) */
    if ( p > buffer+len ) {
      fprintf(stderr,"%s| %s: Message to small: %d < header + query name,type,class + answer name + RR type,class,ttl\n",LogTime(), PROGRAM,len); 
      goto cleanup;
    }
    NS_GET16(rdlength,p);         /* RR data length (16bit) */  

    if ( type  == ns_t_srv ) { /* SRV record */
      if ( p > buffer+len ) {
	fprintf(stderr,"%s| %s: Message to small: %d < header + query name,type,class + answer name + RR type,class,ttl + RR data length\n",LogTime(), PROGRAM,len); 
	goto cleanup;
      }
      NS_GET16(priority, p);    /* Priority (16bit) */
      if ( p > buffer+len ) {
	fprintf(stderr,"%s| %s: Message to small: %d <  SRV RR + priority\n",LogTime(), PROGRAM,len); 
	goto cleanup;
      }
      NS_GET16(weight,p);      /* Weight (16bit) */
      if ( p > buffer+len ) {
	fprintf(stderr,"%s| %s: Message to small: %d <  SRV RR + priority + weight\n",LogTime(), PROGRAM,len); 
	goto cleanup;
      }
      NS_GET16(port,p);       /* Port (16bit) */
      if ( p > buffer+len ) {
	fprintf(stderr,"%s| %s: Message to small: %d <  SRV RR + priority + weight + port\n",LogTime(), PROGRAM,len); 
	goto cleanup;
      }
      if ( (size=dn_expand(buffer,buffer+len,p,host,NS_MAXDNAME)) < 0) {
	fprintf(stderr,"%s| %s: Error while expanding SRV RR name with dn_expand:  %s\n",LogTime(), PROGRAM,strerror(errno));
	goto cleanup;
      } 
      if (margs->debug)
	fprintf(stderr, "%s| %s: Resolved SRV %s record to %s\n",LogTime(), PROGRAM, service, host);
      hp=realloc(hp,sizeof(struct hstruct)*(nh+1));
      hp[nh].host=strdup(host);
      hp[nh].port=port;
      hp[nh].priority=priority;
      hp[nh].weight=weight;
      nh++;
      p += size;
    } else {
      p += rdlength;
    }
    if ( p > buffer+len ) {
      fprintf(stderr,"%s| %s: Message to small: %d <  SRV RR + priority + weight + port + name\n",LogTime(), PROGRAM,len); 
      goto cleanup;
    }
  }
  if ( p != buffer+len ) {
#if (SIZEOF_LONG == 8)
    fprintf(stderr,"%s| %s: Inconsistence message length: %ld!=0\n",LogTime(), PROGRAM,buffer+len-p);
#else
    fprintf(stderr,"%s| %s: Inconsistence message length: %d!=0\n",LogTime(), PROGRAM,buffer+len-p); 
#endif
    goto cleanup;
  }

  nhosts = get_hostname_list(margs,&hp,nh,domain);

  if (margs->debug)
    fprintf(stderr, "%s| %s: Adding %s to list\n",LogTime(), PROGRAM, domain);

  hp = realloc(hp, sizeof(struct hstruct) * (nhosts + 1));
  hp[nhosts].host      = strdup(domain);
  hp[nhosts].port      = -1;
  hp[nhosts].priority  = -2;
  hp[nhosts].weight    = -2;
  nhosts++;

  /* Remove duplicates */
  for (i=0;i<nhosts;i++) {
    for (j=i+1;j<nhosts;j++) {
      if (!strcasecmp(hp[i].host,hp[j].host)) {
	if (hp[i].port == hp[j].port ||
	    (hp[i].port == -1 && hp[j].port == 389) ||
	    (hp[i].port == 389 && hp[j].port == -1) ) {
	  free(hp[j].host);
	  for (k=j+1;k<nhosts;k++) {
	    hp[k-1].host=hp[k].host;
	    hp[k-1].port=hp[k].port;
	    hp[k-1].priority=hp[k].priority;
	    hp[k-1].weight=hp[k].weight;
	  }
	  j--;
	  nhosts--;
	  hp=realloc(hp,sizeof(struct hstruct)*(nhosts+1));
	}
      }
    }
  }

  /* Sort by Priority / Weight */
  msort(hp,nhosts,compare_hosts);

  if (margs->debug) {
    fprintf(stderr, "%s| %s: Sorted ldap server names for domain %s:\n",LogTime(), PROGRAM,domain);
    for (i=0;i<nhosts;i++) {
      fprintf(stderr, "%s| %s: Host: %s Port: %d Priority: %d Weight: %d\n",LogTime(), PROGRAM,hp[i].host,hp[i].port,hp[i].priority,hp[i].weight);
    }
  }
 
  if (buffer)
    free(buffer);
  if (service)
    free(service);
  *hlist=hp;
  return(nhosts);

 cleanup:
  if (buffer)
    free(buffer);
  if (service)
    free(service);
  *hlist=hp;
  return(nhosts);
}
