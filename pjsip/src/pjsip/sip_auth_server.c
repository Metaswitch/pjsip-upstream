/**
 * Some of the content of this file has been edited by Metaswitch, in the time
 * period from May 2013 to the present time.
*/

/* $Id: sip_auth_server.c 4214 2012-07-25 14:29:28Z nanang $ */
/* 
 * Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 * Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */

#include <pjsip/sip_auth.h>
#include <pjsip/sip_auth_parser.h>	/* just to get pjsip_DIGEST_STR */
#include <pjsip/sip_auth_msg.h>
#include <pjsip/sip_errno.h>
#include <pjsip/sip_transport.h>
#include <pj/string.h>
#include <pj/assert.h>


/*
 * Initialize server authorization session data structure to serve the 
 * specified realm and to use lookup_func function to look for the credential 
 * info. 
 */
PJ_DEF(pj_status_t) pjsip_auth_srv_init(  pj_pool_t *pool,
					  pjsip_auth_srv *auth_srv,
					  const pj_str_t *realm,
					  pjsip_auth_lookup_cred *lookup,
					  unsigned options )
{
    PJ_ASSERT_RETURN(pool && auth_srv && realm && lookup, PJ_EINVAL);

    pj_bzero(auth_srv, sizeof(*auth_srv));
    pj_strdup( pool, &auth_srv->realm, realm);
    auth_srv->lookup = lookup;
    auth_srv->is_proxy = (options & PJSIP_AUTH_SRV_IS_PROXY);

    return PJ_SUCCESS;
}

/*
 * Initialize server authorization session data structure to serve the 
 * specified realm and to use lookup_func function to look for the credential 
 * info. 
 */
PJ_DEF(pj_status_t) pjsip_auth_srv_init2(
				    pj_pool_t *pool,
				    pjsip_auth_srv *auth_srv,
				    const pjsip_auth_srv_init_param *param)
{
    PJ_ASSERT_RETURN(pool && auth_srv && param, PJ_EINVAL);

    pj_bzero(auth_srv, sizeof(*auth_srv));
    pj_strdup( pool, &auth_srv->realm, param->realm);
    auth_srv->lookup2 = param->lookup2;
    auth_srv->lookup3 = param->lookup3;
    auth_srv->is_proxy = (param->options & PJSIP_AUTH_SRV_IS_PROXY);

    return PJ_SUCCESS;
}


/* Verify incoming Authorization/Proxy-Authorization header against the 
 * specified credential.
 */
static pj_status_t pjsip_auth_verify( const pjsip_authorization_hdr *hdr,
				      const pj_str_t *method,
				      const pjsip_cred_info *cred_info )
{
    if (pj_stricmp(&hdr->scheme, &pjsip_DIGEST_STR) == 0) {
	char digest_buf[PJSIP_MD5STRLEN];
	pj_str_t digest;
	const pjsip_digest_credential *dig = &hdr->credential.digest;

	/* Check that username and realm match. 
	 * These checks should have been performed before entering this
	 * function.
	 */
	PJ_ASSERT_RETURN(pj_strcmp(&dig->username, &cred_info->username) == 0,
			 PJ_EINVALIDOP);
	PJ_ASSERT_RETURN(pj_strcmp(&dig->realm, &cred_info->realm) == 0,
			 PJ_EINVALIDOP);

	/* Prepare for our digest calculation. */
	digest.ptr = digest_buf;
	digest.slen = PJSIP_MD5STRLEN;

	/* Create digest for comparison. */
	pjsip_auth_create_digest(&digest, 
				 &hdr->credential.digest.nonce,
				 &hdr->credential.digest.nc, 
				 &hdr->credential.digest.cnonce,
				 &hdr->credential.digest.qop,
				 &hdr->credential.digest.uri,
				 &cred_info->realm,
				 cred_info, 
				 method );

	/* Compare digest. */
	return (pj_stricmp(&digest, &hdr->credential.digest.response) == 0) ?
	       PJ_SUCCESS : PJSIP_EAUTHINVALIDDIGEST;

    } else {
	pj_assert(!"Unsupported authentication scheme");
	return PJSIP_EINVALIDAUTHSCHEME;
    }
}


/*
 * Request the authorization server framework to verify the authorization 
 * information in the specified request in rdata.
 */
PJ_DEF(pj_status_t) pjsip_auth_srv_verify( pjsip_auth_srv *auth_srv,
					   pjsip_rx_data *rdata,
					   int *status_code)
{
  pjsip_auth_srv_verify2(auth_srv, rdata, status_code, NULL);
}

PJ_DEF(pj_status_t) pjsip_auth_srv_verify2( pjsip_auth_srv *auth_srv,
					    pjsip_rx_data *rdata,
					    int *status_code,
					    void *lookup_data)
{
  pjsip_auth_srv_verify3(auth_srv,
			 rdata->msg_info.msg,
			 rdata->tp_info.pool,
			 status_code,
			 lookup_data);
}

PJ_DEF(pj_status_t) pjsip_auth_srv_verify3( pjsip_auth_srv *auth_srv,
					    pjsip_msg *msg,
					    pj_pool_t *pool,
					    int *status_code,
					    void *lookup_data)
{
    pjsip_authorization_hdr *h_auth;
    pjsip_hdr_e htype;
    pj_str_t realm;
    pj_str_t acc_name;
    pjsip_cred_info cred_info;
    pj_bool_t invalid_auth_scheme = PJ_FALSE;
    pj_bool_t forbidden = PJ_FALSE;
    pj_bool_t succeeded = PJ_FALSE;
    pj_status_t status;

    PJ_ASSERT_RETURN(auth_srv && msg, PJ_EINVAL);
    PJ_ASSERT_RETURN(msg->type == PJSIP_REQUEST_MSG, PJSIP_ENOTREQUESTMSG);

    htype = auth_srv->is_proxy ? PJSIP_H_PROXY_AUTHORIZATION : 
				 PJSIP_H_AUTHORIZATION;

    /* Find authorization header(s) for our realm and process them. */
    h_auth = (pjsip_authorization_hdr*) pjsip_msg_find_hdr(msg, htype, NULL);
    while (h_auth) {
	realm = h_auth->credential.common.realm;
	if (((auth_srv->realm.slen == 1) &&
             (auth_srv->realm.ptr[0] == '*')) ||
            (!pj_stricmp(&realm, &auth_srv->realm))) {

	    /* Check authorization scheme. */
	    if (pj_stricmp(&h_auth->scheme, &pjsip_DIGEST_STR) == 0) {
		acc_name = h_auth->credential.digest.username;

		    pjsip_auth_lookup_cred_param param;
		    pj_bzero(&param, sizeof(param));
		    param.realm = realm;
		    param.acc_name = acc_name;
		    param.msg = msg;

		/* Find the credential information for the account. */
		if (auth_srv->lookup3) {
		    status = (*auth_srv->lookup3)(pool, &param,
						  &cred_info, lookup_data);
		/* Find the credential information for the account. */
		} else if (auth_srv->lookup2) {
		    status = (*auth_srv->lookup2)(pool, &param,
						  &cred_info);
		} else {
		    status = (*auth_srv->lookup)(pool, &realm,
						 &acc_name, &cred_info);
		}

		/* Authenticate with the specified credential. */
		if (status == PJ_SUCCESS) {
		    status = pjsip_auth_verify(h_auth,
					       &msg->line.req.method.name,
					       &cred_info);
		}

		if (status == PJ_SUCCESS) {
		    succeeded = PJ_TRUE;
		    break;
		} else {
		    if (status == PJSIP_EAUTHNOAUTH)
		        invalid_auth_scheme = PJ_TRUE;
		    else
		        forbidden = PJ_TRUE;
		}
	    } else {
                invalid_auth_scheme = PJ_TRUE;
	    }
        }

	h_auth = h_auth->next;
	if (h_auth == (void*) &msg->hdr) {
	    h_auth = NULL;
	    break;
	}

	h_auth=(pjsip_authorization_hdr*)pjsip_msg_find_hdr(msg,htype,h_auth);
    }

    /* Work out the status code and return code.  Because there may have been
     * multiple authorization headers, we have an order of precedence:
     * Success > forbidden > invalid auth scheme > no auth
     */
    *status_code = succeeded ? 200 :
                   forbidden ? PJSIP_SC_FORBIDDEN :
                   auth_srv->is_proxy ? 407 : 401;
    return succeeded ? PJ_SUCCESS :
	   forbidden ? status :
	   invalid_auth_scheme ? PJSIP_EINVALIDAUTHSCHEME :
	   PJSIP_EAUTHNOAUTH;
}


/*
 * Add authentication challenge headers to the outgoing response in tdata. 
 * Application may specify its customized nonce and opaque for the challenge, 
 * or can leave the value to NULL to make the function fills them in with 
 * random characters.
 */
PJ_DEF(pj_status_t) pjsip_auth_srv_challenge(  pjsip_auth_srv *auth_srv,
					       const pj_str_t *qop,
					       const pj_str_t *nonce,
					       const pj_str_t *opaque,
					       pj_bool_t stale,
					       pjsip_tx_data *tdata)
{
    pjsip_www_authenticate_hdr *hdr;
    char nonce_buf[16];
    pj_str_t random;

    PJ_ASSERT_RETURN( auth_srv && tdata, PJ_EINVAL );

    random.ptr = nonce_buf;
    random.slen = sizeof(nonce_buf);

    /* Create the header. */
    if (auth_srv->is_proxy)
	hdr = pjsip_proxy_authenticate_hdr_create(tdata->pool);
    else
	hdr = pjsip_www_authenticate_hdr_create(tdata->pool);

    /* Initialize header. 
     * Note: only support digest authentication now.
     */
    hdr->scheme = pjsip_DIGEST_STR;
    hdr->challenge.digest.algorithm = pjsip_MD5_STR;
    if (nonce) {
	pj_strdup(tdata->pool, &hdr->challenge.digest.nonce, nonce);
    } else {
	pj_create_random_string(nonce_buf, sizeof(nonce_buf));
	pj_strdup(tdata->pool, &hdr->challenge.digest.nonce, &random);
    }
    if (opaque) {
	pj_strdup(tdata->pool, &hdr->challenge.digest.opaque, opaque);
    } else {
	pj_create_random_string(nonce_buf, sizeof(nonce_buf));
	pj_strdup(tdata->pool, &hdr->challenge.digest.opaque, &random);
    }
    if (qop) {
	pj_strdup(tdata->pool, &hdr->challenge.digest.qop, qop);
    } else {
	hdr->challenge.digest.qop.slen = 0;
    }
    pj_strdup(tdata->pool, &hdr->challenge.digest.realm, &auth_srv->realm);
    hdr->challenge.digest.stale = stale;

    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)hdr);

    return PJ_SUCCESS;
}
