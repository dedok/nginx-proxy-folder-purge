
/*
 * (C)
 */

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_masks_storage.h>

#ifndef nginx_version
#     error This module cannot be build against an unknown nginx version.
#endif


typedef struct {
    ngx_flag_t                    enable;
    ngx_str_t                     method;
    ngx_array_t                  *access;   /* array of ngx_in_cidr_t */
    ngx_array_t                  *access6;  /* array of ngx_in6_cidr_t */
} ngx_http_folder_purge_conf_t;

typedef struct {
    ngx_http_folder_purge_conf_t   proxy;

    ngx_http_folder_purge_conf_t  *conf;
    ngx_http_handler_pt           handler;
    ngx_http_handler_pt           original_handler;
} ngx_http_folder_purge_loc_conf_t;


char *ngx_http_proxy_folder_purge_conf(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
ngx_int_t ngx_http_proxy_folder_purge_handler(ngx_http_request_t *r);

ngx_int_t ngx_http_folder_purge_access_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_folder_purge_access(ngx_array_t *a, ngx_array_t *a6,
        struct sockaddr *s);

char *ngx_http_folder_purge_conf(ngx_conf_t *cf,
        ngx_http_folder_purge_conf_t *cpcf);
void *ngx_http_folder_purge_create_loc_conf(ngx_conf_t *cf);
char *ngx_http_folder_purge_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_command_t  ngx_http_folder_purge_module_commands[] = {

    { ngx_string("proxy_folder_purge"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_proxy_folder_purge_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_folder_purge_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_folder_purge_create_loc_conf,  /* create location configuration */
    ngx_http_folder_purge_merge_loc_conf    /* merge location configuration */
};

ngx_module_t  ngx_http_proxy_folder_purge = {
    NGX_MODULE_V1,
    &ngx_http_folder_purge_module_ctx,      /* module context */
    ngx_http_folder_purge_module_commands,  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

extern ngx_module_t  ngx_http_proxy_module;

typedef struct {
    ngx_str_t                      key_start;
    ngx_str_t                      schema;
    ngx_str_t                      host_header;
    ngx_str_t                      port;
    ngx_str_t                      uri;
} ngx_http_proxy_vars_t;

#  if (nginx_version >= 1007009)

typedef struct {
    ngx_array_t                    caches;  /* ngx_http_file_cache_t * */
} ngx_http_proxy_main_conf_t;

#  endif /* nginx_version >= 1007009 */

#  if (nginx_version >= 1007008)

typedef struct {
    ngx_array_t                   *flushes;
    ngx_array_t                   *lengths;
    ngx_array_t                   *values;
    ngx_hash_t                     hash;
} ngx_http_proxy_headers_t;

#  endif /* nginx_version >= 1007008 */

typedef struct {
    ngx_http_upstream_conf_t       upstream;

#  if (nginx_version >= 1007008)
    ngx_array_t                   *body_flushes;
    ngx_array_t                   *body_lengths;
    ngx_array_t                   *body_values;
    ngx_str_t                      body_source;

    ngx_http_proxy_headers_t       headers;
    ngx_http_proxy_headers_t       headers_cache;
#  else
    ngx_array_t                   *flushes;
    ngx_array_t                   *body_set_len;
    ngx_array_t                   *body_set;
    ngx_array_t                   *headers_set_len;
    ngx_array_t                   *headers_set;
    ngx_hash_t                     headers_set_hash;
#  endif /* nginx_version >= 1007008 */

    ngx_array_t                   *headers_source;
#  if (nginx_version < 8040)
    ngx_array_t                   *headers_names;
#  endif /* nginx_version < 8040 */

    ngx_array_t                   *proxy_lengths;
    ngx_array_t                   *proxy_values;

    ngx_array_t                   *redirects;
#  if (nginx_version >= 1001015)
    ngx_array_t                   *cookie_domains;
    ngx_array_t                   *cookie_paths;
#  endif /* nginx_version >= 1001015 */

#  if (nginx_version < 1007008)
    ngx_str_t                      body_source;
#  endif /* nginx_version < 1007008 */

#  if (nginx_version >= 1011006)
    ngx_http_complex_value_t      *method;
#  else
    ngx_str_t                      method;
#  endif /* nginx_version >= 1011006 */

    ngx_str_t                      location;
    ngx_str_t                      url;

    ngx_http_complex_value_t       cache_key;

    ngx_http_proxy_vars_t          vars;

    ngx_flag_t                     redirect;

#  if (nginx_version >= 1001004)
    ngx_uint_t                     http_version;
#  endif /* nginx_version >= 1001004 */

    ngx_uint_t                     headers_hash_max_size;
    ngx_uint_t                     headers_hash_bucket_size;

#  if (NGX_HTTP_SSL)
#    if (nginx_version >= 1005006)
    ngx_uint_t                     ssl;
    ngx_uint_t                     ssl_protocols;
    ngx_str_t                      ssl_ciphers;
#    endif /* nginx_version >= 1005006 */
#    if (nginx_version >= 1007000)
    ngx_uint_t                     ssl_verify_depth;
    ngx_str_t                      ssl_trusted_certificate;
    ngx_str_t                      ssl_crl;
#    endif /* nginx_version >= 1007000 */
#    if (nginx_version >= 1007008)
    ngx_str_t                      ssl_certificate;
    ngx_str_t                      ssl_certificate_key;
    ngx_array_t                   *ssl_passwords;
#    endif /* nginx_version >= 1007008 */
#  endif
} ngx_http_proxy_loc_conf_t;


char *
ngx_http_proxy_folder_purge_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_folder_purge_loc_conf_t   *cplcf;

    cplcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_folder_purge);

    /* check for duplicates / collisions */
    if (cplcf->proxy.enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    return ngx_http_folder_purge_conf(cf, &cplcf->proxy);
}


ngx_int_t
ngx_http_proxy_folder_purge_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_str_t                 content_type;
    ngx_http_complex_value_t  cv;

#if (NGX_HAVE_FILE_AIO)
    if (r->aio) {
        goto exit;
    }
#endif /** NGX_HAVE_FILE_AIO */

#if defined (NGX_DEBUG)
    if (ngx_http_folder_dump(r) == NGX_MASKS_STORAGE_OK) {
        (void) ngx_http_folder_send_dump_handler(r);
        goto exit;
    }

    if (ngx_http_folder_flush(r) == NGX_MASKS_STORAGE_OK) {
        (void) ngx_http_folder_send_flush_handler(r);
        goto exit;
    }
#endif /* (NGX_DEBUG) */

    ngx_str_set(&content_type, "plain/text");
    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    rc = ngx_http_folder_cache_purge(r);

#  if (nginx_version >= 8011)
    r->main->count++;
#  endif

    switch (rc) {

        case NGX_MASKS_STORAGE_OK:
            ngx_str_set(&cv.value, "{\"status\": \"ok\"}");
            r->write_event_handler = ngx_http_request_empty_handler;
            rc = ngx_http_send_response(r, NGX_HTTP_OK, &content_type, &cv);
            if (rc == NGX_OK) {
                rc = NGX_HTTP_OK;

            } else {
                ngx_str_set(&cv.value, "{\"status\": \"failed\"}");
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;

            }
            /** rc ~== NGX_HTTP_OK */
            break;

        case NGX_MASKS_STORAGE_LIMIT_REACHED:
            rc = NGX_HTTP_TOO_MANY_REQUESTS;
            break;

        case NGX_MASKS_STORAGE_BAD_REQUEST:
            rc = NGX_HTTP_BAD_REQUEST;
            break;

        case NGX_MASKS_STORAGE_SERVICE_DISABLE:
            rc = NGX_HTTP_SERVICE_UNAVAILABLE;
            break;

        case NGX_MASKS_STORAGE_FAIL:
        case NGX_MASKS_STORAGE_DENY:
        default:
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "masks_storage: unknown response=%d for \"%V\"",
                rc, &r->uri);
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
    }

    ngx_http_finalize_request(r, rc);

#if (NGX_HAVE_FILE_AIO || NGX_DEBUG)
exit:
#endif /** NGX_HAVE_FILE_AIO || NGX_DEBUG */

    return NGX_DONE;
}


ngx_int_t
ngx_http_folder_purge_access_handler(ngx_http_request_t *r)
{
    ngx_http_folder_purge_loc_conf_t   *cplcf;

    cplcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_folder_purge);

    if (!cplcf || !cplcf->conf) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->method_name.len != cplcf->conf->method.len
        || (ngx_strncmp(r->method_name.data, cplcf->conf->method.data,
                        r->method_name.len)))
    {
        return cplcf->original_handler(r);
    }

    if ((cplcf->conf->access || cplcf->conf->access6)
         && ngx_http_folder_purge_access(cplcf->conf->access,
                                        cplcf->conf->access6,
                                        r->connection->sockaddr) != NGX_OK)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    if (cplcf->handler == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    return cplcf->handler(r);
}


ngx_int_t
ngx_http_folder_purge_access(ngx_array_t *access, ngx_array_t *access6,
    struct sockaddr *s)
{
    in_addr_t         inaddr;
    ngx_in_cidr_t    *a;
    ngx_uint_t        i;
# if (NGX_HAVE_INET6)
    struct in6_addr  *inaddr6;
    ngx_in6_cidr_t   *a6;
    u_char           *p;
    ngx_uint_t        n;
# endif /* NGX_HAVE_INET6 */

    switch (s->sa_family) {
    case AF_INET:
        if (access == NULL) {
            return NGX_DECLINED;
        }

        inaddr = ((struct sockaddr_in *) s)->sin_addr.s_addr;

# if (NGX_HAVE_INET6)
    ipv4:
# endif /* NGX_HAVE_INET6 */

        a = access->elts;
        for (i = 0; i < access->nelts; i++) {
            if ((inaddr & a[i].mask) == a[i].addr) {
                return NGX_OK;
            }
        }

        return NGX_DECLINED;

# if (NGX_HAVE_INET6)
    case AF_INET6:
        inaddr6 = &((struct sockaddr_in6 *) s)->sin6_addr;
        p = inaddr6->s6_addr;

        if (access && IN6_IS_ADDR_V4MAPPED(inaddr6)) {
            inaddr = p[12] << 24;
            inaddr += p[13] << 16;
            inaddr += p[14] << 8;
            inaddr += p[15];
            inaddr = htonl(inaddr);

            goto ipv4;
        }

        if (access6 == NULL) {
            return NGX_DECLINED;
        }

        a6 = access6->elts;
        for (i = 0; i < access6->nelts; i++) {
            for (n = 0; n < 16; n++) {
                if ((p[n] & a6[i].mask.s6_addr[n]) != a6[i].addr.s6_addr[n]) {
                    goto next;
                }
            }

            return NGX_OK;

        next:
            continue;
        }

        return NGX_DECLINED;
# endif /* NGX_HAVE_INET6 */
    }

    return NGX_DECLINED;
}


char *
ngx_http_folder_purge_conf(ngx_conf_t *cf, ngx_http_folder_purge_conf_t *cpcf)
{
    ngx_cidr_t       cidr;
    ngx_in_cidr_t   *access;
# if (NGX_HAVE_INET6)
    ngx_in6_cidr_t  *access6;
# endif /* NGX_HAVE_INET6 */
    ngx_str_t       *value;
    ngx_int_t        rc;
    ngx_uint_t       i;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        cpcf->enable = 0;
        return NGX_CONF_OK;

    } else if (ngx_strcmp(value[1].data, "on") == 0) {
        ngx_str_set(&cpcf->method, "PURGE");

    } else {
        cpcf->method = value[1];
    }

    if (cf->args->nelts < 4) {
        cpcf->enable = 1;
        return NGX_CONF_OK;
    }

    /* sanity check */
    if (ngx_strcmp(value[2].data, "from") != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\", expected"
                           " \"from\" keyword", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (ngx_strcmp(value[3].data, "all") == 0) {
        cpcf->enable = 1;
        return NGX_CONF_OK;
    }

    for (i = 3; i < cf->args->nelts; i++) {
        rc = ngx_ptocidr(&value[i], &cidr);

        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[i]);
        }

        switch (cidr.family) {
        case AF_INET:
            if (cpcf->access == NULL) {
                cpcf->access = ngx_array_create(cf->pool, cf->args->nelts - 3,
                                                sizeof(ngx_in_cidr_t));
                if (cpcf->access == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            access = ngx_array_push(cpcf->access);
            if (access == NULL) {
                return NGX_CONF_ERROR;
            }

            access->mask = cidr.u.in.mask;
            access->addr = cidr.u.in.addr;

            break;

# if (NGX_HAVE_INET6)
        case AF_INET6:
            if (cpcf->access6 == NULL) {
                cpcf->access6 = ngx_array_create(cf->pool, cf->args->nelts - 3,
                                                 sizeof(ngx_in6_cidr_t));
                if (cpcf->access6 == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            access6 = ngx_array_push(cpcf->access6);
            if (access6 == NULL) {
                return NGX_CONF_ERROR;
            }

            access6->mask = cidr.u.in6.mask;
            access6->addr = cidr.u.in6.addr;

            break;
# endif /* NGX_HAVE_INET6 */
        }
    }

    cpcf->enable = 1;

    return NGX_CONF_OK;
}


void
ngx_http_folder_purge_merge_conf(ngx_http_folder_purge_conf_t *conf,
    ngx_http_folder_purge_conf_t *prev)
{
    if (conf->enable == NGX_CONF_UNSET) {
        if (prev->enable == 1) {
            conf->enable = prev->enable;
            conf->method = prev->method;
            conf->access = prev->access;
            conf->access6 = prev->access6;

        } else {
            conf->enable = 0;
        }
    }
}


void *
ngx_http_folder_purge_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_folder_purge_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_folder_purge_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->proxy.enable = NGX_CONF_UNSET;

    conf->conf = NGX_CONF_UNSET_PTR;

    return conf;
}


char *
ngx_http_folder_purge_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_folder_purge_loc_conf_t  *prev = parent;
    ngx_http_folder_purge_loc_conf_t  *conf = child;
    ngx_http_core_loc_conf_t         *clcf;
    ngx_http_proxy_loc_conf_t        *plcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    ngx_http_folder_purge_merge_conf(&conf->proxy, &prev->proxy);

    if (conf->proxy.enable && clcf->handler != NULL) {
        plcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_module);

        if (plcf->upstream.upstream || plcf->proxy_lengths) {
            conf->conf = &conf->proxy;
            conf->handler = plcf->upstream.cache
                          ? ngx_http_proxy_folder_purge_handler : NULL;
            conf->original_handler = clcf->handler;

            clcf->handler = ngx_http_folder_purge_access_handler;

            return NGX_CONF_OK;
        }
    }

    ngx_conf_merge_ptr_value(conf->conf, prev->conf, NULL);

    if (conf->handler == NULL) {
        conf->handler = prev->handler;
    }

    if (conf->original_handler == NULL) {
        conf->original_handler = prev->original_handler;
    }

    return NGX_CONF_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
