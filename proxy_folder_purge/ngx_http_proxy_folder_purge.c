
/*
 * (C)
 */

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_masks_storage.h>


#if NGX_CACHE_PURGE_MODULE
#error "Please off cache_purge_module. It's higly not recomented to use "
        "both modules in the same build."
#endif /** NGX_CACHE_PURGE_MODULE */


#define _LP "proxy_folder_purge: "


typedef struct {
    ngx_flag_t                    enable;
    ngx_str_t                     method;
    ngx_array_t                  *access;   /* array of ngx_in_cidr_t */
    ngx_array_t                  *access6;  /* array of ngx_in6_cidr_t */
} ngx_http_folder_purge_conf_t;


typedef struct {
    ngx_http_folder_purge_conf_t   cf;
    ngx_http_handler_pt            handler;
    ngx_http_handler_pt            original_handler;
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
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


char *
ngx_http_proxy_folder_purge_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_folder_purge_loc_conf_t   *c;

    c = ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_folder_purge);

    if (c->cf.enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    return ngx_http_folder_purge_conf(cf, &c->cf);
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

    /** Check aux functions first */
    if (ngx_http_folder_dump(r) == NGX_MASKS_STORAGE_OK) {
        (void) ngx_http_folder_send_dump_handler(r);
        goto exit;
    } else if (ngx_http_folder_flush(r) == NGX_MASKS_STORAGE_OK) {
        (void) ngx_http_folder_send_flush_handler(r);
        goto exit;
    }

    /** Add purging */
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
                _LP "unknown response=%d (or storage is failed) for \"%V\"",
                rc, &r->uri);
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
    }

    ngx_http_finalize_request(r, rc);

exit:
    return NGX_DONE;
}


ngx_int_t
ngx_http_folder_purge_access_handler(ngx_http_request_t *r)
{
    ngx_http_folder_purge_loc_conf_t   *c;

    c = ngx_http_get_module_loc_conf(r, ngx_http_proxy_folder_purge);

    if (c == NULL) {

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                _LP "ngx_http_proxy_folder_purge_handler: loc conf is NULL "
                "this is not expected");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!c->cf.enable) {
        return c->original_handler(r);
    }

    if (r->method_name.len != c->cf.method.len
        || (ngx_strncmp(r->method_name.data, c->cf.method.data,
                        r->method_name.len)))
    {
        return c->original_handler(r);
    }

    if ((c->cf.access || c->cf.access6)
         && ngx_http_folder_purge_access(c->cf.access,
                                         c->cf.access6,
                                         r->connection->sockaddr) != NGX_OK)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    if (c->handler == NULL) {

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                _LP "folder purge handler is not configured for the "
                "PURGE request");
        return NGX_HTTP_NOT_FOUND;
    }

    return c->handler(r);
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
                           _LP "invalid parameter \"%V\", expected"
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
                               _LP "invalid parameter \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               _LP "low address bits of %V are meaningless",
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

    conf->cf.enable = NGX_CONF_UNSET;

    return conf;
}


char *
ngx_http_folder_purge_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_folder_purge_loc_conf_t  *prev = parent;
    ngx_http_folder_purge_loc_conf_t  *conf = child;
    ngx_http_core_loc_conf_t          *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    ngx_http_folder_purge_merge_conf(&conf->cf, &prev->cf);

    if (conf->cf.enable && clcf->handler != NULL) {

        conf->handler = ngx_http_proxy_folder_purge_handler;
        conf->original_handler = clcf->handler;
        clcf->handler = ngx_http_folder_purge_access_handler;

        return NGX_CONF_OK;
    }

    if (conf->handler == NULL) {
        conf->handler = prev->handler;
    }

    if (conf->original_handler == NULL) {
        conf->original_handler = prev->original_handler;
    }

    return NGX_CONF_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
