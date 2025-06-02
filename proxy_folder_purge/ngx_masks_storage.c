
/**
 * (C)
 */

#include <ngx_masks_storage.h>
#include <ngx_masks_resume_utils.h>
#include <ngx_masks_fs_walker.h>
#include <ngx_masks_storage_utils.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/dir.h>
#include <sys/file.h>
#include <dirent.h>
#include <fnmatch.h>


/** A structure for holding writer context (for X-Purge-Options: dump) */
typedef struct {
    /** A reference to an http request */
    ngx_http_request_t  *r;

    /** Temp file for the message */
    ngx_temp_file_t     *temp_file;
} ngx_http_cache_purge_folder_writer_ctx_t;


typedef struct {
    ngx_str_t                    cache_path;
    ngx_uint_t                   max_allowed_masks_per_domain;
    ngx_masks_storage_t         *masks_storage;
    ngx_flag_t                   foreground_purge_enable;
} ngx_masks_storage_loc_conf_t;


typedef struct {
    ngx_masks_storage_t           *masks;
    ngx_cycle_t                   *cycle;
    ngx_event_t                   *ev;

    /** Purge urls to apply to current domain */
    ngx_list_t                    *purge_urls;
} ngx_remove_file_ctx_t;


typedef ngx_int_t (*ngx_on_add_mask) (ngx_masks_storage_t * /*ms*/,
    ngx_str_t * /*domain*/, ngx_str_t * /*mask*/,
    time_t /*purge_start_time*/, ngx_int_t /*is_restoring*/);
static inline void ngx_masks_storage_purger_queue_free(
        ngx_masks_storage_t *ms);

static ngx_int_t ngx_masks_storage_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_masks_storage_cached_since_var(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data);

static char *ngx_masks_storage_conf(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_masks_storage_merge_loc_conf(ngx_conf_t *cf, void *parent,
        void *child);
static void *ngx_masks_storage_create_loc_conf(ngx_conf_t *cf);

static ngx_masks_storage_t *ngx_masks_storage_init(ngx_conf_t *cf,
        ngx_str_t *shared_memory_size, size_t max_allowed_masks_per_domain);

static ngx_int_t ngx_http_cache_purge_folder_dump_shared_memory(
        ngx_http_request_t *r);
static ngx_int_t ngx_http_cache_purge_folder_flush(ngx_http_request_t *r);

static ngx_int_t ngx_masks_storage_purger_add_mask(
        ngx_masks_storage_t *ms, ngx_str_t *domain, ngx_str_t *mask,
        time_t purge_start_time, ngx_int_t is_restoring);
static ngx_int_t ngx_masks_storage_read_purger_queue(
        ngx_masks_storage_t *ms, u_char *filename);
static ngx_int_t ngx_remove_file(void *ctx_,
        ngx_masks_fs_walker_ctx *entry);
static ngx_int_t ngx_masks_storage_old_purger_file(
    ngx_masks_storage_t *m, ngx_str_t *dirname, DIR *dp, char **files);
static ngx_int_t ngx_masks_storage_remove_purger_file(
        ngx_masks_storage_t *m, ngx_str_t *dirname);
static ngx_int_t ngx_masks_storage_get_pid(u_char *path);


static ngx_command_t ngx_masks_storage_commands[] = {

    { ngx_string("folder_purge"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_masks_storage_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_folder_purge_on_request"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|
        NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_masks_storage_loc_conf_t, foreground_purge_enable),
      NULL },

    { ngx_string("proxy_folder_purge_cache_path"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_masks_storage_loc_conf_t, cache_path),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_masks_storage_module_ctx = {
    ngx_masks_storage_add_variables,    /* preconfiguration */
    NULL,                               /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_masks_storage_create_loc_conf,  /* create location configuration */
    ngx_masks_storage_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_masks_storage_module = {
    NGX_MODULE_V1,
    &ngx_masks_storage_module_ctx,          /* module context */
    ngx_masks_storage_commands,             /* module directives */
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


static ngx_http_variable_t  ngx_masks_storage_vars[] = {

    { ngx_string("cached_since"), NULL,
      ngx_masks_storage_cached_since_var, 0, 0, 0 },

      ngx_http_null_variable
};

/**
 * @retval 0 arg starts with the "prefix" and argv is set to arg remainder
 * @retval 1 arg doesn't starts with the "prefix" and argv is untouched
 */
static inline int
compare_and_set_argv(ngx_str_t *arg, const char *prefix,
                     unsigned prefix_len, ngx_str_t *argv)
{
    if (arg->len >= prefix_len
        && ngx_memcmp(arg->data, prefix, prefix_len) == 0)
    {
        argv->data = arg->data + prefix_len;
        argv->len = arg->len - prefix_len;
        return 0;
    }

    return 1;
}


/**
 * Returns non-zero if specified string value should be treated as false
 */
static int
ngx_masks_conf_str_is_false(ngx_str_t *cv)
{
#define CVCMP(x) \
        (cv->len == sizeof(x) - 1 \
         && ngx_memcmp(cv->data, x, sizeof(x) - 1) == 0)
    return CVCMP("no") || CVCMP("off") || CVCMP("false");
#undef CVCMP
}


/**
 * nginx conf functions {{{
 */
static char *
ngx_masks_storage_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_masks_storage_loc_conf_t  *loc_conf;
    ngx_str_t                     *value, tmp;
    ngx_masks_storage_t           *ms;
    ngx_int_t                      max_allowed_masks_per_domain,
                                   background_purger_off;
    u_char                        *p;
    ngx_uint_t                     i, background_purger_files;
    ngx_msec_t                     background_purger_sleep;
    ngx_msec_t                     background_purger_threshold;
    ngx_msec_t                     background_purger_startup_lock_wait;

    if (cf->args->nelts < 4) {
        return "folder_purge requires at least 3 arguments";
    }

    loc_conf = ngx_http_conf_get_module_loc_conf(cf,
            ngx_masks_storage_module);

    value = cf->args->elts;

    background_purger_files = MASKS_STORAGE_PURGER_FILES_DEFAULT;
    background_purger_sleep = MASKS_STORAGE_PURGER_SLEEP_DEFAULT;
    background_purger_threshold = MASKS_STORAGE_PURGER_THRESHOLD_DEFAULT;
    background_purger_startup_lock_wait
                                = MASKS_STORAGE_PURGER_STARTUP_LOCK_WAIT;
    background_purger_off = 0;

    /** Optional options {{{ */
    for (i = 4; i < cf->args->nelts; i++) {

    /* Most people would look for option= string,
     * so don't make that '=' sign implicit */
#define IS_OPT(optn) (compare_and_set_argv(value + i, optn, sizeof(optn) - 1, &tmp) == 0)
        if (IS_OPT("purger_files=")) {
            background_purger_files = (ngx_uint_t) ngx_atoi(tmp.data, tmp.len);
            if (background_purger_files == (ngx_uint_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "proxy_folder_purge: invalid purger_files value \"%V\"",
                        &value[i]);
                return NGX_CONF_ERROR;
            }

        } else if (IS_OPT("purger_sleep=")) {
            background_purger_sleep = ngx_parse_time(&tmp, 0);

            if (background_purger_sleep == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "proxy_folder_purge: invalid purger_sleep value \"%V\"",
                        &value[i]);
                return NGX_CONF_ERROR;
            }

        } else if (IS_OPT("purger_threshold=")) {
            background_purger_threshold = ngx_parse_time(&tmp, 0);
            if (background_purger_threshold == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "proxy_folder_purge: invalid purger_sleep value \"%V\"",
                        &value[i]);
                return NGX_CONF_ERROR;
            }

        } else if (IS_OPT("purger_off")) {
            background_purger_off = 1;

        } else if (IS_OPT("startup_lock_delay=")) {
            /* How long to wait for lock acquisition */
            background_purger_startup_lock_wait =
                    ngx_masks_conf_str_is_false(&tmp) ? 0
                                                      : ngx_parse_time(&tmp, 1);
            if (background_purger_startup_lock_wait
                    == (ngx_msec_t) NGX_ERROR)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "proxy_folder_purge: "
                                   "invalid startup_lock_delay value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

        } else {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                    "proxy_folder_purge: found an unknown option = \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }
    /** }}}*/

    /** The first requred(!) options (3 options) {{{ */
    max_allowed_masks_per_domain = ngx_atoi(value[2].data, value[2].len);

    if (max_allowed_masks_per_domain < MIN_ALLOWED_MASKS_NUM) {
        return "max allowed masks per domain should be >= "
                MIN_ALLOWED_MASKS;
    }

    /** Masks storage */
    loc_conf->max_allowed_masks_per_domain = max_allowed_masks_per_domain;
    ms = ngx_masks_storage_init(cf, &value[1], max_allowed_masks_per_domain);

    if (!ms) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "proxy_folder_purge: "
                "can't allocate masks storage: size = \"%V\", "
                "masks per domain = %d",
                &value[1], max_allowed_masks_per_domain);
        return NGX_CONF_ERROR;
    }

    /** background purge */
    ms->path->manager = NULL;
    ms->path->loader = NULL;
    ms->path->purger = NULL;

    ms->background_purger_files = background_purger_files;
    ms->background_purger_sleep = background_purger_sleep;
    ms->background_purger_threshold = background_purger_threshold;
    ms->background_purger_off = background_purger_off;
    ms->background_purger_startup_lock_wait = background_purger_startup_lock_wait;

    tmp = value[3];

    if (tmp.data[tmp.len - 1] == '/') {
        tmp.data[tmp.len - 1] = 0;
        --tmp.len;
    }

    ms->path->purger_ = -1;
    ms->path->data = (void *) ms;
    ms->path->conf_file = cf->conf_file->file.name.data;
    ms->path->line = cf->conf_file->line;
    ms->path->name.len = tmp.len + sizeof(MASKS_STORAGE_DIR) - 1;

    /* +1 for ngx_create_full_path, as it requires null-terminated string */
    ms->path->name.data = ngx_pcalloc(cf->pool, ms->path->name.len + 1);
    if (!ms->path->name.data) {
        return NGX_CONF_ERROR;
    }

    p = ngx_snprintf(ms->path->name.data, ms->path->name.len + 1, "%V%s%Z",
            &tmp, MASKS_STORAGE_DIR);
    ms->path->name.len = (size_t) (p - ms->path->name.data - 1);

    if (ngx_conf_full_name(cf->cycle, &ms->path->name, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_create_full_path(ms->path->name.data, ngx_dir_access(0755))
            == NGX_FILE_ERROR)
    {
        if (ngx_errno != NGX_EEXIST) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                                "proxy_folder_purge: "
                                "ngx_create_full_path() \"%V\" failed",
                                &ms->path->name);
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_add_path(cf, &ms->path) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ms->tmp_path->manager = NULL;
    ms->tmp_path->loader = NULL;
    ms->tmp_path->purger = NULL;

    ms->tmp_path->purger_ = -1;
    ms->tmp_path->data = (void *) ms;
    ms->tmp_path->conf_file = cf->conf_file->file.name.data;
    ms->tmp_path->line = cf->conf_file->line;
    ms->tmp_path->name.len = sizeof("logs") - 1;
    ms->tmp_path->name.data = ngx_pcalloc(cf->pool, ms->tmp_path->name.len);
    if (!ms->tmp_path->name.data) {
        return NGX_CONF_ERROR;
    }

    ngx_snprintf(ms->tmp_path->name.data, ms->tmp_path->name.len, "logs");

    if (ngx_conf_full_name(cf->cycle, &ms->tmp_path->name, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    loc_conf->masks_storage = ms;
    /** }}} */

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_masks_storage_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_masks_storage_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_masks_storage_create_loc_conf(ngx_conf_t *cf)
{
    ngx_masks_storage_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_masks_storage_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->masks_storage = NGX_CONF_UNSET_PTR;
    conf->foreground_purge_enable = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_masks_storage_merge_loc_conf(ngx_conf_t *cf, void *parent,
        void *child)
{
    ngx_masks_storage_loc_conf_t  *prev = parent;
    ngx_masks_storage_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->masks_storage, prev->masks_storage,
            NULL);

    ngx_conf_merge_uint_value(conf->max_allowed_masks_per_domain,
            prev->max_allowed_masks_per_domain,
            (ngx_uint_t) MIN_ALLOWED_MASKS_NUM);

    ngx_conf_merge_value(conf->foreground_purge_enable,
            prev->foreground_purge_enable, 1);

    ngx_conf_merge_str_value(conf->cache_path, prev->cache_path, "");

    return NGX_CONF_OK;
}
/** }}} */

/** Vars {{{ */
static void
ngx_format_time_iso8601(time_t sec, u_char *iso_string, size_t len)
{
    ngx_tm_t  gmt, tm;
    ngx_int_t gmtoff;

    ngx_gmtime(sec, &gmt);

#if (NGX_HAVE_GETTIMEZONE)
     gmtoff = ngx_gettimezone();
     ngx_gmtime(sec + gmtoff * 60, &tm);
#elif (NGX_HAVE_GMTOFF)
     ngx_localtime(sec, &tm);
     gmtoff = (ngx_int_t) (tm.ngx_tm_gmtoff / 60);
#else
     ngx_localtime(sec, &tm);
     gmtoff = ngx_timezone(tm.ngx_tm_isdst);
#endif

    ngx_snprintf(iso_string, len, "%4d-%02d-%02dT%02d:%02d:%02d%c%02i:%02i",
                        tm.ngx_tm_year, tm.ngx_tm_mon,
                        tm.ngx_tm_mday, tm.ngx_tm_hour,
                        tm.ngx_tm_min, tm.ngx_tm_sec,
                        gmtoff < 0 ? '-' : '+',
                        ngx_abs(gmtoff / 60), ngx_abs(gmtoff % 60));
}


static ngx_int_t
ngx_masks_storage_cached_since_var(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data)
{
    size_t  len;
    u_char *val;

    *v = ngx_http_variable_null_value;

    if (r->upstream == NULL || r->cache == NULL) {
        goto exit;
    }

    if ((r->upstream->cache_status == NGX_HTTP_CACHE_HIT
            || r->upstream->cache_status == NGX_HTTP_CACHE_STALE
            || r->upstream->cache_status == NGX_HTTP_CACHE_UPDATING)
        && r->cache->date > 0)
    {

        len = sizeof("1970-09-28T12:00:00+06:00");
        val = ngx_pcalloc(r->pool, len);
        if (val == NULL) {
            goto exit;
        }

        ngx_format_time_iso8601(r->cache->date, val, len);

        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 1;
        v->len = len - 1;
        v->not_found = 0;
        v->data = val;
    }

exit:
    return NGX_OK;
}

/** }}} */

/** Storage helpers {{{*/
static ngx_int_t
ngx_serialize_mask(ngx_masks_storage_t *ms, ngx_str_t *b,
        ngx_str_t *domain, ngx_mask_t *mask)
{
    /** XXX
     *  Why not a binary format?
     *
     *  Well, It's more harder for debugging & copying.
     *  For instance, we need to write a (d/s)11n for writing Python or Perl
     *  tests.
     *
     *  A file format is:
     *  magic,crc32,domain,mask,purge_start_time\n
     *  ...
     *
     *  where:
     *  1) magic - uniq 4-bar string
     *  2) crc32 - a crc32(domain + mask + purge_start_time) string
     *  3) domain - a domain string
     *  4) mask - a mask string
     *  5) purge_start_time - a purge_start_time string
     *  6) '\n' - end of the message
     */

    ngx_str_t  header, body;
    u_char    *p;

    header.data = NULL;
    body.data = NULL;
    b->data = NULL;

    /** Body */
    body.len = domain->len + 1 + mask->mask.len + 1 +
                UINT32_STR_MAX + 1 + UINT64_STR_MAX + 1 +
                sizeof("\n") - 1;

    body.data = ngx_pcalloc(ms->r->pool, body.len);
    if (body.data == NULL) {
        goto error_exit;
    }

    p = ngx_snprintf(body.data, body.len,
            "%V,%V,%T\n", domain, &mask->mask, mask->purge_start_time);
    body.len = (size_t) (p - body.data);

    /** Header */
    header.len = sizeof(MASKS_STORAGE_MAGIC) - 1 + UINT64_STR_MAX + 1;
    header.data = ngx_pcalloc(ms->r->pool, header.len);
    if (header.data == NULL) {
        goto error_exit;
    }

    p = ngx_snprintf(header.data, header.len, "%s%uz,",
            MASKS_STORAGE_MAGIC,
            ngx_crc32_long(body.data, body.len - 1 /* exclude '\n' */));

    header.len = (size_t) (p - header.data);

    /** Message */
    b->len = header.len + body.len;
    b->data = ngx_pnalloc(ms->r->pool, b->len);
    if (b->data == NULL) {
        goto error_exit;
    }

    ngx_snprintf(b->data, b->len, "%V%V", &header, &body);

    ngx_pfree(ms->r->pool, body.data);
    ngx_pfree(ms->r->pool, header.data);

    return NGX_OK;

error_exit:

    if (body.data) {
        ngx_pfree(ms->r->pool, body.data);
    }

    if (header.data) {
        ngx_pfree(ms->r->pool, header.data);
    }

    return NGX_ERROR;
}


/** Decode a single mask and invoke callback on success
 *
 * mask pattern:
 *
 * MASKS_STORAGE_MAGIC${line_crc},${vhost_id},${purge_pattern},${timestamp}
 *
 * where
 * <ul>
 * <li>all numbers are encoded in ASCII
 * <li>vhost_id is assumed to not contain commas and newlines
 * <li>purge_pattern is not escaped, rather its end is detected by finding
 *     commas from the end of the line
 * </ul>
 *
 * @param start start of the mask block. Function will look for MASKS_STORAGE_MAGIC
 *           there
 * @param eol end-of-line
 * @param mask caller-provided buffer where to store decoded mast
 *
 * @return NULL on success or statically-allocated error message on failure
 */
static const char*
parse_mask_line(ngx_masks_storage_t *ms, u_char *start, u_char *eol, ngx_full_mask_t *mask)
{
    ngx_int_t rc;
    uint32_t crc32;
    u_char *p, *separator;

    p = start;

    /* Avoid call to memmem with memcmp, as highly likely most lines will be
     * valid and start from signature */
    if (start + sizeof(MASKS_STORAGE_MAGIC) >= eol
        || (memcmp(p, MASKS_STORAGE_MAGIC, sizeof(MASKS_STORAGE_MAGIC) - 1) != 0
            && (p = memmem(p, eol - p,
                           MASKS_STORAGE_MAGIC,
                           sizeof(MASKS_STORAGE_MAGIC) - 1)) == NULL))
    {
        return "can't find a MAGIC";
    }

    /* Parse crc */
    p += sizeof(MASKS_STORAGE_MAGIC) - 1;
    separator = memchr(p, ',', eol - p);
    if (separator == NULL || separator == p) {
        return "can't find a CRC32 and next fields";
    }

    rc = ngx_atoi(p, separator - p);
    if (rc == NGX_ERROR) {
        return "CRC32 is not a number";
    }

    mask->crc32 = (uint32_t) rc;

    /* Validate checksum */
    p = separator + 1;
    crc32 = ngx_crc32_long(p, eol - p);
    if (crc32 != mask->crc32) {
        return "CRC32 check failed";
    }

    /* vhost_id */
    p = separator + 1;
    separator = memchr(p, ',', eol - p);
    if (separator == NULL) {
        return "can't find a domain";
    }
    mask->domain.data = p;
    mask->domain.len = separator - p;

    /* pattern or mask */
    p = separator + 1;
    separator = memchr(p, ',', eol - p);
    if (separator == NULL) {
        return "can't find a pattern, e.g. mask";
    }
    mask->mask.mask.data = p;
    mask->mask.mask.len = separator - p;

    /* timestamp */
    p = separator + 1;
    mask->mask.purge_start_time = ngx_atotm(p, eol /* \n */ - p);
    if (mask->mask.purge_start_time == NGX_ERROR) {
        return "timestamp is not a number";
    }

    return NULL;
}


/**
 * Decode all purge mask requests from buffer [it, end) invoking
 * on_add_mask() for each valid mask found
 */
static ngx_int_t
ngx_deserialize_mask(ngx_masks_storage_t *ms, u_char *it,
        u_char *end, ngx_on_add_mask on_add_mask)
{
    ngx_int_t lineno, rc;
    u_char *start, *eol;
    const char *err;
    ngx_full_mask_t tmp;

    for (start = it, lineno = 1; start < end; lineno++, start = eol + 1) {

        eol = memchr(start, '\n', end - start);
        if (eol == NULL) {
            break;
        }

        err = parse_mask_line(ms, start, eol, &tmp);
        if (err != NULL) {
            ngx_str_t line = { .data = start, .len = eol - start };
            ngx_log_error(NGX_LOG_ERR, ms->log, 0,
                          "proxy_folder_purge: can't parse a line, "
                          "err = \"%s\", line [%d] = \"%V\"",
                          err, lineno, &line);
            continue;
        }

        rc = on_add_mask(ms, &tmp.domain, &tmp.mask.mask,
                         tmp.mask.purge_start_time, 1);
        if (rc != NGX_MASKS_STORAGE_OK) {
            ngx_log_error(NGX_LOG_ERR, ms->log, 0,
                          "proxy_folder_purge: on_add_mask failed rc = %d", rc);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_masks_write_to_masks_in(ngx_masks_storage_t *ms,
        ngx_str_t *domain, ngx_mask_t *mask)
{
    ngx_str_t    b;
    ngx_str_t    masks_in;

    b.data = NULL;
    b.len = 0;

    /** We didn't set a file name at start, since we can't get pid
     * inside a master process.
     */

    /** TODO: cache it, it won't be changed
     * Will be: {PATH} / {MASKS_IN}.{PID} \0
     */
    masks_in.len = ms->path->name.len + sizeof(MASKS_IN) - 1 +
        sizeof(UINT32_STR_MAX) - 1 + 1;
    masks_in.data = ngx_pnalloc(ms->r->pool, masks_in.len);
    if (masks_in.data == NULL) {
        return NGX_ERROR;
    }

    ngx_snprintf(masks_in.data, masks_in.len, "%V%s%d%Z",
            &ms->path->name, MASKS_IN, (ngx_int_t) ngx_getpid());

    if (ngx_serialize_mask(ms, &b, domain, mask) != NGX_OK) {
        /** Well we don't need close FD here. This isn't a system bug
         * if it happens. */
        ngx_log_error(NGX_LOG_ERR, ms->log, 0,
                "proxy_folder_purge: can't s11n the mask to domain = "
                "\"%V\", mask = \"%V\"", domain, mask);

        return NGX_ERROR;
    }

    /* TODO: improve it.
     * (1) Detect that file has been deleted.
     * (2) And re-open it again.
     * If we just cache fd, and if file is removed, then
     * it would not detected; hence logic may corrupted.
     */
    ms->masks_in_fd = open_append_only_file(&masks_in);
    if (ms->masks_in_fd == -1) {
        ms->masks_in_fd = NGX_INVALID_FILE;

        ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: can't open \"%V\"", &masks_in);
        return NGX_ERROR;
    }

    if (write(ms->masks_in_fd, b.data, b.len) != (ssize_t) b.len) {

        ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: can't write to \"%V\"", &masks_in);

        close(ms->masks_in_fd);
        ms->masks_in_fd = NGX_INVALID_FILE;

        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, ms->log, errno,
            "proxy_folder_purge: write to \"%V\", fd = %d, bytes = %d",
            &masks_in, ms->masks_in_fd, b.len);

    /** Make sure, that the data flushed */
#if 0
    /** NOTE:
     *  This could freeze worker process.
     *  Probably this should be an option from the nginx.conf
     *  with default value is off
     */
    if (fsync(ms->masks_in_fd) > 0) {
        ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: can't flush to \"%V\"", masks_in);
    }
#endif

    close(ms->masks_in_fd);
    ms->masks_in_fd = NGX_INVALID_FILE;

    return NGX_OK;
}


static ngx_int_t
ngx_init_storage(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_masks_storage_t  *octx = (ngx_masks_storage_t *) data;

    ngx_masks_storage_t  *ctx;
    ngx_slab_pool_t          *shpool;

    ctx = shm_zone->data;

    /** An old shared memory context, so we don't need init a new shm.
     * Actually, this means that we don't need restoring, all data are here */
    if (octx) {

        ctx->sh = octx->sh;
        ctx->sh->restoring = octx->sh->restoring;
        ctx->shpool = octx->shpool;
        ctx->log = octx->log;
        ctx->r = NULL;

        return NGX_OK;
    }

    /** It isn't exist, so create it
     */
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    ctx->shpool = shpool;

    ctx->sh = ngx_slab_alloc(shpool, sizeof(ngx_masks_storage_shctx_t));

    if (ctx->sh == NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                "proxy_folder_purge: "
                "can't allocated masks storage context, size = %d",
                sizeof(ngx_masks_storage_shctx_t));
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ctx->sh->rbtree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (ctx->sh->rbtree == NULL) {

        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                "proxy_folder_purge: "
                "can't allocated masks storage rbtree context, size = %d",
                sizeof(ngx_rbtree_t));
        return NGX_ERROR;
    }

    ctx->sh->sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (ctx->sh->sentinel == NULL) {

        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                "proxy_folder_purge: "
                "can't allocated masks storage rbtree sentinel, size = %d",
                sizeof(ngx_rbtree_node_t));
        return NGX_ERROR;
    }

    ngx_rbtree_init(ctx->sh->rbtree, ctx->sh->sentinel,
        ngx_str_rbtree_insert_value);

    ctx->shpool->log_ctx = ngx_slab_alloc(shpool, sizeof(LOG_HINT) /* + \0*/);
    if (ctx->shpool->log_ctx == NULL) {

        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                "proxy_folder_purge: "
                "can't allocated masks storage log ctx, size = %d",
                sizeof(LOG_HINT));
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, "%s\0", LOG_HINT);

    /** If a new segment hasn't memory for allocating,
     * then nginx writes some logs. */
    ctx->shpool->log_nomem = 1;

    ctx->sh->restoring = -1;

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
            "proxy_folder_purge: "
            "shared memory created, sh = %p, data = %p, restoring = %d",
            ctx->sh, ctx, ctx->sh->restoring);

    return NGX_OK;
}


static ngx_masks_storage_t *
ngx_masks_storage_init(ngx_conf_t *cf, ngx_str_t *shared_memory_size,
        size_t max_allowed_masks_per_domain)
{
    ngx_masks_storage_t         *ctx;
    ngx_shm_zone_t              *shm_zone;
    ngx_uint_t                   n;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_masks_storage_t));

    if (!ctx) {
        return NULL;
    }

    ctx->path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (ctx->path == NULL) {
        return NULL;
    }

    ctx->tmp_path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (ctx->tmp_path == NULL) {
        return NULL;
    }

    ngx_str_set(&ctx->masks_purger, MASKS_PURGER);
    ngx_str_set(&ctx->shm_name, ZONE_NAME);
    ctx->max_allowed_masks_per_domain = max_allowed_masks_per_domain;
    ctx->r = NULL;
    ctx->log = cf->log;
    ctx->masks_in_fd = NGX_INVALID_FILE;
    ctx->masks_purger_fd = NGX_INVALID_FILE;

    n = ngx_parse_size(shared_memory_size);
    if (n < (ngx_uint_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "proxy_folder_purge: \"%V\" is too small", shared_memory_size);
        return NULL;
    }

    shm_zone = ngx_shared_memory_add(cf, &ctx->shm_name, n,
            &ngx_masks_storage_module);
    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "proxy_folder_purge: ngx_shared_memory_add failed");
        return NULL;
    }

    if (shm_zone->data) {
#if (NGX_DEBUG)
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "proxy_folder_purge: "
                "\"%V\" is already bound at ngx_masks_storage_init",
                &ctx->shm_name);
#endif /* (NGX_DEBUG) */
        return NULL;
    }

    shm_zone->data = (void *) ctx;
    shm_zone->init = ngx_init_storage;

    ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
            "proxy_folder_purge: "
            "shm_zone allocated, shm = %p, data = %p",
            shm_zone, shm_zone->data);

    return ctx;
}



static ngx_rbtree_node_t *
ngx_masks_lookup_domain_unlocked(ngx_masks_storage_t *ms,
    ngx_str_t *domain)
{
    uint32_t              hash;

    if (ms == NULL || ms->sh == NULL || ms->sh->rbtree == NULL) {
        return NULL;
    }

    hash = ngx_crc32_long(domain->data, domain->len);

    return (ngx_rbtree_node_t *)
        ngx_str_rbtree_lookup(ms->sh->rbtree, domain, hash);
}


static ngx_rbtree_node_t *
ngx_masks_insert_domain_unlocked(ngx_masks_storage_t *ms,
        const ngx_str_t *domain)
{
    ngx_domain_rbtree_node_t      *node;
    ngx_masks_storage_shctx_t     *sh;
    ngx_slab_pool_t               *shpool;

    sh = ms->sh;
    shpool = ms->shpool;

    node = ngx_slab_alloc_locked(shpool, sizeof(ngx_domain_rbtree_node_t));
    if (node == NULL) {
        goto error_exit;
    }

    ngx_memzero(node, sizeof(ngx_domain_rbtree_node_t));

    node->sn.str.len = domain->len;

    node->sn.str.data = ngx_slab_alloc_locked(shpool, node->sn.str.len);
    if (node->sn.str.data == NULL) {
        goto error_exit;
    }

    ngx_snprintf(node->sn.str.data, node->sn.str.len, "%V", domain);

    node->sn.node.key = ngx_crc32_long(domain->data, domain->len);

    node->value.max = ms->max_allowed_masks_per_domain;

    node->value.masks = ngx_slab_alloc_locked(shpool, sizeof(ngx_rbtree_t));
    if (node->value.masks == NULL) {
        goto error_exit;
    }

    node->value.sentinel = ngx_slab_alloc_locked(shpool,
                                                 sizeof(ngx_rbtree_node_t));
    if (node->value.sentinel == NULL) {
        goto error_exit;
    }

    ngx_rbtree_init(node->value.masks, node->value.sentinel,
        ngx_str_rbtree_insert_value);

    ngx_rbtree_insert(sh->rbtree, &node->sn.node);

    return (ngx_rbtree_node_t *) &node->sn.node;

error_exit:

    if (node) {

        if (node->value.masks) {
            ngx_slab_free_locked(shpool, node->value.masks);
        }

        if (node->value.sentinel) {
            ngx_slab_free_locked(shpool, node->value.sentinel);
        }

        if (node->sn.str.data) {
            ngx_slab_free_locked(shpool, node->sn.str.data);
        }

        ngx_slab_free_locked(shpool, node);
    }

    return NULL;
}


static ngx_int_t
ngx_masks_compare(ngx_masks_storage_t *ms, ngx_str_t *mask_a,
        ngx_str_t *mask_b)
{
    (void) ms;

    if (mask_b->len >= mask_a->len
            && ngx_strncmp(mask_b->data, mask_a->data, mask_a->len) == 0)
    {
        return NGX_OK;
    }

    return NGX_DECLINED;
}


static ngx_masks_rbtree_node_t *
ngx_masks_get_mask_queue_unlocked(ngx_masks_storage_t *ms,
    ngx_domain_rbtree_node_t *qnode, ngx_str_t *mask, ngx_int_t need_parse)
{
    uint32_t                     hash;
    ngx_masks_rbtree_node_t     *node;
    ngx_str_t                    mask_path, mask_rest;

    if (need_parse) {
        parse_path(mask, &mask_path, &mask_rest);

    } else {
        mask_path.len = mask->len;
        mask_path.data = mask->data;
    }

    hash = ngx_crc32_long(mask_path.data, mask_path.len);

    node = (ngx_masks_rbtree_node_t *)
            ngx_str_rbtree_lookup(qnode->value.masks, &mask_path, hash);

    return node;
}


static ngx_mask_t *
ngx_masks_lookup_mask_unlocked(ngx_masks_storage_t *ms,
    ngx_domain_rbtree_node_t *qnode, ngx_str_t *mask)
{
    ngx_masks_rbtree_node_t *node;
    ngx_mask_queue_t        *mask_queue;
    ngx_queue_t             *q;
    ngx_int_t                rc;

    node = ngx_masks_get_mask_queue_unlocked(ms, qnode, mask, 1);
    if (node == NULL) {
        return NULL;
    }

    for (q = ngx_queue_head(&node->mask_queue.queue);
            q != ngx_queue_sentinel(&node->mask_queue.queue);
            q = ngx_queue_next(q))
    {
        mask_queue = ngx_queue_data(q, ngx_mask_queue_t, queue);
        rc = ngx_masks_compare(ms, &mask_queue->mask.mask, mask);
        if (rc == NGX_OK) {
            return &mask_queue->mask;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_masks_insert_mask_unlocked(ngx_masks_storage_t *ms,
        ngx_rbtree_node_t *n, ngx_str_t *domain, ngx_str_t *mask,
        time_t purge_start_time)
{
    ngx_domain_rbtree_node_t       *qnode = (ngx_domain_rbtree_node_t *) n;

    ngx_masks_rbtree_node_t     *node;
    ngx_slab_pool_t             *shpool;
    ngx_mask_queue_t            *mask_queue;
    uint32_t                     hash;
    ngx_str_t                    mask_path, mask_rest;

    shpool = ms->shpool;

    /** Lookup the first avaliable node for putting masks into it.
     *
     * And also checks limit for this domain.
     *
     */
    if (qnode->value.len >= qnode->value.max) {
        return NGX_MASKS_STORAGE_LIMIT_REACHED;
    }

    parse_path(mask, &mask_path, &mask_rest);

    hash = ngx_crc32_long(mask_path.data, mask_path.len);

    node = (ngx_masks_rbtree_node_t *)
            ngx_str_rbtree_lookup(qnode->value.masks, &mask_path, hash);
    if (node == NULL) {

        node = ngx_slab_alloc_locked(shpool, sizeof(ngx_masks_rbtree_node_t));
        if (node == NULL) {
            ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                    "proxy_folder_purge: "
                    "can't add mask, slab allocation failed, mask size = %d",
                mask->len);
            return NGX_MASKS_STORAGE_FAIL;
        }

        ngx_memzero(node, sizeof(ngx_masks_rbtree_node_t));

        node->sn.str.len = mask_path.len;
        node->sn.str.data = ngx_slab_alloc_locked(shpool, node->sn.str.len);
        if (node->sn.str.data == NULL) {
            ngx_slab_free_locked(shpool, node);
            return NGX_MASKS_STORAGE_FAIL;
        }
        ngx_snprintf(node->sn.str.data, node->sn.str.len, "%V", &mask_path);
        node->sn.node.key = hash;

        ngx_queue_init(&node->mask_queue.queue);
        ngx_rbtree_insert(qnode->value.masks, &node->sn.node);
    }

    mask_queue = ngx_slab_alloc_locked(shpool, sizeof(ngx_mask_queue_t));
    if (mask_queue == NULL) {
        ngx_rbtree_delete(qnode->value.masks, &node->sn.node);
        ngx_slab_free_locked(shpool, node->sn.str.data);
        ngx_slab_free_locked(shpool, node);
        return NGX_MASKS_STORAGE_FAIL;
    }

    ngx_memzero(mask_queue, sizeof(ngx_mask_queue_t));

    mask_queue->mask.mask.len = mask->len;
    mask_queue->mask.mask.data = ngx_slab_alloc_locked(shpool,
                                        mask_queue->mask.mask.len);
    if (mask_queue->mask.mask.data == NULL) {
        ngx_slab_free_locked(shpool, mask_queue);
        ngx_rbtree_delete(qnode->value.masks, &node->sn.node);
        ngx_slab_free_locked(shpool, node->sn.str.data);
        ngx_slab_free_locked(shpool, node);
        return NGX_MASKS_STORAGE_FAIL;
    }

    ngx_snprintf(mask_queue->mask.mask.data,
                    mask_queue->mask.mask.len, "%V", mask);
    mask_queue->mask.purge_start_time = purge_start_time;
    mask_queue->mask.ref_count = 0;

    ngx_queue_insert_tail(&node->mask_queue.queue, &mask_queue->queue);

    ngx_log_error(NGX_LOG_INFO, ms->log, 0,
            "proxy_folder_purge: %p mask added, domain = \"%V\" (%d), "
            "mask = \"%V\" (%d), purge_start_time = %d",
            ms->sh->rbtree, domain, domain->len,
            mask, mask->len, mask_queue->mask.purge_start_time);

    ++qnode->value.len;

    return NGX_MASKS_STORAGE_OK;
}


static ngx_int_t
ngx_masks_storage_parse_request(ngx_masks_storage_t *ms,
        ngx_str_t *mask, time_t *purge_start_time, ngx_str_t *err)
{
    size_t               i;
    ngx_str_t            uri;
    ngx_table_elt_t     *h;
    ngx_list_part_t     *part;
    ngx_http_request_t  *r;
    time_t               current_time;

    r = ms->r;
    uri = ms->r->uri;

    mask->len = 0;
    mask->data = NULL;
    *purge_start_time = 0;
    ngx_str_set(err, "");

    ngx_time_update();

    current_time = ngx_time();

    mask->data = uri.data;
    mask->len = uri.len;

    /** Getting the type of operation */
    part = &r->headers_in.headers.part;
    h = part->elts;
    i = 0;

    for (;; i++) {

        if (i >= part->nelts) {

            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "proxy_folder_purge: process headers: \"%V\":\"%V\"",
                &h[i].key, &h[i].value);

        if ((h[i].key.len == (sizeof("x-purge-key") - 1)) &&
                  (ngx_strncmp(h[i].lowcase_key, (u_char *) "x-purge-key",
                                 h[i].key.len) == 0))
        {
            mask->data = h[i].value.data;
            mask->len = h[i].value.len;
        }
    }

    *purge_start_time = current_time;

    return NGX_MASKS_STORAGE_OK;
}
/**}}}*/


/** PURGE HTTP API {{{ */
static void
ngx_masks_storage_flush(ngx_masks_storage_t *ms)
{
    ngx_domain_rbtree_node_t       *n;
    ngx_rbtree_node_t              *node, *next, *root, *sentinel;
    ngx_masks_rbtree_node_t        *sub_n;
    ngx_rbtree_node_t              *sub_node, *sub_next,
                                   *sub_root, *sub_sentinel;
    ngx_slab_pool_t                *shpool;
    ngx_queue_t                    *q;
    ngx_mask_queue_t               *mask_queue;

    shpool = ms->shpool;

    ngx_shmtx_lock(&shpool->mutex);

    sentinel = ms->sh->sentinel;
    root = ms->sh->rbtree->root;

    if (root == sentinel) {
        goto exit;
    }

    node = ngx_rbtree_min(root, sentinel);
    while (node) {

        next = ngx_rbtree_next(ms->sh->rbtree, node);
        n = (ngx_domain_rbtree_node_t *) node;

        sub_sentinel = n->value.sentinel;
        sub_root = n->value.masks->root;

        if (sub_sentinel != sub_root) {

            sub_node = ngx_rbtree_min(sub_root, sub_sentinel);
            while (sub_node) {

                sub_next = ngx_rbtree_next(n->value.masks, sub_node);
                sub_n = (ngx_masks_rbtree_node_t *) sub_node;

                while (!ngx_queue_empty(&sub_n->mask_queue.queue)) {

                    q = ngx_queue_head(&sub_n->mask_queue.queue);

                    mask_queue = ngx_queue_data(q, ngx_mask_queue_t, queue);
                    if (mask_queue) {
                        ngx_slab_free_locked(shpool, mask_queue);
                    }

                    ngx_queue_remove(q);
                }

                ngx_rbtree_delete(n->value.masks, sub_node);
                ngx_slab_free_locked(shpool, sub_n->sn.str.data);
                ngx_slab_free_locked(shpool, sub_n);

                sub_node = sub_next;
            }
        }

        ngx_slab_free_locked(shpool, n->value.masks);

        ngx_rbtree_delete(ms->sh->rbtree, node);
        ngx_slab_free_locked(shpool, n->sn.str.data);
        ngx_slab_free_locked(shpool, n);

        node = next;
    }

exit:
    ngx_shmtx_unlock(&shpool->mutex);
}


/*
 * Bref:
 * A key logic is: write purge pattern into the append only file, iff limit is
 * not reached, and do not rollback, if insertion in rbtree failed;
 * reason: rollback is much complicated, at least background purge would
 * work and does compaction.
 * But(!): if can't write to file, then fail, else shared memory will not be
 * cleared.
 *
 * if is_restoring - no writing to append only file.
 */
static ngx_int_t
ngx_masks_storage_add_mask(ngx_masks_storage_t *ms, ngx_str_t *domain,
        ngx_str_t *mask, time_t purge_start_time,
        ngx_int_t is_restoring)
{
    ngx_slab_pool_t               *shpool;
    ngx_int_t                      rc;
    ngx_rbtree_node_t             *node;
    ngx_domain_rbtree_node_t      *qnode;
    ngx_mask_t                    *m;

    if (ms == NULL || domain == NULL || mask == NULL) {
        ngx_log_error(NGX_LOG_WARN, ms->log, 0,
                "proxy_folder_purge: ngx_masks_storage_add_mask: "
                "got invalid val(s), ms = %p, domain = %p, mask = %p",
                ms, domain, mask);
        return NGX_MASKS_STORAGE_FAIL;
    }

    qnode = NULL;
    shpool = ms->shpool;
    rc = NGX_MASKS_STORAGE_OK;

    if (is_restoring == 0) {

        ngx_mask_t mask_to_write = {
                .mask = *mask,
                .purge_start_time = purge_start_time,
                .ref_count = 0 };

        if (ngx_masks_write_to_masks_in(ms, domain, &mask_to_write)
                != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: can't persist the mask while updating "
                "domain = \"%V\", mask = \"%V\", purge_start_time = %d",
                domain, mask, purge_start_time);
            return NGX_MASKS_STORAGE_FAIL;
        }
    }

    ngx_shmtx_lock(&shpool->mutex);

    node = ngx_masks_lookup_domain_unlocked(ms, domain);

    /** Domain not found, insert a new node */
    if (node == NULL) {

        ngx_log_error(NGX_LOG_INFO, ms->log, 0,
                "proxy_folder_purge: "
                "domain \"%V\" NOT found in the storage; adding it",
                domain);

        node = ngx_masks_insert_domain_unlocked(ms, domain);
        if (node == NULL) {
            rc = NGX_MASKS_STORAGE_FAIL;
            ngx_log_error(NGX_LOG_ERR, ms->log, 0,
                "proxy_folder_purge: can't add \"%V\", "
                "the insert failed, rc = %d",
                domain, rc);
            goto out;
        }

    }
    /** Domain found. Update a tree, if mask exists or insert if does not.
     *
     * Update: It does update a purge_start_time and also saves
     * this information to the disk.
     *
     * Insert: It does add a new element and also saves this
     * information to the disk.
     */
    else {

        ngx_log_error(NGX_LOG_INFO, ms->log, 0,
                "proxy_folder_purge: domain \"%V\" found", domain);

        qnode = (ngx_domain_rbtree_node_t *) node;

        m = ngx_masks_lookup_mask_unlocked(ms, qnode, mask);
        if (m != NULL) {
            /** We have to have some limits here, or hackers may spam us
             */
            if (m->ref_count >
                    MASKS_STORAGE_PURGE_REF_COUNT_MAX)
            {
                rc = NGX_MASKS_STORAGE_LIMIT_REACHED;
                ngx_log_error(NGX_LOG_ERR, ms->log, 0,
                        "proxy_folder_purge: \"%V\""
                        "limit reached; ref_count: %d > limit: %d",
                        domain, m->ref_count, MASKS_STORAGE_PURGE_REF_COUNT_MAX);
                goto out;
            }

            m->purge_start_time = purge_start_time;

            ++m->ref_count;

            rc = NGX_MASKS_STORAGE_OK;
            goto out;
        }
    }

    rc = ngx_masks_insert_mask_unlocked(ms, node,
                                        domain, mask, purge_start_time);
    if (rc != NGX_MASKS_STORAGE_OK) {
        /** XXX We don't need rollback changes here, since it was'nt added */
        goto out;
    }

out:
    ngx_shmtx_unlock(&shpool->mutex);
    return rc;
}


/** Add masks from file into shared memory */
static ngx_int_t
ngx_masks_storage_restore_from_file(ngx_masks_storage_t *ms,
        ngx_str_t *path)
{
    ngx_int_t               rc;
    ngx_file_t              file;
    u_char                  *start, *end;
    ssize_t                 n;
    size_t                  size;
    ngx_file_info_t         fi;

    start = NULL;
    rc = NGX_ERROR;

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name.data = path->data;
    file.name.len = path->len;
    file.log = ms->log;
    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY, 0, 0);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: restoration failed, can't open a file, "
                "ms = %p, file = \"%V\"", ms, &file.name);
        return NGX_ERROR;
    }

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: restoration failed, can't stat a file, "
                "ms = %p, file = \"%V\"", ms, &file.name);
        goto exit;
    }

    size = ngx_file_size(&fi);

    start = ngx_palloc(ms->pool, size);
    if (!start) {
        goto exit;
    }

    end = start + size;

    n = ngx_read_file(&file, start, size, 0);
    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: restoration failed, can't read a file, "
                "ms = %p, file = \"%V\"", ms, &file.name);
        goto exit;
    }

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: restoration failed, can't read a file, "
                "returned only %z bytes instead of %uz ms = %p, file = \"%V\"",
                n, size, ms, &file.name);
        goto exit;
    }

    rc = ngx_deserialize_mask(ms, start, end,
            &ngx_masks_storage_add_mask);

    if (rc == NGX_ERROR) {
        goto exit;
    }

exit:
    if (start) {
        ngx_pfree(ms->pool, start);
    }

    (void) ngx_close_file(file.fd);

    return rc;
}


ngx_int_t
ngx_masks_storage_restore(ngx_masks_storage_t *ms, ngx_str_t *dirname)
{
    struct dirent   *dp;
    DIR             *dirp;
    u_char           full_path[PATH_MAX];
    u_char          *p;
    ngx_str_t        full_path_str;
    ngx_int_t        is_masks_in, is_masks_purger;
    ngx_int_t        rc;

    ngx_errno = 0;

    ngx_shmtx_lock(&ms->shpool->mutex);

    if (ms->sh->restoring == 0) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ms->log, 0,
                "proxy_folder_purge: restored already, ms = %p, path = \"%V\"",
                ms, dirname);
        ngx_shmtx_unlock(&ms->shpool->mutex);
        return NGX_DECLINED;
    }

    ngx_shmtx_unlock(&ms->shpool->mutex);

    /** Restoring {{{ */
    ngx_log_error(NGX_LOG_INFO, ms->log, 0,
            "proxy_folder_purge: restoring, ms = %p, path = \"%V\"",
            ms, dirname);

    dirp = opendir((char *) get_dirname(dirname));
    if (dirp == NULL) {
        ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: "
                "background purge can't open a directory = \"%s\" "
                "dirname  = \"%s\"", get_dirname(dirname), dirname);
        return NGX_ERROR;
    }

    rc = NGX_OK;

    while ((dp = readdir(dirp)) != NULL) {

        is_masks_in = 0;
        is_masks_purger = 0;

        p = ngx_snprintf(full_path, sizeof(full_path), "%V%s%Z",
                dirname, dp->d_name);
        full_path_str.data = &full_path[0];
        full_path_str.len = (size_t) (p - full_path_str.data);

        if ((dp->d_reclen == 1) && (dp->d_name[0] == '.')) {
            continue;
        }

        if ((dp->d_reclen == 2) && (dp->d_name[0] == '.') &&
                (dp->d_name[1] == '.'))
        {
            continue;
        }

        if (!is_regular_file(full_path)) {
            continue;
        }

        if ((dp->d_reclen > sizeof(MASKS_IN) - 1) &&
                (ngx_strncmp(dp->d_name, MASKS_IN, sizeof(MASKS_IN) - 1)
                    == 0))
        {
            is_masks_in = 1;
        }

        if ((dp->d_reclen == (sizeof(MASKS_PURGER) - 1)) &&
                (ngx_strncmp(dp->d_name, MASKS_PURGER,
                    sizeof(MASKS_PURGER) - 1) == 0))
        {
            is_masks_purger = 1;
        }

        if (is_masks_in == 0 && is_masks_purger == 0) {
            continue;
        }

        if (ngx_masks_storage_restore_from_file(ms, &full_path_str)
                != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: restoration failed, ms = %p, path = \"%V\"",
                ms, &full_path_str);
        }

        if (ngx_quit || ngx_terminate) {
            rc = NGX_ABORT;
            break;
        }
    }

    closedir(dirp);
    /** }}} */

    ngx_shmtx_lock(&ms->shpool->mutex);
    ms->sh->restoring = 0;
    ngx_shmtx_unlock(&ms->shpool->mutex);

    ngx_log_error(NGX_LOG_INFO, ms->log, 0,
            "proxy_folder_purge: restored successfully, ms = %p, path = \"%V\"",
            ms, dirname);

    return rc;
}


static ngx_int_t
ngx_masks_storage_foreach(ngx_masks_storage_t *ms,
    void *data, ngx_int_t (*on_element)(void *, ngx_mask_t *, ngx_str_t *))
{
    ngx_domain_rbtree_node_t        *n;
    ngx_rbtree_node_t               *node, *root, *sentinel;
    ngx_masks_rbtree_node_t         *sub_n;
    ngx_rbtree_node_t               *sub_node, *sub_root, *sub_sentinel;
    ngx_int_t                        rc;
    ngx_queue_t                     *q;
    ngx_mask_queue_t                *mqueue;

    if (ms == NULL || ms->sh == NULL || ms->sh->rbtree == NULL) {
        return NGX_OK;
    }

    sentinel = ms->sh->sentinel;
    root = ms->sh->rbtree->root;

    ngx_shmtx_lock(&ms->shpool->mutex);

    if (root == sentinel) {
        ngx_shmtx_unlock(&ms->shpool->mutex);
        return NGX_OK;
    }

    for (node = ngx_rbtree_min(root, sentinel);
         node;
         node = ngx_rbtree_next(ms->sh->rbtree, node))
    {
        n = (ngx_domain_rbtree_node_t *) node;

        sub_sentinel = n->value.sentinel;
        sub_root = n->value.masks->root;

        if (sub_sentinel != sub_root) {

            for (sub_node = ngx_rbtree_min(sub_root, sub_sentinel);
                 sub_node;
                 sub_node = ngx_rbtree_next(n->value.masks, sub_node))
            {
                sub_n = (ngx_masks_rbtree_node_t *) sub_node;

                for (q = ngx_queue_head(&sub_n->mask_queue.queue);
                        q != ngx_queue_sentinel(&sub_n->mask_queue.queue);
                        q = ngx_queue_next(q))
                {
                    mqueue = ngx_queue_data(q, ngx_mask_queue_t, queue);

                    rc = on_element(data, &mqueue->mask, &n->sn.str);
                    if (rc != NGX_OK) {
                        ngx_shmtx_unlock(&ms->shpool->mutex);
                        return rc;
                    }
                }
            }
        }
    }

    ngx_shmtx_unlock(&ms->shpool->mutex);

    return NGX_OK;
}
/** }}} */


/** PURGE HTTP API an entry point {{{ */
static ngx_int_t
ngx_http_cache_purge_folder_writer(void *ctx, ngx_mask_t *mask,
    ngx_str_t *domain)
{
    ngx_http_cache_purge_folder_writer_ctx_t *fw_ctx;
    ngx_pool_t                               *pool;
    ngx_chain_t                              *cl;
    ngx_buf_t                                *b;
    ngx_temp_file_t                          *tf;
    ssize_t                                   size, n;

    fw_ctx = (ngx_http_cache_purge_folder_writer_ctx_t *) ctx;
    pool = fw_ctx->r->pool;
    tf = fw_ctx->temp_file;

    size = (sizeof("{'mask':'','pst':,'domain':''},") - 1) +
                UINT32_STR_MAX + mask->mask.len +
                UINT64_STR_MAX + domain->len;

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }
    b = ngx_create_temp_buf(pool, size);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "{\"mask\":\"%V\",\"pst\":%T,\"domain\":\"%V\"},",
            &mask->mask, mask->purge_start_time, domain);

    cl->buf = b;
    cl->next = NULL;

    n = ngx_write_chain_to_temp_file(tf, cl);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }
    tf->offset += n;

    ngx_pfree(pool, b->start);
    ngx_pfree(pool, b);
    cl->buf = NULL;
    ngx_free_chain(pool, cl);

    return NGX_OK;
}


static ngx_int_t
ngx_http_cache_purge_folder_writer_format(
        ngx_http_cache_purge_folder_writer_ctx_t *ctx,
        char *str, ngx_int_t size)
{
    ngx_pool_t                               *pool;
    ngx_chain_t                              *cl;
    ngx_buf_t                                *b;
    ngx_temp_file_t                          *tf;
    ssize_t                                   n;

    pool = ctx->r->pool;
    tf = ctx->temp_file;

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }
    b = ngx_create_temp_buf(pool, size);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, str, size);

    cl->buf = b;
    cl->next = NULL;

    n = ngx_write_chain_to_temp_file(tf, cl);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }
    tf->offset += n;

    ngx_pfree(pool, b->start);
    ngx_pfree(pool, b);
    cl->buf = NULL;
    ngx_free_chain(pool, cl);

    return NGX_OK;
}


static ngx_int_t
ngx_http_cache_purge_folder_dump_shared_memory(ngx_http_request_t *r)
{
    /** TODO: optimise, limit, offset */

    ngx_masks_storage_loc_conf_t         *conf;
    ngx_int_t                                 rc;
    ngx_chain_t                               out;
    ngx_http_cache_purge_folder_writer_ctx_t  ctx;
    ngx_temp_file_t                          *tf;
    ngx_buf_t                                *b;
    off_t                                     size, start;

    conf = ngx_http_get_module_loc_conf(r, ngx_masks_storage_module);
    if (!conf->masks_storage) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "proxy_folder_purge: the module is off for \"%V\"", &r->uri);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
    if (tf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    tf->file.fd = NGX_INVALID_FILE;
    tf->file.log = r->connection->log;
    tf->path = conf->masks_storage->tmp_path;
    tf->pool = r->pool;
    tf->warn = "a folder dump response body is buffered to a temporary file";
    tf->log_level = 0;
    tf->persistent = 0;
    tf->clean = 1;

    ctx.r = r;
    ctx.temp_file = tf;

    rc = ngx_http_cache_purge_folder_writer_format(&ctx, "[", sizeof("[") - 1);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "proxy_folder_purge: ngx_http_cache_purge_folder_writer_format "
                "failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    start = tf->offset;

    rc = ngx_masks_storage_foreach(conf->masks_storage, (void *) &ctx,
            &ngx_http_cache_purge_folder_writer);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "proxy_folder_purge: ngx_masks_storage_foreach failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (tf->offset > start) {
        tf->offset--;
    }
    rc = ngx_http_cache_purge_folder_writer_format(&ctx, "]", sizeof("]") - 1);
    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    size = tf->offset;
    tf->offset = 0;

    r->headers_out.content_type.len = sizeof("application/json") - 1;
    r->headers_out.content_type.data = (u_char *) "application/json";
    r->headers_out.status = NGX_HTTP_OK;
    r->header_only = 0;
    r->headers_out.content_length_n = size;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "proxy_folder_purge: ngx_http_send_header failed");
        return rc;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file_pos = 0;
    b->file_last = size;

    b->in_file = 1;
    b->last_buf = 1;
    b->last_in_chain = 1;

    b->file->fd = tf->file.fd;
    b->file->name = tf->path->name;
    b->file->log = r->connection->log;
    b->file->directio = 0;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_cache_purge_folder_flush(ngx_http_request_t *r)
{
    ngx_masks_storage_loc_conf_t         *conf;
    ngx_int_t                                 rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_masks_storage_module);
    if (conf->masks_storage == NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "proxy_folder_purge: the module is off for \"%V\"", &r->uri);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_masks_storage_flush(conf->masks_storage);

    r->headers_out.content_type.len = 0;
    r->headers_out.content_type.data = NULL;
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
       return rc;
    }

    return NGX_HTTP_OK;
}


static int
fnmatch_adapter(ngx_pool_t *pool, ngx_log_t *log,
        ngx_str_t *pattern, ngx_str_t *url)
{
    int   ret;
    char *p, *u, *e;

    if (pool == NULL || pattern == NULL || url == NULL) {
        return -1;
    }

    p = ngx_palloc(pool, pattern->len + 1);
    if (p == NULL) {
        return -1;
    }
    e = (char *) ngx_copy(p, pattern->data, pattern->len);
    *e++ = '\0';

    u = ngx_palloc(pool, url->len + 1);
    if (u == NULL) {
        return -1;
    }
    e = (char *) ngx_copy(u, url->data, url->len);
    *e++ = '\0';

    ret = fnmatch(p, u, 0);

    ngx_log_error(NGX_LOG_INFO, log, 0,
                "proxy_folder_purge: "
                "fnmatch: match result %d, pattern = %s ~ url = %s",
                (int) ret, p, u);
    return ret;
}


static ngx_str_t
make_domain_key(ngx_pool_t *pool, ngx_str_t *cache_path, ngx_str_t *domain)
{
    ngx_str_t r;
    u_char    *p;

    ngx_str_set(&r, "");

    if (cache_path->len == 0) {
        r = *domain;
        return r;
    }

    r.len = cache_path->len + (sizeof(":") - 1) + domain->len;
    r.data = ngx_palloc(pool, r.len);
    if (r.data == NULL) {
        r.len = 0;
        return r;
    }

    p = ngx_copy(r.data, cache_path->data, cache_path->len);
    p = ngx_copy(p, ":", sizeof(":") - 1);
    p = ngx_copy(p, domain->data, domain->len);

    return r;
}


static void
parse_domain_key(ngx_str_t *b, ngx_str_t *cache_path, ngx_str_t *domain)
{
    u_char *p, *e;

    domain->data = (cache_path->data = b->data);
    domain->len = (cache_path->len = b->len);

    p = b->data;
    e = b->data + b->len;

    for (; p != e; ++p) {

        if (*p == ':') {
            ++p;
            domain->data = p;
            domain->len = (size_t) (e - p);
            cache_path->len = cache_path->len - domain->len - 1;
            return;
        }
    }
}


ngx_int_t
ngx_http_foreground_purge(ngx_http_request_t *r,
        ngx_http_cache_t *c, time_t now)
{
    ngx_masks_storage_shctx_t        *sh;
    ngx_slab_pool_t                  *shpool;
    ngx_domain_rbtree_node_t         *node;
    ngx_str_t                        *mask, domain, *url, temp_url;
    ngx_mask_t                       *v;
    ngx_masks_storage_t              *masks_storage;
    ngx_masks_storage_loc_conf_t     *conf;
    ngx_core_conf_t                  *ccf;
    ngx_int_t                         cnt;
    ngx_masks_rbtree_node_t          *sub_node;
    ngx_queue_t                      *q;
    ngx_mask_queue_t                 *mask_queue;

    if (c == NULL
        || c->node == NULL
        || (c->node->updating && c->updating)
        || c->valid_sec < now
        /* This module may be recalled. Ignore sub-requests. */
        || r != r->main)
    {
        return NGX_DECLINED;
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
            ngx_core_module);

    if (!ccf->master) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "proxy_folder_purge: not support with \"master_process off;\"");
        return NGX_DECLINED;
    }

    /* Do no do anythong for non-purge requests */
    if (r->method_name.len == (sizeof("PURGE") - 1) &&
            ngx_strncasecmp(r->method_name.data, (u_char *) "PURGE",
                             sizeof("PURGE") -1) == 0)
    {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_masks_storage_module);

    /* The module is off */
    if (!conf->masks_storage) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "proxy_folder_purge: the module is off for \"%V\"", &r->uri);
        return NGX_DECLINED;
    }

    /** Module is on, but the feature is off */
    if (!conf->foreground_purge_enable) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "foreground purge: feature is off for \"%V\"", &r->uri);
        return NGX_DECLINED;
    }

    masks_storage = conf->masks_storage;
    v = NULL;
    sh = masks_storage->sh;
    shpool = masks_storage->shpool;
    url = &r->uri;
    domain = make_domain_key(r->pool, &conf->cache_path,
                &r->headers_in.server);

    ngx_shmtx_lock(&shpool->mutex);

    if (sh->restoring) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "proxy_folder_purge: masks storage is restoring, skiping");
        goto out;
    }

    node = (ngx_domain_rbtree_node_t *)
        ngx_masks_lookup_domain_unlocked(masks_storage, &domain);
    if (node == NULL) {
        /** This domain does not have any active purges */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "foreground purge: domain does not have any active purges, "
                "domain = \"%V\"", &domain);
        goto out;
    }

    temp_url.len = url->len;
    temp_url.data = url->data;
    cnt = 0;

    while (temp_url.len > 0) {

        sub_node = ngx_masks_get_mask_queue_unlocked(
                        masks_storage, node, &temp_url, 1);
        if (sub_node == NULL) {
            goto next_path;
        }

        for (q = ngx_queue_head(&sub_node->mask_queue.queue);
             q != ngx_queue_sentinel(&sub_node->mask_queue.queue);
             q = ngx_queue_next(q))
        {
            mask_queue = ngx_queue_data(q, ngx_mask_queue_t, queue);
            v = &mask_queue->mask;

            if (v->mask.data == NULL) {
                continue;
            }

            mask = &v->mask;

            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "proxy_folder_purge: compare "
                    "mask = \"%V\" ~ url = \"%V\" ~ temp_url = \"%V\" "
                    "purge_start_time = %d ~ cache_create_time = %d",
                    mask, url, &temp_url, v->purge_start_time, c->date);

            /** First check that purge_start_time > cache_create_time
             * since it may skip a lot of string compare operations */
            if (c->date <= v->purge_start_time) {

                if (fnmatch_adapter(r->pool, r->connection->log,
                        mask, &temp_url) == 0)
                {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                        "proxy_folder_purge: \"%V\" purged", &r->uri);
                    c->valid_sec = 0;
                    r->upstream->cache_status = NGX_HTTP_CACHE_BYPASS;
                    goto out;
                }
            }
        } /** for */

next_path:
        cnt = next_path(&temp_url, cnt);
    }

out:
    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_DONE;
}


ngx_int_t
ngx_http_folder_cache_purge(ngx_http_request_t *r)
{
    ngx_str_t                         domain, mask, err;
    ngx_int_t                         rc;
    time_t                            purge_start_time;
    ngx_masks_storage_loc_conf_t     *conf;
    ngx_core_conf_t                  *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
            ngx_core_module);

    if (!ccf->master) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "proxy_folder_purge: not support with \"master_process off;\"");
        return NGX_MASKS_STORAGE_DENY;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_masks_storage_module);

    /**
     * The module is off
     */
    if (!conf->masks_storage) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "proxy_folder_purge: the module is off for \"%V\"", &r->uri);
        return NGX_MASKS_STORAGE_DENY;
    }

    err.data = NULL;
    err.len = 0;

    conf->masks_storage->r = r;
    conf->masks_storage->log = r->connection->log;

    rc = ngx_masks_storage_parse_request(conf->masks_storage,
            &mask, &purge_start_time, &err);
    if (rc != NGX_MASKS_STORAGE_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "proxy_folder_purge: can't parse request, rc = %d", rc);
        return rc;
    }

    domain = make_domain_key(r->pool, &conf->cache_path, &r->headers_in.server);

    rc = ngx_masks_storage_add_mask(conf->masks_storage, &domain, &mask,
            purge_start_time, 0);
    if (rc == NGX_MASKS_STORAGE_LIMIT_REACHED) {
        ngx_str_set(&err, "can't add a mask: ref count limit has been "
                "reached. Please retry later. Current limit is: "
                MASKS_STORAGE_PURGE_REF_COUNT_MAX_STR);
    }

    return rc;
}


ngx_int_t
ngx_http_folder_dump(ngx_http_request_t *r)
{
    size_t                            i;
    ngx_table_elt_t                  *h;
    ngx_list_part_t                  *part;
    ngx_masks_storage_loc_conf_t     *conf;
    ngx_core_conf_t                  *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
            ngx_core_module);

    if (!ccf->master) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "proxy_folder_purge: not support with \"master_process off;\"");
        return NGX_MASKS_STORAGE_SERVICE_DISABLE;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_masks_storage_module);

    /**
     * The module is off
     */
    if (!conf->masks_storage) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "proxy_folder_purge: the module is off for \"%V\"", &r->uri);
        return NGX_MASKS_STORAGE_SERVICE_DISABLE;
    }

    part = &r->headers_in.headers.part;
    h = part->elts;
    i = 0;

    for (;; i++) {

        if (i >= part->nelts) {

            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if ((h[i].key.len == (sizeof("x-purge-options") - 1)) &&
                (ngx_strncmp(h[i].lowcase_key,
                            (u_char *) "x-purge-options",
                            /* len(lowcase_key) == len(key) */
                            h[i].key.len) == 0))
        {
            if ((h[i].value.len == (sizeof("dump") - 1)) &&
                    (ngx_strncmp(h[i].value.data, "dump",
                        h[i].value.len) == 0))
            {
                return NGX_MASKS_STORAGE_OK;
            }
        }
    }

    return NGX_MASKS_STORAGE_DENY;
}


ngx_int_t
ngx_http_folder_flush(ngx_http_request_t *r)
{
    size_t                            i;
    ngx_table_elt_t                  *h;
    ngx_list_part_t                  *part;
    ngx_masks_storage_loc_conf_t *conf;
    ngx_core_conf_t                  *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
            ngx_core_module);

    if (!ccf->master) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "proxy_folder_purge: not support with \"master_process off;\"");
        return NGX_MASKS_STORAGE_SERVICE_DISABLE;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_masks_storage_module);

    /**
     * The module is off
     */
    if (!conf->masks_storage) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "proxy_folder_purge: the module is off for \"%V\"", &r->uri);
        return NGX_MASKS_STORAGE_SERVICE_DISABLE;
    }

    part = &r->headers_in.headers.part;
    h = part->elts;
    i = 0;

    for (;; i++) {

        if (i >= part->nelts) {

            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if ((h[i].key.len == (sizeof("x-purge-options") - 1)) &&
                (ngx_strncmp(h[i].lowcase_key,
                            (u_char *) "x-purge-options",
                            /* len(lowcase_key) == len(key) */
                            h[i].key.len) == 0))
        {
            if ((h[i].value.len == (sizeof("flush") - 1)) &&
                    (ngx_strncmp(h[i].value.data, "flush",
                        h[i].value.len) == 0))
            {
                return NGX_MASKS_STORAGE_OK;
            }
        }
    }

    return NGX_MASKS_STORAGE_DENY;
}


ngx_int_t
ngx_http_folder_send_dump_handler(ngx_http_request_t *r)
{
    r->main->count++;
    r->write_event_handler = ngx_http_request_empty_handler;
    ngx_http_finalize_request(r,
            ngx_http_cache_purge_folder_dump_shared_memory(r));
    return NGX_DONE;
}


ngx_int_t
ngx_http_folder_send_flush_handler(ngx_http_request_t *r)
{
    r->main->count++;
    r->write_event_handler = ngx_http_request_empty_handler;
    ngx_http_finalize_request(r, ngx_http_cache_purge_folder_flush(r));
    return NGX_DONE;
}
/**}}}*/


/** ngx_masks_storage_core_api.h {{{ */
static ngx_int_t
ngx_masks_storage_purger_add_mask(ngx_masks_storage_t *ms,
    ngx_str_t *unparsed_key, ngx_str_t *mask, time_t purge_start_time,
    ngx_int_t is_restoring)
{
    (void) is_restoring;

    ngx_str_t cache_path, domain;

    ngx_full_mask_t *full_mask;

    parse_domain_key(unparsed_key, &cache_path, &domain);

    ngx_log_error(NGX_LOG_INFO, ms->log, 0,
            "proxy_folder_purge: ngx_masks_storage_purger_add_mask: "
            "cache_path = \"%V\"  domain = \"%V\"",
            &cache_path, &domain);

    full_mask = ngx_masks_push_purge_mask(ms, &cache_path);
    if (full_mask == NULL) {
        ngx_log_error(NGX_LOG_ERR, ms->log, 0,
                "proxy_folder_purge: ngx_masks_push_purge_mask: failed, ms = %p",
                ms);
        return NGX_MASKS_STORAGE_FAIL;
    }

    /** Domain */
    full_mask->domain.len = domain.len;
    full_mask->domain.data = ngx_palloc(ms->pool,
            sizeof(u_char) * domain.len + 1 /* \0 - \0 */);
    if (full_mask->domain.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, ms->log, 0,
                "proxy_folder_purge: can't clone domain, ms = %p",
                ms);
        return NGX_MASKS_STORAGE_FAIL;
    }
    ngx_snprintf(full_mask->domain.data, domain.len, "%V%Z", &domain);

    /** Mask */
    full_mask->mask.mask.len = mask->len;
    full_mask->mask.mask.data = ngx_palloc(ms->pool,
            sizeof(u_char) * mask->len + 1 /* \0 - \0 */);
    if (full_mask->mask.mask.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, ms->log, 0,
                "proxy_folder_purge: can't clone mask, ms = %p",
                ms);
        return NGX_MASKS_STORAGE_FAIL;
    }

    ngx_snprintf(full_mask->mask.mask.data, mask->len, "%V%Z", mask);

    /** Purge start time */
    full_mask->mask.purge_start_time = purge_start_time;

    return NGX_MASKS_STORAGE_OK;
}


static inline void
ngx_masks_storage_purger_queue_free_part(ngx_masks_storage_t *ms,
        ngx_str_t *cache_path, ngx_list_part_t *part)
{
    ngx_uint_t                   i;
    ngx_full_mask_t             *fm;
    ngx_domain_rbtree_node_t    *n;
    ngx_rbtree_node_t           *node;
    ngx_slab_pool_t             *shpool;
    ngx_str_t                   *mask, *masksh, domain;
    ngx_int_t                    rc;
    ngx_masks_rbtree_node_t     *sub_node;
    ngx_queue_t                 *q;
    ngx_mask_queue_t            *mask_queue;

    shpool = ms->shpool;
    fm = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            fm = part->elts;
            i = 0;
        }

        ngx_shmtx_lock(&shpool->mutex);

        domain = make_domain_key(ms->pool, cache_path, &fm[i].domain);

        node = (ngx_rbtree_node_t *)
            ngx_str_rbtree_lookup(ms->sh->rbtree, &domain, ngx_crc32_long(
                        domain.data, domain.len));

        ngx_log_error(NGX_LOG_INFO, ms->log, 0,
                "proxy_folder_purge: cleanup shmem %p "
                "domain = \"%V\", domain not parsed = \"%V\", cache path = \"%V\", found = %s",
                ms->sh->rbtree, &domain, &fm[i].domain, cache_path,
                (node != NULL ? "yes" : "no"));

        if (node == NULL) {
            goto shmtx_unlock;
        }

        n = (ngx_domain_rbtree_node_t *) node;
        mask = &fm[i].mask.mask;

        sub_node = ngx_masks_get_mask_queue_unlocked(ms, n, mask, 1);
        if (sub_node == NULL) {
            goto shmtx_unlock;
        }

        for (q = ngx_queue_head(&sub_node->mask_queue.queue);
             q != ngx_queue_sentinel(&sub_node->mask_queue.queue);
             q = ngx_queue_next(q))
        {
            mask_queue = ngx_queue_data(q, ngx_mask_queue_t, queue);
            masksh = &mask_queue->mask.mask;

            rc = ngx_masks_compare(ms, mask, masksh);

            ngx_log_error(NGX_LOG_INFO, ms->log, 0,
                "proxy_folder_purge: compare sh = \"%V\" ~ mask = \"%V\", "
                "is equal = %s, ref_count = %d",
                masksh, mask, (rc == NGX_DECLINED) ? "yes" : "no",
                (ngx_int_t) mask_queue->mask.ref_count);

            if (rc == NGX_DECLINED) {
                continue;
            }

            --mask_queue->mask.ref_count;

            if (mask_queue->mask.ref_count == 0 ||
                /** This case is possible then shared memory has been
                 * corrupted */
                mask_queue->mask.ref_count
                    > MASKS_STORAGE_PURGE_REF_COUNT_MAX)
            {
                ngx_queue_remove(q);
                ngx_slab_free_locked(shpool, mask_queue);
                --n->value.len;
            }

            break;
        }

        if (ngx_queue_empty(&sub_node->mask_queue.queue)) {

            ngx_rbtree_delete(n->value.masks, &sub_node->sn.node);
            ngx_slab_free_locked(shpool, sub_node->sn.str.data);
            ngx_slab_free_locked(shpool, sub_node);
        }

        if (n->value.len == 0) {

            ngx_slab_free_locked(shpool, n->value.masks);
            ngx_rbtree_delete(ms->sh->rbtree, node);
            ngx_slab_free_locked(shpool, n->sn.str.data);
            ngx_slab_free_locked(shpool, n);
        }

shmtx_unlock:
        ngx_shmtx_unlock(&shpool->mutex);
    }

}


static inline void
ngx_masks_storage_purger_queue_free(ngx_masks_storage_t *ms)
{
    ngx_masks_purge_queue_t *elt,
                            *tmp;

    HASH_ITER(hh, ms->per_domain_purge_masks, elt, tmp) {
        ngx_masks_storage_purger_queue_free_part(ms, &elt->domain,
                &elt->purge_urls.part);
        ngx_memzero(&elt->purge_urls, sizeof(ngx_list_t));
    }

    HASH_CLEAR(hh, ms->per_domain_purge_masks);

    ms->per_domain_purge_masks = NULL;
}


/**
 * Append masks from specified file into local purger queue
 */
static ngx_int_t
ngx_masks_storage_read_purger_queue(ngx_masks_storage_t *ms,
    u_char *filename)
{
    ngx_int_t               rc;
    ngx_file_t              file;
    u_char                  *start, *end;
    ssize_t                 n;
    size_t                  size;
    ngx_file_info_t         fi;

    start = NULL;
    rc = NGX_ERROR;

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name.data = filename;
    file.name.len = ngx_strlen(filename);
    file.log = ms->log;
    file.fd = ngx_open_file(filename, NGX_FILE_RDONLY, 0, 0);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: can't open a file, "
                "ms = %p, file = \"%V\"", ms, &file.name);
        return NGX_ERROR;
    }

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: can't stat a file, "
                "ms = %p, file = \"%V\"", ms, &file.name);
        goto exit;
    }

    size = ngx_file_size(&fi);

    start = ngx_palloc(ms->pool, size);
    if (!start) {
        goto exit;
    }

    end = start + size;

    n = ngx_read_file(&file, start, size, 0);

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: can't read a file ",
                "ms = %p, file = \"%V\"", ms, &file.name);
        goto exit;
    }

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: can't read a file "
                "returned only %z bytes instead of %uz ms = %p, file = \"%V\"",
                n, size, ms, &file.name);
        goto exit;
    }

    ngx_sha1_update(&ms->masks_sha1_state, start, size);
    rc = ngx_deserialize_mask(ms, start, end,
            &ngx_masks_storage_purger_add_mask);
    if (rc == NGX_ERROR) {
        goto exit;
    }

exit:
    if (start) {
        ngx_pfree(ms->pool, start);
    }

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        /** Warning? */
        ngx_log_error(NGX_LOG_ERR, ms->log, ngx_errno,
                "proxy_folder_purge: " ngx_close_file_n " \"%V\" failed",
                &file.name);
    }

    ngx_log_error(NGX_LOG_INFO, ms->log, 0,
            "proxy_folder_purge: read purger queue, rc = %d", rc);

    return rc;
}


/**
 * Dump handler called then we wish to slow down
 * disk scanning.
 */
static void
ngx_dumb_timer(ngx_event_t *ev)
{
    return;
}


static void
ngx_background_purge_slowdown(ngx_masks_storage_t *m,
    ngx_cycle_t *cycle, ngx_event_t *ev)
{
    ngx_msec_t                      elapsed;
    ngx_int_t                       do_sleep;
    ngx_connection_t                dumb_con;

    ngx_time_update();

    do_sleep = 0;

    if (++m->processed_files >= m->background_purger_files) {
        do_sleep = 1;

    } else {

        elapsed = ngx_abs((ngx_msec_int_t) (ngx_current_msec - m->last));

        if (m->background_purger_threshold > 0 &&
            elapsed >= m->background_purger_threshold)
        {
            do_sleep = 1;
        }
    }

    if (do_sleep) {

        ngx_log_error(NGX_LOG_INFO, m->log, 0,
                "proxy_folder_purge: slowdown for %T msec, last slowdown = %T",
                m->background_purger_sleep, m->last);

        ngx_memzero(&dumb_con, sizeof(ngx_connection_t));
        ev->handler = ngx_dumb_timer;
        ev->log = m->log;
        ev->data = &dumb_con;
        dumb_con.fd = (ngx_socket_t) -1;

        ngx_add_timer(ev, m->background_purger_sleep);
        ngx_process_events_and_timers(cycle);

        m->last = ngx_current_msec;
        m->processed_files = 0;
    }
}


/** Filename is always NUL-terminated */
static ngx_int_t
ngx_remove_file(void *ctx_, ngx_masks_fs_walker_ctx *entry)
{
    static u_char cache_key[] = { LF, 'K', 'E', 'Y', ':', ' ' };
    static size_t header_size = sizeof(ngx_http_file_cache_header_t)
                    + sizeof(cache_key);

    ngx_remove_file_ctx_t            *ctx = ctx_;

    ngx_str_t                         url, domain;
    ngx_masks_storage_t              *m;
    ngx_int_t                         fd, rc;
    u_char                            buf[sizeof(ngx_http_file_cache_header_t)
                                         + sizeof(cache_key) + 2 * 4096]
                                            __attribute__((aligned(sizeof(ngx_uint_t))));
    u_char                           *buf_start, *buf_end,
                                     *url_start,
                                     *url_end;
    ngx_http_file_cache_header_t     *h;
    ngx_full_mask_t                  *mask, *fm;
    ngx_uint_t                        buf_size;
    ngx_uint_t                        i;
    ngx_list_part_t                  *part;
    ngx_cycle_t                      *cycle;
    ngx_event_t                      *ev;


    fd = -1;
    m = ctx->masks;
    cycle = ctx->cycle;
    ev = ctx->ev;

    ngx_log_error(NGX_LOG_INFO, m->log, 0,
        "proxy_folder_purge: ngx_remove_file: at file \"%s\"",
        entry->full_path);

    rc = NGX_OK;

    fd = openat(entry->cfd, entry->e_name, O_RDWR | O_SYNC | O_NOFOLLOW);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_INFO, m->log, ngx_errno,
                "proxy_folder_purge: ngx_remove_file: can't open a file "
                "\"%s\". Possible that nginx's cache manger did a remove",
                entry->full_path);
        return NGX_OK;
    }

    buf_size = sizeof(buf);

#if _POSIX_C_SOURCE >= 200112L
    /* This will make OS to read only 3 pages
     * from device instead of 64kb readahead
     */
    (void) posix_fadvise(fd, 0, buf_size, POSIX_FADV_RANDOM);
#endif /* posix_fadvise */

    rc = pread(fd, buf, buf_size, 0);
    if (rc == -1 || rc < (off_t) header_size) {

        ngx_log_error(NGX_LOG_INFO, m->log, ngx_errno,
                "proxy_folder_purge: ngx_remove_file: can't read a file "
                "\"%s\", rc = %d, hs = %d",
                entry->full_path, rc, (ngx_int_t) header_size);
        rc = NGX_ABORT;
        goto exit;
    }

    h = (ngx_http_file_cache_header_t *) &buf[0];

    buf_start = &buf[0] + header_size;
    buf_end = buf_start + rc;

    rc = NGX_OK;

    if (h->version != NGX_HTTP_CACHE_VERSION) {
        /** This will be deleted by nginx */
        ngx_log_error(NGX_LOG_ERR, m->log, 0,
                "proxy_folder_purge: ngx_remove_file: "
                "cache file \"%s\" version mismatch",
                entry->full_path);
        /** NGX_OK */
        rc = NGX_OK;
        goto exit;
    }

    domain.data = buf_start;
    domain.len = 0;

    /** TODO:
     *  this should be removed in the future, since it
     *  can make module less predictable for users.
     *  Also check matching logic
     *  Skip schema if exists {{{ */
    while (*buf_start != '/') {

        /** Read a domain, if exist: */
        if (*buf_start == ':') {
            domain.len = (size_t) (buf_start - domain.data);
        }

        buf_start++;
    }

    if (domain.len == 0) {
        domain.data = NULL;
    }
    /** }}} */

    url_start = buf_start;
    url_end = buf_end;

    /** Exclude extra cache args: */
    for ( ;buf_start != buf_end; ++buf_start) {

        if (*buf_start == '|'
            || *buf_start == '\n'
            || *buf_start == '[')
        {
            url_end = buf_start;
            break;
        }
    }

    if (url_start == NULL || url_end == NULL) {

        ngx_log_error(NGX_LOG_ERR, m->log, 0,
            "proxy_folder_purge: ngx_remove_file: can't find an url in the key "
            "at \"%s\", skiping", entry->full_path);
        /** NGX_OK */;
        rc = NGX_OK;
        goto exit;
    }

    url.data = url_start;
    url.len = (size_t) (url_end - url_start);
    /** }}} */

    /** Compare urls & dates */
    part = &ctx->purge_urls->part;
    fm = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            fm = part->elts;
            i = 0;
        }

        mask = &fm[i];

        ngx_log_error(NGX_LOG_INFO, m->log, 0,
                "proxy_folder_purge: "
                "test a file = \"%s\" "
                "url = \"%V\" ~ mask = %V (%V), "
                "domain = \"%V\", "
                "h->date = %d ~ purge_start_time = %d",
                entry->full_path,
                &url, &mask->mask.mask,
                &mask->domain, &domain,
                (ngx_int_t) h->date, (ngx_int_t) mask->mask.purge_start_time);

        if (domain.len != 0 && !(mask->domain.len == domain.len
                && ngx_strncmp(mask->domain.data, domain.data, domain.len)
                    == 0))
        {
            continue;
        }

        if (fnmatch_adapter(m->pool, m->log, &mask->mask.mask, &url) != 0) {
            continue;
        }

        if (h->date > mask->mask.purge_start_time) {
            goto exit;
        }

        ngx_log_error(NGX_LOG_INFO, m->log, 0,
                "proxy_folder_purge: delete a file = \"%s\" "
                "url = \"%V\"", entry->full_path, &url);

        if (unlinkat(entry->cfd, entry->e_name, 0) == -1) {
            ngx_log_error(NGX_LOG_WARN, m->log, ngx_errno,
                    "proxy_folder_purge: can't remove a file \"%s\"",
                    entry->full_path);
            /** NOTE
             * Do not break, even if removal is not possible for some
             * reasons.
             */
        }

        ++m->removed_files;

        break;
    } /* for */

exit:

    (void) close(fd);

    /** Master has been restarted or terminated.
     */
    if (ngx_quit || ngx_terminate) {
        m->walk_tree_failed = 1;
        return NGX_ABORT;
    }

    ngx_background_purge_slowdown(m, cycle, ev);

    ++m->processed_files;

    return rc;
}


ngx_int_t
ngx_masks_storage_purger_is_off(void *ms)
{
    ngx_masks_storage_t *m = (ngx_masks_storage_t *) ms;

    if (m == NULL || m->background_purger_off == 1) {
        return NGX_OK;
    }

    return NGX_DECLINED;
}

/**
 * Background Purge [[[
 */
ngx_int_t
ngx_masks_storage_background_purge_init(ngx_cycle_t *cycle, void *ms,
        ngx_pool_t *pool, ngx_log_t *log, ngx_str_t *dirname)
{
    ngx_masks_storage_t *m = (ngx_masks_storage_t *) ms;

    if (ms == NULL
            || pool == NULL
            || log == NULL
            || dirname == NULL)
    {
        return NGX_ERROR;
    }

    m->log = log;
    m->pool = pool;

    if (ngx_masks_storage_acquire_lock_file(cycle, m, dirname) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_masks_storage_restore(m, dirname);
}


/** Attempts to save checkpoint. Any errors are silently ignored. */
static void
save_checkpoint(void *data, const char *checkpoint)
{
    ngx_masks_checkpoint_t *ck = data;
    ck->path_checkpoint.data = (u_char*) checkpoint;
    ck->path_checkpoint.len = strlen(checkpoint);
    ngx_masks_save_checkpoint(ck);
}


ngx_msec_t
ngx_masks_storage_background_purge(void *ms, ngx_pool_t *pool,
        ngx_log_t *log, ngx_str_t *dirname, ngx_cycle_t *cycle,
        ngx_event_t *ev)
{
    ngx_masks_storage_t              *m = (ngx_masks_storage_t *) ms;

    ngx_uint_t                        i;
    ngx_int_t                         rc;
    ngx_array_t                      *roots;
    ngx_str_t                        *path;
    ngx_masks_checkpoint_t           *ck;
    ngx_remove_file_ctx_t             rm_ctx;
    const char                       *checkpoint;
    ngx_str_t                         domain;

    if (ms == NULL || pool == NULL || log == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "proxy_folder_purge: invalid pointer ms = %p, poll = %p, log = %p",
            ms, pool, log);
        goto out;
    }

    m->log = log;
    m->pool = pool;

    path = ngx_cycle->paths.elts;

    m->removed_files = 0;
    m->processed_files = 0;
    m->walk_tree_failed = 0;
    m->last = 0;
    m->start_time = ngx_time();

    rm_ctx.masks = m;
    rm_ctx.cycle = cycle;
    rm_ctx.ev = ev;

    ck = ngx_masks_load_checkpoint(dirname, pool, m->masks_sha1);
    if (ck == NULL) {
        ngx_log_error(NGX_LOG_ERR, m->log, 0,
                      "proxy_folder_purge: unable to load checkpoint");
        goto out;
    }

    /* set current masks checksum */
    memcpy(ck->checksum, m->masks_sha1, sizeof(ck->checksum));

    roots = ngx_masks_prepare_paths(ms, (ngx_array_t*) &ngx_cycle->paths, ck);
    if (roots == NULL) {
        goto out;
    }

    path = roots->elts;
    checkpoint = (ck != NULL) ? (char*) ck->path_checkpoint.data : NULL;

    /*
     * Searching & revoming cached date
     */
    for (i = 0; i < roots->nelts; i++) {

        ngx_log_error(NGX_LOG_INFO, log, 0,
                "proxy_folder_purge: working on path = \"%V\"",
                &path[i]);

        ck->cycle_path = path[i];

        /* Find masks queue per domain */
        domain = ngx_masks_get_domain_from_path(&path[i]);

        rm_ctx.purge_urls = ngx_masks_get_per_domain_purge_queue(ms, &domain);

        rc = ngx_masks_walk_fs((char*) path[i].data, checkpoint,
                                ngx_remove_file, &rm_ctx,
                                save_checkpoint, ck);

        /* checkpoint only affects the very first entry */
        checkpoint = NULL;

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, m->log, ngx_errno,
                    "proxy_folder_purge: can't read a path = \"%V\"",
                    &path[i]);
        } else if (rc == NGX_ABORT || rc == NGX_DECLINED) {

            if (!m->walk_tree_failed) {
                ngx_log_error(NGX_LOG_ERR, m->log, ngx_errno,
                    "proxy_folder_purge: can't purge a file, request failed "
                    "probably process is interupted by purge");
                continue;
            }

            break;
        }
    } /* for */

    /** All goes well, cleanup all resources, print some stats */
    ngx_log_error(NGX_LOG_INFO, m->log, 0,
            "proxy_folder_purge: finished purge queue = \"%s\", "
            "processed files = %d, removed files = %d, "
            "exec. time (in sec) = %d",
             m->purger_filename, m->processed_files, m->removed_files,
             ngx_time() - m->start_time);

    /* Remove checkpoint on successful exit.
     * We may run into situation when ngx_masks_storage_remove_purger_file()
     * fails and next purger run will have to do everything from scratch.
     * But we're protected against situation when purge masks files are removed,
     * but state is clean - in this case new run will try to resume from previous
     * iteration checkpoint.
     * It could be improved by comparing timestamps of checkpoint/purger files,
     * but that would be: a) complex; b) sensitive to clock skew */
    if (unlink(ck->state_fname) != 0 && errno != ENOENT) {
        ngx_log_error(NGX_LOG_ERR, m->log, 0,
                      "proxy_folder_purge: can't remove checkpoint file \"%s\"",
                      ck->state_fname);
        goto out;
    }

    if (ngx_masks_storage_remove_purger_file(m, dirname) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, m->log, 0,
                "proxy_folder_purge: can't remove purger file \"%V\"",
                dirname);
        goto out;
    }

out:
    ngx_masks_storage_purger_queue_free(m);

    return PURGER_DEFAULT_NEXT;
}


static ngx_int_t
ngx_masks_storage_old_purger_file(ngx_masks_storage_t *m,
    ngx_str_t *dirname, DIR *dirp, char **names)
{
    char             *name;
    u_char           full_path[PATH_MAX + 1];
    ngx_int_t        cnt;

    cnt = 0;

    ngx_sha1_init(&m->masks_sha1_state);
    ngx_sha1_update(&m->masks_sha1_state,
                    NGX_MASKS_CKPOINT_MAGIC, sizeof(NGX_MASKS_CKPOINT_MAGIC));

    while ((name = get_regular_file_with_prefix(dirp, &names,
            MASKS_PURGER, sizeof(MASKS_PURGER) - 1, NULL)) != NULL)
    {
        ngx_snprintf(full_path, sizeof(full_path), "%V/%s%Z",
                dirname, name);

        ngx_log_error(NGX_LOG_INFO, m->log, 0,
                      "proxy_folder_purge: found a purge queue file = \"%s\"",
                      full_path);

        if (ngx_masks_storage_read_purger_queue(m, full_path) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, m->log, 0,
                    "proxy_folder_purge: ngx_masks_storage_read_purger_queue "
                    "failed; background purge does not work");
            closedir(dirp);
            return -3;
        }
        cnt++;
    }

    ngx_sha1_final(m->masks_sha1, &m->masks_sha1_state);

    return cnt;
}


static ngx_int_t
ngx_masks_storage_remove_purger_file(ngx_masks_storage_t *m,
    ngx_str_t *dirname)
{
    DIR             *dirp;
    const u_char    *dirn;
    int              dfd;
    struct dirent   *e;
    struct stat      st_buf;

    dirn = get_dirname(dirname);

    dirp = opendir((char *) dirn);
    if (dirp == NULL) {
        ngx_log_error(NGX_LOG_WARN, m->log, 0,
                "proxy_folder_purge: can't open a directory = \"%s\"",
                dirn);
        return NGX_ERROR;
    }

    dfd = dirfd(dirp);

    while ((e = readdir(dirp)) != NULL) {

        if ((e->d_name[0] == '.' && e->d_name[1] == 0)
               || (e->d_name[1] == '.' && e->d_name[2] == 0))
        {
            continue;
        }

        if (memcmp(e->d_name, MASKS_PURGER, sizeof(MASKS_PURGER) - 1) != 0) {
            continue;
        }

        if (fstatat(dfd, e->d_name, &st_buf, 0) == 0
                && S_ISREG(st_buf.st_mode))
        {
            ngx_log_error(NGX_LOG_INFO, m->log, 0,
                    "proxy_folder_purge: remove purger file \"%s/%s\"",
                    dirn, e->d_name);

            if (unlinkat(dfd, e->d_name, 0) == -1) {
                ngx_log_error(NGX_LOG_ERR, m->log, ngx_errno,
                        "proxy_folder_purge: can't remove a file = \"%s/%s\"",
                        dirn, e->d_name);
            }
        }
    }

    closedir(dirp);

    return NGX_OK;
}


static ngx_int_t
ngx_masks_storage_get_pid(u_char *path)
{
    ngx_int_t i, digit;
    ngx_int_t len;
    ngx_int_t pid;
    u_char    c;

    pid = 0;
    digit = 1;
    len = ngx_strlen(path);

    for (i = len - 1; i >= 0; i--) {
        c = path[i];
        if (!isdigit(c)) {
            break;
        }

        c = c - '0';
        pid += (c * digit);
        digit *= 10;
    }

    return pid;
}


ngx_int_t
ngx_masks_storage_prepare_purger_queue(void *ms, ngx_pool_t *pool,
        ngx_log_t *log, ngx_str_t *dirname)
{
    ngx_masks_storage_t *m = (ngx_masks_storage_t *) ms;

    DIR             *dirp;
    ngx_int_t        rc;
    u_char           full_path[PATH_MAX + 1];
    u_char           rename_path[PATH_MAX + 1];
    const u_char    *dirn;
    ngx_int_t        pid;
    ngx_int_t        cnt;
    char           **names, *name;

    if (ms == NULL || pool == NULL || log == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "proxy_folder_purge: invalid pointer ms = %p, poll = %p, log = %p",
            ms, pool, log);
        return NGX_ERROR;
    }

    cnt = 0;
    m->log = log;
    m->pool = pool;

    dirn = get_dirname(dirname);

    ngx_snprintf(m->purger_filename, sizeof(m->purger_filename),
            "%s/%s%Z", dirn, MASKS_PURGER);

    m->per_domain_purge_masks = NULL;

    /**
     * Trying to get a next purger file
     */
    dirp = opendir((char *) dirn);
    if (dirp == NULL) {
        ngx_log_error(NGX_LOG_WARN, m->log, 0,
                "proxy_folder_purge: can't open a directory = \"%s\"",
                dirn);
        goto error;
    }

    names = ngx_masks_load_sorted_filenames(dirp, m->pool);
    if (names == NULL) {
        ngx_log_error(NGX_LOG_WARN, m->log, 0,
            "proxy_folder_purge: OOM while loading list of files from = \"%s\"",
            dirn);
        goto error_and_closedir;
    }

    /* Try to load "already processing" masks list */
    rc = ngx_masks_storage_old_purger_file(m, dirname, dirp, names);
    if (rc > 0) {

        return NGX_OK;

    } else if (rc < 0) {

        ngx_log_error(NGX_LOG_WARN, m->log, 0,
                      "proxy_folder_purge: can't handle old purger file "
                      "in directory = \"%s\"",
                      dirn);
        goto error;
    }

    ngx_sha1_init(&m->masks_sha1_state);
    ngx_sha1_update(&m->masks_sha1_state,
                    NGX_MASKS_CKPOINT_MAGIC, sizeof(NGX_MASKS_CKPOINT_MAGIC));

    while ((name = get_regular_file_with_prefix(dirp, &names, MASKS_IN,
            sizeof(MASKS_IN) - 1, NULL)) != NULL)
    {
        ngx_snprintf(full_path, sizeof(full_path), "%s/%s%Z",
                dirn, name);

        pid = ngx_masks_storage_get_pid(full_path);

        ngx_log_error(NGX_LOG_INFO, m->log, 0,
                "proxy_folder_purge: found a masks file = \"%s\" pid = %d",
                full_path, pid);

        ngx_snprintf(rename_path, sizeof(rename_path),
            "%s.%d%Z", m->purger_filename, pid);

        rc = (ngx_int_t) rename((char *) full_path, (char *) rename_path);
        if (rc == -1) {
            ngx_log_error(NGX_LOG_ERR, m->log, ngx_errno,
                "proxy_folder_purge: can't rename \"%s\" to \"%s\"",
                full_path, rename_path);
            goto error_and_closedir;
        }

        rc = ngx_masks_storage_read_purger_queue(m, rename_path);
        if (rc != NGX_OK) {
            goto error_and_closedir;
        }

        cnt++;
    }

    ngx_sha1_final(m->masks_sha1, &m->masks_sha1_state);
    closedir(dirp);

    rc = NGX_DECLINED;

    if (cnt > 0) {
        rc = NGX_OK;
    }
    else if (cnt == 0) {
        ngx_masks_storage_purger_queue_free(m);
    }

    return rc;

error_and_closedir:
    if (dirp != NULL) {
        closedir(dirp);
    }

error:
    ngx_masks_storage_purger_queue_free(m);
    return NGX_ERROR;
}


ngx_msec_t
ngx_masks_storage_purger_sleep(void *ms)
{
    ngx_masks_storage_t *m = (ngx_masks_storage_t *) ms;

    if (m == NULL || m->background_purger_sleep == 0) {
        return MASKS_STORAGE_PURGER_SLEEP_DEFAULT;
    }

    return m->background_purger_sleep;
}
/** ]]] */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
