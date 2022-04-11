
/**
 * (C)
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/dir.h>
#include <sys/file.h>
#include <dirent.h>

#include <ngx_masks_storage.h>
#include <ngx_masks_storage_core_api.h>


#if (NGX_HTTP_CACHE)

/** A structure for holding writer context (for X-Purge-Options: dump) */
typedef struct {
    /** A reference to an http request */
    ngx_http_request_t  *r_;

    /** Temp file for the message */
    ngx_temp_file_t     *temp_file;
} ngx_http_cache_purge_folder_writer_ctx_t;


typedef struct {
    ngx_uint_t                   max_allowed_masks_per_domain_;
    ngx_masks_storage_t     *masks_storage_;
    ngx_flag_t                   foreground_purge_enable_;
} ngx_masks_storage_loc_conf_t;


typedef ngx_int_t (*ngx_on_add_mask) (ngx_masks_storage_t * /*ms*/,
    ngx_str_t * /*domain*/, ngx_str_t * /*mask*/, ngx_int_t /*flags*/,
    time_t /*purge_start_time*/, ngx_int_t /*is_restoring*/);
static inline void ngx_masks_storage_purger_queue_free(
        ngx_masks_storage_t *ms, ngx_int_t clean_shared_memory);

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
        ngx_int_t flags, time_t purge_start_time, ngx_int_t is_restoring);
static ngx_int_t ngx_masks_storage_read_purger_queue(
        ngx_masks_storage_t *ms, u_char *filename);
static ngx_int_t ngx_remove_file(ngx_tree_ctx_t *ctx, ngx_str_t *filename);
static ngx_int_t ngx_walk_tree_stub(ngx_tree_ctx_t *ctx,
        ngx_str_t *filename);
static ngx_int_t ngx_masks_storage_old_purger_file(
    ngx_masks_storage_t *m, ngx_str_t *dirname);
static ngx_int_t ngx_masks_storage_remove_purger_file(
        ngx_masks_storage_t *m, ngx_str_t *dirname);
static ngx_int_t ngx_masks_storage_get_pid(u_char *path);

static ngx_command_t  ngx_masks_storage_commands[] = {

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
      offsetof(ngx_masks_storage_loc_conf_t, foreground_purge_enable_),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_masks_storage_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_masks_storage_create_loc_conf,  /* create location configuration */
    ngx_masks_storage_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_masks_storage_module = {
    NGX_MODULE_V1,
    &ngx_masks_storage_module_ctx,      /* module context */
    ngx_masks_storage_commands,         /* module directives */
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


/** nginx conf functions {{{ */
static char *
ngx_masks_storage_conf(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf)
{
    ngx_masks_storage_loc_conf_t  *loc_conf;
    ngx_str_t                         *value, tmp;
    ngx_masks_storage_t           *ms;
    ngx_int_t                          max_allowed_masks_per_domain,
                                       background_purger_off;
    u_char                            *p;
    ngx_uint_t                         i, background_purger_files;
    ngx_msec_t                         background_purger_sleep;
    ngx_msec_t                         background_purger_threshold;

    loc_conf = ngx_http_conf_get_module_loc_conf(cf,
            ngx_masks_storage_module);

    value = cf->args->elts;

    background_purger_files = MASKS_STORAGE_PURGER_FILES_DEFAULT;
    background_purger_sleep = MASKS_STORAGE_PURGER_SLEEP_DEFAULT;
    background_purger_threshold = MASKS_STORAGE_PURGER_THRESHOLD_DEFAULT;

    background_purger_off = 0;

    /** Optional options {{{ */
    for (i = 4; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "purger_files=",
                     sizeof("purger_files=") - 1) == 0)
        {
            tmp.data = value[i].data + sizeof("purger_files=") - 1;
            tmp.len = value[i].len - (sizeof("purger_files=") - 1);

            background_purger_files = (ngx_uint_t) ngx_atoi(tmp.data, tmp.len);
            if (background_purger_files == (ngx_uint_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid purger_files value \"%V\"",
                        &value[i]);
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "purger_sleep=",
                    sizeof("purger_sleep=") - 1) == 0)
        {
            tmp.data = value[i].data + (sizeof("purger_sleep=") - 1);
            tmp.len = value[i].len - (sizeof("purger_sleep=") - 1);

            background_purger_sleep = ngx_parse_time(&tmp, 0);

            if (background_purger_sleep == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid purger_sleep value \"%V\"",
                        &value[i]);
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "purger_threshold=",
                    sizeof("purger_threshold=") - 1) == 0)
        {
            tmp.data = value[i].data + (sizeof("purger_threshold=") - 1);
            tmp.len = value[i].len - (sizeof("purger_threshold=") - 1);

            background_purger_threshold = ngx_parse_time(&tmp, 0);
            if (background_purger_threshold == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid purger_sleep value \"%V\"",
                        &value[i]);
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "purger_off",
                    sizeof("purger_off") - 1) == 0)
        {
            background_purger_off = 1;
        }
        else {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                    "found an unknown option = \"%V\"", &value[i]);
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
    loc_conf->max_allowed_masks_per_domain_ = max_allowed_masks_per_domain;
    ms = ngx_masks_storage_init(cf, &value[1], max_allowed_masks_per_domain);

    if (!ms) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "can't allocate masks storage: size = \"%V\", "
                "masks per domain = %d",
                &value[1], max_allowed_masks_per_domain);
        return NGX_CONF_ERROR;
    }

    /** background purge */
    ms->path_->manager = NULL;
    ms->path_->loader = NULL;
    ms->path_->purger = NULL;

    ms->background_purger_files_ = background_purger_files;
    ms->background_purger_sleep_ = background_purger_sleep;
    ms->background_purger_threshold_ = background_purger_threshold;

    ms->background_purger_off_ = background_purger_off;

    tmp = value[3];

    if (tmp.data[tmp.len - 1] == '/') {
        tmp.data[tmp.len - 1] = 0;
        --tmp.len;
    }

    ms->path_->purger_ = 1;
    ms->path_->data = (void *) ms;
    ms->path_->conf_file = cf->conf_file->file.name.data;
    ms->path_->line = cf->conf_file->line;
    ms->path_->name.len = tmp.len + sizeof(MASKS_STORAGE_DIR) - 1;
    ms->path_->name.data = ngx_pcalloc(cf->pool, ms->path_->name.len);
    if (!ms->path_->name.data) {
        return NGX_CONF_ERROR;
    }

    p = ngx_snprintf(ms->path_->name.data, ms->path_->name.len, "%V%s%Z",
            &tmp, MASKS_STORAGE_DIR);
    ms->path_->name.len = (size_t) (p - ms->path_->name.data);

    if (ngx_conf_full_name(cf->cycle, &ms->path_->name, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /** See details: NCCS-621 */
    if (ngx_create_full_path(ms->path_->name.data, ngx_dir_access(0755))
            == NGX_FILE_ERROR)
    {
        if (ngx_errno != NGX_EEXIST) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                                "ngx_create_full_path() \"%V\" failed",
                                &ms->path_->name);
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_add_path(cf, &ms->path_) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ms->tmp_path_->manager = NULL;
    ms->tmp_path_->loader = NULL;
    ms->tmp_path_->purger = NULL;

    ms->tmp_path_->purger_ = 1;
    ms->tmp_path_->data = (void *) ms;
    ms->tmp_path_->conf_file = cf->conf_file->file.name.data;
    ms->tmp_path_->line = cf->conf_file->line;
    ms->tmp_path_->name.len = sizeof("logs") - 1;
    ms->tmp_path_->name.data = ngx_pcalloc(cf->pool, ms->tmp_path_->name.len);
    if (!ms->tmp_path_->name.data) {
        return NGX_CONF_ERROR;
    }

    ngx_snprintf(ms->tmp_path_->name.data, ms->tmp_path_->name.len, "logs");

    if (ngx_conf_full_name(cf->cycle, &ms->tmp_path_->name, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    loc_conf->masks_storage_ = ms;
    /** }}} */

    return NGX_CONF_OK;
}


static void *
ngx_masks_storage_create_loc_conf(ngx_conf_t *cf)
{
    ngx_masks_storage_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_masks_storage_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->masks_storage_ = NGX_CONF_UNSET_PTR;
    conf->foreground_purge_enable_ = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_masks_storage_merge_loc_conf(ngx_conf_t *cf, void *parent,
        void *child)
{
    ngx_masks_storage_loc_conf_t  *prev = parent;
    ngx_masks_storage_loc_conf_t  *conf = child;

    /**
     * XXX
     *
     * We don't need this code anymore, see an issue: NCCS-672
     *
     * But let's keep it, it could be useful in the future and
     * it doesn't affect anything.
     *
     * {{{
     */
    ngx_conf_merge_ptr_value(conf->masks_storage_, prev->masks_storage_,
            NULL);

    ngx_conf_merge_uint_value(conf->max_allowed_masks_per_domain_,
            prev->max_allowed_masks_per_domain_,
            (ngx_uint_t) MIN_ALLOWED_MASKS_NUM);
    /** }}} */

    ngx_conf_merge_value(conf->foreground_purge_enable_,
            prev->foreground_purge_enable_, 1);

    return NGX_CONF_OK;
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
     *  magic,crc32,domain,mask,flags,purge_start_time\n
     *  ...
     *
     *  where:
     *  1) magic - uniq 4-bar string
     *  2) crc32 - a crc32(domain + mask + flags + purge_start_time) string
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
    body.len = domain->len + 1 + mask->mask_.len + 1 +
                UINT32_STR_MAX + 1 + UINT64_STR_MAX + 1 +
                sizeof("\n") - 1;
    body.data = ngx_pcalloc(ms->r_->pool, body.len);

    if (!body.data) {
        goto error_exit;
    }

    p = ngx_snprintf(body.data, body.len,
            "%V,%V,%uz,%T\n", domain, &mask->mask_, mask->flags_,
            mask->purge_start_time_);
    body.len = (size_t) (p - body.data);

    /** Header */
    header.len = sizeof(MASKS_STORAGE_MAGIC) - 1 + UINT64_STR_MAX + 1;
    header.data = ngx_pcalloc(ms->r_->pool, header.len);

    if (!header.data) {
        goto error_exit;
    }

    p = ngx_snprintf(header.data, header.len, "%s%uz,",
            MASKS_STORAGE_MAGIC,
            ngx_crc32_long(body.data, body.len - 1 /* exclude '\n' */));

    header.len = (size_t) (p - header.data);

    /** Message */
    b->len = header.len + body.len;
    b->data = ngx_pnalloc(ms->r_->pool, b->len);

    if (!b->data) {
        goto error_exit;
    }

    ngx_snprintf(b->data, b->len, "%V%V", &header, &body);

    ngx_pfree(ms->r_->pool, body.data);
    ngx_pfree(ms->r_->pool, header.data);

    return NGX_OK;

error_exit:

    if (body.data) {
        ngx_pfree(ms->r_->pool, body.data);
    }

    if (header.data) {
        ngx_pfree(ms->r_->pool, header.data);
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_deserialize_mask(ngx_masks_storage_t *ms, u_char *it,
        u_char *end, ngx_on_add_mask on_add_mask)
{
    ngx_str_t                   line, err;
    ngx_int_t                   lineno;
    ngx_full_mask_t         tmp;
    ngx_string_list_arg_t   a;
    uint32_t                    crc32;
    ngx_int_t                   rc;

    lineno = 0;

    for (line.data = it; it < end; ++it) {

        /* End was reached */
        if (line.data == NULL) {
            break;
        }

        if (*it != '\n') {
            continue;
        }

        err.data = NULL;
        err.len = 0;

        line.len = (size_t) (it - line.data);

        /** parse header */
        if ((line.len < (sizeof(MASKS_STORAGE_MAGIC) - 1)) ||
                (ngx_strncmp(line.data, MASKS_STORAGE_MAGIC,
                        sizeof(MASKS_STORAGE_MAGIC) - 1) != 0))
        {
            ngx_str_set(&err, "can't find a MAGIC");
            goto invalid_line;
        }

        line.data += sizeof(MASKS_STORAGE_MAGIC) - 1;
        line.len -= sizeof(MASKS_STORAGE_MAGIC) - 1;

        /** parse body */

        /** crc32 */
        a = ngx_string_list_get_next_arg(line.data, line.data + line.len);

        if (a.arg_ == a.end_) {
            ngx_str_set(&err, "can't find a CRC32 and next fields");
            goto invalid_line;
        }

        rc = ngx_atoi(a.arg_, (size_t) (a.end_ - a.arg_));
        if (rc == NGX_ERROR) {
            ngx_str_set(&err, "ngx_atoi failed");
            goto invalid_line;
        }
        tmp.crc32_ = (uint32_t) rc;

        line.data = a.end_ + 1;
        line.len = (size_t) (it - line.data);

        crc32 = ngx_crc32_long(line.data, line.len);

        if (crc32 != tmp.crc32_) {
            ngx_str_set(&err, "CRC32 check failed");
            goto invalid_line;
        }

        /** domain */
        a = ngx_string_list_get_next_arg(line.data, line.data + line.len);

        if (a.arg_ == a.end_) {
            ngx_str_set(&err, "can't find a domain and next fields");
            goto invalid_line;
        }

        tmp.domain_.data = a.arg_;
        tmp.domain_.len = (size_t) (a.end_ - a.arg_);

        line.data = a.end_ + 1;
        line.len = (size_t) (it - line.data);

        /** mask */
        a = ngx_string_list_get_next_arg(line.data, line.data + line.len);

        if (a.arg_ == a.end_) {
            ngx_str_set(&err, "can't find a mask and next fields");
            goto invalid_line;
        }

        tmp.mask_.mask_.data = a.arg_;
        tmp.mask_.mask_.len = (size_t) (a.end_ - a.arg_);

        line.data = a.end_ + 1;
        line.len = (size_t) (it - line.data);

       /** flags */
        a = ngx_string_list_get_next_arg(line.data, line.data + line.len);

        if (a.arg_ == a.end_) {
            ngx_str_set(&err, "can't find a flags and next fields");
            goto invalid_line;
        }

        tmp.mask_.flags_ = ngx_atoi(a.arg_, (size_t) (a.end_ - a.arg_));
        if (tmp.mask_.flags_ == NGX_ERROR) {
            ngx_str_set(&err, "ngx_atoi failed");
            goto invalid_line;
        }

        line.data = a.end_ + 1;
        line.len = (size_t) (it - line.data);

        /** purge start time */
        a = ngx_string_list_get_next_arg(line.data, line.data + line.len);

        if (a.arg_ == a.end_) {
            ngx_str_set(&err, "can't find a purge start time");
            goto invalid_line;
        }

        tmp.mask_.purge_start_time_ = ngx_atotm(a.arg_,
                (size_t) (a.end_ - a.arg_));
        if (tmp.mask_.purge_start_time_ == NGX_ERROR) {
            ngx_str_set(&err, "ngx_atotm failed");
            goto invalid_line;
        }

        rc = on_add_mask(ms, &tmp.domain_, &tmp.mask_.mask_,
                tmp.mask_.flags_, tmp.mask_.purge_start_time_, 1);

        if (rc != NGX_MASKS_STORAGE_OK) {
            ngx_log_error(NGX_LOG_ERR, ms->log_, 0,
                    "masks storage: on_add_mask failed rc = %d", rc);
            return NGX_ERROR;
        }

invalid_line:

        if (err.data) {
            ngx_log_error(NGX_LOG_ERR, ms->log_, 0,
                "masks storage: "
                "can't parse a line, err = \"%V\", line [%d] = \"%V\"",
                &err, lineno, &line);
            err.data = NULL;
            err.len = 0;
        }

        /** next line if it exists */
        if (it == end) {
            line.data = NULL;
        } else {
            line.data = it + 1 /* Skip '\n' */;
            ++lineno;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_masks_write_to_masks_in(ngx_masks_storage_t *ms,
        ngx_str_t *domain, ngx_mask_t *mask)
{
    ngx_str_t    b;
    ngx_int_t    tried;
    ngx_str_t    masks_in;

    tried = 0;
    b.data = NULL;
    b.len = 0;

    /** We didn't set a file name at start, since we can't get pid
     * inside a master process.
     */

    /** Will be: {PATH} / {MASKS_IN}.{PID} \0 */
    masks_in.len = ms->path_->name.len + sizeof(MASKS_IN) - 1 +
        sizeof(UINT32_STR_MAX) - 1 + 1;
    masks_in.data = ngx_pnalloc(ms->r_->pool, masks_in.len);
    if (!masks_in.data) {
        return NGX_ERROR;
    }

    ngx_snprintf(masks_in.data, masks_in.len, "%V%s%d%Z",
            &ms->path_->name, MASKS_IN, (ngx_int_t) ngx_getpid());

    /** We have to check "access()" each call. UNIX-kernel has something
     * like reference count, that means, we may have a valid and good
     * filedesc even if the file was deleted.
     */
    if ((ms->masks_in_fd_ >= 0) &&
            (access((char *) masks_in.data, F_OK) == -1))
    {
        close(ms->masks_in_fd_);
        ms->masks_in_fd_ = NGX_INVALID_FILE;
    }

try_reopen:

    if (ms->masks_in_fd_ == NGX_INVALID_FILE) {

        ms->masks_in_fd_ = open_append_only_file(&masks_in);

        if (ms->masks_in_fd_ == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_ERR, ms->log_, ngx_errno,
                    "can't open \"%V\"", &masks_in);
            return NGX_ERROR;
        }
    }

    if (ngx_serialize_mask(ms, &b, domain, mask) != NGX_OK) {

        /** Well we don't need close FD here. This isn't a system a bug
         * if it happens. */
        ngx_log_error(NGX_LOG_ERR, ms->log_, 0,
                "can't s11n the mask to domain = \"%V\", mask = \"%V\"",
                domain, mask);
        return NGX_ERROR;
    }

#if defined (MASKS_STORAGE_WITH_FLOCK)
    if (flock(ms->masks_in_fd_, LOCK_EX) == -1) {
        close(ms->masks_in_fd_);
        ms->masks_in_fd_ = NGX_INVALID_FILE;
        return NGX_ERROR;
    }
#endif /* MASKS_STORAGE_WITH_FLOCK */

    if (!b.data || !b.len ||
            write(ms->masks_in_fd_, b.data, b.len) != (ssize_t) b.len)
    {
        ngx_log_error(NGX_LOG_ERR, ms->log_, ngx_errno,
                "can't write to \"%V\"", &masks_in);

#if defined (MASKS_STORAGE_WITH_FLOCK)
        flock(ms->masks_in_fd_, LOCK_UN);
#endif /* MASKS_STORAGE_WITH_FLOCK */

        close(ms->masks_in_fd_);
        ms->masks_in_fd_ = NGX_INVALID_FILE;

        if (!tried) {

            tried = 1;
            goto try_reopen;
        }

        return NGX_ERROR;
    }

    /** Make sure, that the data flushed */
    if (do_sync(ms->masks_in_fd_) == NGX_INVALID_FILE) {

        ngx_log_error(NGX_LOG_ERR, ms->log_, ngx_errno,
                "can't flush to \"%V\"", masks_in);

#if defined (MASKS_STORAGE_WITH_FLOCK)
        flock(ms->masks_in_fd_, LOCK_UN);
#endif /* MASKS_STORAGE_WITH_FLOCK */

        do_close(ms->masks_in_fd_);
        ms->masks_in_fd_ = NGX_INVALID_FILE;

        return NGX_ERROR;
    }

#if defined (MASKS_STORAGE_WITH_FLOCK)
    flock(ms->masks_in_fd_, LOCK_UN);
#endif /* MASKS_STORAGE_WITH_FLOCK */

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

        ctx->sh_ = octx->sh_;
        ctx->sh_->restoring_ = octx->sh_->restoring_;
        ctx->shpool_ = octx->shpool_;
        ctx->log_ = octx->log_;
        ctx->r_ = NULL;

        ngx_log_error(NGX_LOG_INFO, ctx->log_, 0,
                "shared memory restored from an old context, sh = %p, "
                "data = %p, restoring = %d", ctx->sh_, ctx,
                ctx->sh_->restoring_);

        return NGX_OK;
    }

    /** It isn't exist, so create it
     */
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    ctx->shpool_ = shpool;

    ctx->sh_ = ngx_slab_alloc(shpool, sizeof(ngx_masks_storage_shctx_t));

    if (!ctx->sh_) {

        ngx_log_error(NGX_LOG_ERR, ctx->log_, 0,
                "can't allocated masks storage context, size = %d",
                sizeof(ngx_masks_storage_shctx_t));
        return NGX_ERROR;
    }

    ctx->shpool_->data = ctx->sh_;

    ctx->sh_->rbtree_ = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));

    if (!ctx->sh_->rbtree_) {

        ngx_log_error(NGX_LOG_ERR, ctx->log_, 0,
                "can't allocated masks storage rbtree context, size = %d",
                sizeof(ngx_rbtree_t));

        return NGX_ERROR;
    }

    ctx->sh_->sentinel_ = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));

    if (!ctx->sh_->sentinel_) {

        ngx_log_error(NGX_LOG_ERR, ctx->log_, 0,
                "can't allocated masks storage rbtree sentinel, size = %d",
                sizeof(ngx_rbtree_node_t));

        return NGX_ERROR;
    }

    ngx_rbtree_init(ctx->sh_->rbtree_, ctx->sh_->sentinel_,
        ngx_str_rbtree_insert_value);

    ctx->shpool_->log_ctx = ngx_slab_alloc(shpool,
            sizeof(LOG_HINT) /* + \0*/);

    if (!ctx->shpool_->log_ctx) {

        ngx_log_error(NGX_LOG_ERR, ctx->log_, 0,
                "can't allocated masks storage log ctx, size = %d",
                sizeof(LOG_HINT));

        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool_->log_ctx, "%s\0", LOG_HINT);

    /** If a new segment hasn't memory for allocating,
     * then nginx writes some logs. */
    ctx->shpool_->log_nomem = 1;

    ctx->sh_->restoring_ = 1;

    ngx_log_error(NGX_LOG_INFO, ctx->log_, 0,
            "shared memory created, sh = %p, "
            "data = %p, restoring = %d", ctx->sh_, ctx, ctx->sh_->restoring_);

    return NGX_OK;
}


static ngx_masks_storage_t *
ngx_masks_storage_init(ngx_conf_t *cf, ngx_str_t *shared_memory_size,
        size_t max_allowed_masks_per_domain)
{
    ngx_masks_storage_t     *ctx;
    ngx_shm_zone_t              *shm_zone;
    ngx_uint_t                  n;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_masks_storage_t));

    if (!ctx) {
        return NULL;
    }

    ctx->path_ = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (!ctx->path_) {
        return NULL;
    }

    ctx->tmp_path_ = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (!ctx->tmp_path_) {
        return NULL;
    }

    ngx_str_set(&ctx->masks_purger_, MASKS_PURGER);
    ngx_str_set(&ctx->shm_name_, ZONE_NAME);
    ctx->max_allowed_masks_per_domain_ = max_allowed_masks_per_domain;
    ctx->r_ = NULL;
    ctx->log_ = cf->log;
    ctx->masks_in_fd_ = NGX_INVALID_FILE;
    ctx->masks_purger_fd_ = NGX_INVALID_FILE;

    n = ngx_parse_size(shared_memory_size);

    if (n < (ngx_uint_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "masks storage \"%V\" is too small", shared_memory_size);
        return NULL;
    }

    shm_zone = ngx_shared_memory_add(cf, &ctx->shm_name_, n,
            &ngx_masks_storage_module);

    if (!shm_zone) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "ngx_shared_memory_add failed at ngx_masks_storage_init");
        return NULL;
    }

    if (shm_zone->data) {
#if defined (NGX_DEBUG)
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "\"%V\" is already bound at ngx_masks_storage_init",
                &ctx->shm_name_);
#endif /* (NGX_DEBUG) */
        return NULL;
    }

    shm_zone->data = (void *) ctx;
    shm_zone->init = ngx_init_storage;

    ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
            "shm_zone allocated, shm = %p, data = %p",
            shm_zone, shm_zone->data);

    return ctx;
}



static ngx_rbtree_node_t *
ngx_masks_lookup_domain_unlocked(ngx_masks_storage_t *ms,
    ngx_str_t *domain)
{
    uint32_t              hash;

    if (!ms || !ms->sh_ || !ms->sh_->rbtree_) {
        return NULL;
    }

    hash = ngx_crc32_long(domain->data, domain->len);

    return (ngx_rbtree_node_t *)
        ngx_str_rbtree_lookup(ms->sh_->rbtree_, domain, hash);
}


static ngx_rbtree_node_t *
ngx_masks_insert_domain_unlocked(ngx_masks_storage_t *ms,
        const ngx_str_t *domain)
{
    ngx_domain_rbtree_node_t         *node;
    ngx_masks_storage_shctx_t *sh;
    ngx_slab_pool_t               *shpool;

    sh = ms->sh_;
    shpool = ms->shpool_;

    node = ngx_slab_alloc_locked(shpool, sizeof(ngx_domain_rbtree_node_t));

    if (!node) {
        goto error_exit;
    }

    ngx_memzero(node, sizeof(ngx_domain_rbtree_node_t));

    node->sn_.str.len = domain->len;

    node->sn_.str.data = ngx_slab_alloc_locked(shpool, node->sn_.str.len);
    if (!node->sn_.str.data) {
        goto error_exit;
    }

    ngx_snprintf(node->sn_.str.data, node->sn_.str.len, "%V", domain);

    node->sn_.node.key = ngx_crc32_long(domain->data, domain->len);

    node->value_.max_ = ms->max_allowed_masks_per_domain_;

    node->value_.masks_ = ngx_slab_alloc_locked(shpool,
                            sizeof(ngx_rbtree_t));

    if (!node->value_.masks_) {
        goto error_exit;
    }

    node->value_.sentinel_ = ngx_slab_alloc_locked(shpool,
                                sizeof(ngx_rbtree_node_t));
    if (!node->value_.sentinel_) {
        goto error_exit;
    }

    ngx_rbtree_init(node->value_.masks_, node->value_.sentinel_,
        ngx_str_rbtree_insert_value);

    ngx_rbtree_insert(sh->rbtree_, &node->sn_.node);

    return (ngx_rbtree_node_t *) &node->sn_.node;

error_exit:

    if (node) {

        if (node->value_.masks_) {
            ngx_slab_free_locked(shpool, node->value_.masks_);
        }

        if (node->value_.sentinel_) {
            ngx_slab_free_locked(shpool, node->value_.sentinel_);
        }

        if (node->sn_.str.data) {
            ngx_slab_free_locked(shpool, node->sn_.str.data);
        }

        ngx_slab_free_locked(shpool, node);
    }

    return NULL;
}


static ngx_int_t
ngx_masks_compare(ngx_masks_storage_t *ms, ngx_str_t *mask_a,
        ngx_int_t flags_a, ngx_str_t *mask_b, ngx_int_t flags_b)
{
    (void) ms;

    if ((flags_a & NGX_MASK_FLAG_PURGE_FOLDER) &&
            (flags_b & NGX_MASK_FLAG_PURGE_FOLDER))
    {
        if ((mask_b->len >= mask_a->len) &&
                (ngx_strncmp(mask_b->data, mask_a->data, mask_a->len) == 0))
        {
            return NGX_OK;
        }

    /** TODO: Think about case: /a/b/ *.txt && /a/b/ * {{{ */
    } else {

        if ((mask_b->len == mask_a->len) &&
                (ngx_strncmp(mask_b->data, mask_a->data, mask_b->len) == 0))
        {
            return NGX_OK;
        }
    }

    /** }}} */

    return NGX_DECLINED;
}


static ngx_masks_rbtree_node_t *
ngx_masks_get_mask_queue_unlocked(ngx_masks_storage_t *ms,
    ngx_domain_rbtree_node_t *qnode, ngx_str_t *mask, ngx_int_t need_parse)
{
    uint32_t                     hash;
    ngx_masks_rbtree_node_t *node;
    ngx_str_t                    mask_path, mask_rest;

    if (need_parse) {
        parse_path(mask, &mask_path, &mask_rest);
    }
    else {
        mask_path.len = mask->len;
        mask_path.data = mask->data;
    }
    hash = ngx_crc32_long(mask_path.data, mask_path.len);

    node = (ngx_masks_rbtree_node_t *)
            ngx_str_rbtree_lookup(qnode->value_.masks_, &mask_path, hash);

    return node;
}


static ngx_mask_t *
ngx_masks_lookup_mask_unlocked(ngx_masks_storage_t *ms,
    ngx_domain_rbtree_node_t *qnode, ngx_str_t *mask, ngx_int_t flags)
{
    ngx_masks_rbtree_node_t *node;
    ngx_mask_queue_t        *mask_queue;
    ngx_queue_t                 *q;
    ngx_int_t                    rc;

    node = ngx_masks_get_mask_queue_unlocked(ms, qnode, mask, 1);
    if (!node) {
        return NULL;
    }

    for (q = ngx_queue_head(&node->mask_queue_.queue_);
            q != ngx_queue_sentinel(&node->mask_queue_.queue_);
            q = ngx_queue_next(q))
    {
        mask_queue = ngx_queue_data(q, ngx_mask_queue_t, queue_);
        rc = ngx_masks_compare(ms, &mask_queue->mask_.mask_,
                mask_queue->mask_.flags_, mask, flags);
        if (rc == NGX_OK) {
            return &mask_queue->mask_;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_masks_insert_mask_unlocked(ngx_masks_storage_t *ms,
        ngx_rbtree_node_t *n, ngx_str_t *domain, ngx_str_t *mask,
        ngx_int_t flags, time_t purge_start_time, ngx_int_t is_restoring)
{
    ngx_domain_rbtree_node_t       *qnode = (ngx_domain_rbtree_node_t *) n;

    ngx_masks_rbtree_node_t *node;
    ngx_slab_pool_t             *shpool;
    ngx_mask_queue_t        *mask_queue;
    uint32_t                     hash;
    ngx_str_t                    mask_path, mask_rest;

    shpool = ms->shpool_;

    /** Lookup the first avaliable node for putting masks into it.
     *
     * And also checks limit for this domain.
     *
     * XXX
     * A full-scan should be replaced to tree (radix?) search
     * in the future.
     */
    if (qnode->value_.len_ >= qnode->value_.max_) {
        return NGX_MASKS_STORAGE_LIMIT_REACHED;
    }

    parse_path(mask, &mask_path, &mask_rest);

    hash = ngx_crc32_long(mask_path.data, mask_path.len);

    node = (ngx_masks_rbtree_node_t *)
            ngx_str_rbtree_lookup(qnode->value_.masks_, &mask_path, hash);
    if (!node) {
        node = ngx_slab_alloc_locked(shpool,
                sizeof(ngx_masks_rbtree_node_t));
        if (!node) {
            ngx_log_error(NGX_LOG_ERR, ms->log_, ngx_errno,
                "can't add mask, slab allocation failed, mask size = %d",
                mask->len);
            return NGX_MASKS_STORAGE_FAIL;
        }
        ngx_memzero(node, sizeof(ngx_masks_rbtree_node_t));
        node->sn_.str.len = mask_path.len;
        node->sn_.str.data = ngx_slab_alloc_locked(shpool, node->sn_.str.len);
        if (!node->sn_.str.data) {
            ngx_slab_free_locked(shpool, node);
            return NGX_MASKS_STORAGE_FAIL;
        }
        ngx_snprintf(node->sn_.str.data, node->sn_.str.len, "%V", &mask_path);
        node->sn_.node.key = hash;
        ngx_queue_init(&node->mask_queue_.queue_);
        ngx_rbtree_insert(qnode->value_.masks_, &node->sn_.node);
    }

    mask_queue = ngx_slab_alloc_locked(shpool, sizeof(ngx_mask_queue_t));
    if (!mask_queue) {
        ngx_rbtree_delete(qnode->value_.masks_, &node->sn_.node);
        ngx_slab_free_locked(shpool, node->sn_.str.data);
        ngx_slab_free_locked(shpool, node);
        return NGX_MASKS_STORAGE_FAIL;
    }
    ngx_memzero(mask_queue, sizeof(ngx_mask_queue_t));
    mask_queue->mask_.mask_.len = mask->len;
    mask_queue->mask_.mask_.data = ngx_slab_alloc_locked(shpool,
                                        mask_queue->mask_.mask_.len);
    if (!mask_queue->mask_.mask_.data) {
        ngx_slab_free_locked(shpool, mask_queue);
        ngx_rbtree_delete(qnode->value_.masks_, &node->sn_.node);
        ngx_slab_free_locked(shpool, node->sn_.str.data);
        ngx_slab_free_locked(shpool, node);
        return NGX_MASKS_STORAGE_FAIL;
    }
    ngx_snprintf(mask_queue->mask_.mask_.data,
                    mask_queue->mask_.mask_.len, "%V", mask);
    mask_queue->mask_.flags_ = flags;
    mask_queue->mask_.purge_start_time_ = purge_start_time;
    mask_queue->mask_.ref_count_ = 0;
    ngx_queue_insert_tail(&node->mask_queue_.queue_, &mask_queue->queue_);

    ngx_log_debug7(NGX_LOG_DEBUG_HTTP, ms->log_, 0,
            "masks storage: %p mask added, domain = \"%V\" (%d), "
            "mask = \"%V\" (%d), flags = %d, purge_start_time = %d",
            ms->sh_->rbtree_, domain, domain->len,
            mask, mask->len, mask_queue->mask_.flags_,
            mask_queue->mask_.purge_start_time_);

    ++qnode->value_.len_;

    /** If it is restoring, then set flag commited and exit.
     *  The restiring means, we read masks.in or masks.purter files.
     */
    if (is_restoring) {
        mask_queue->mask_.flags_ |= NGX_MASK_FLAG_COMMITED;
        return NGX_MASKS_STORAGE_OK;
    }

    /** XXX ngx_masks_write_to_masks_in() needs ms->r_ */
    if (ngx_masks_write_to_masks_in(ms, domain,
                &mask_queue->mask_) != NGX_OK)
    {

        /**
         * XXX
         * The bad case is: nginx received sigfault and/or fault signal.
         * What will happen? The background purge will clean up shared memory
         * and files, but it could take some time.
         */
        ngx_log_error(NGX_LOG_ERR, ms->log_, ngx_errno,
            "masks storage: can't persist the mask = \"%V\", flags = %d, "
            "purge_start_time = %d", mask, mask_queue->mask_.flags_,
            mask_queue->mask_.purge_start_time_);

        ngx_queue_remove(&mask_queue->queue_);
        ngx_slab_free_locked(shpool, mask_queue);
        if (ngx_queue_empty(&node->mask_queue_.queue_)) {
            ngx_rbtree_delete(qnode->value_.masks_, &node->sn_.node);
            ngx_slab_free_locked(shpool, node->sn_.str.data);
            ngx_slab_free_locked(shpool, node);
        }

        --qnode->value_.len_;

        if (qnode->value_.len_ == 0) {
            ngx_slab_free_locked(shpool, qnode->value_.masks_);
            ngx_rbtree_delete(ms->sh_->rbtree_, n);
            ngx_slab_free_locked(shpool, qnode->sn_.str.data);
            ngx_slab_free_locked(shpool, qnode);
        }

        return NGX_MASKS_STORAGE_FAIL;
    }

    mask_queue->mask_.flags_ |= NGX_MASK_FLAG_COMMITED;

    return NGX_MASKS_STORAGE_OK;
}


static ngx_int_t
ngx_masks_storage_parse_request(ngx_masks_storage_t *ms,
        ngx_str_t *domain, ngx_str_t *mask, ngx_int_t *flags,
        time_t *purge_start_time, ngx_str_t *err)
{
    size_t               i;
    ngx_str_t            uri;
    u_char              *it, *end;
    ngx_int_t            found_asterik, found_dot, found_ext,
                         set_default_op_type;
    ngx_table_elt_t     *h;
    ngx_list_part_t     *part;
    ngx_http_request_t  *r;
    time_t               current_time;

    r = ms->r_;
    uri = ms->r_->uri;

    *domain = r->headers_in.server;
    *mask = uri;
    *flags = 0;
    *purge_start_time = 0;
    ngx_str_set(err, "");
    set_default_op_type = 1;

    if (uri.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "masks_storage: can't parse request, uri/mask is not set");
        return NGX_MASKS_STORAGE_DENY;
    }

    ngx_time_update();

    current_time = ngx_time();

    end = uri.data + uri.len;
    it = end;

    for (; it != uri.data; --it) {

        if (*it == '/') {
            break;
        }
    }

    if (((size_t) (end - it) == 2) && (*it == '/') && (*(it + 1) == '*')) {

        *flags |= NGX_MASK_FLAG_PURGE_FILES;

    } else if (((size_t) (end - it) == 1) && (*it == '/')) {

        *flags |= NGX_MASK_FLAG_PURGE_FOLDER;

    /** Something complex is comming */
    } else {

        found_asterik = 0;
        found_dot = 0;
        found_ext = 0;

        for (; it != end; ++it) {

            if (!found_asterik && (*it == '*')) {

                found_asterik = 1;

            } else if (!found_dot && (*it == '.')) {

                found_dot = 1;

            } else if (found_asterik && found_dot) {

                *flags |= NGX_MASK_FLAG_PURGE_FILES_WITH_EXT;
                found_ext = 1;
                break;

            }
        }

        if (!(found_asterik && found_dot && found_ext)) {

            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "masks_storage: no EXT, dots, or *");

            return NGX_MASKS_STORAGE_BAD_REQUEST;
        }
    }

    /** Type of operation */

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
                "purge process header: \"%V\":\"%V\"",
                &h[i].key, &h[i].value);

        /** Documentation about options [1].
         *  Here is a short description:
         *
         *  1) invalidate - invalidate a folder;
         *  2) delete - delete a folder;
         *  3) {delete, invalidate}-recursive - delete or invalidate recursive;
         *  4) [Debug only] flush - delete shared memory only;
         *  5) [Debug only] dump - output shared memory content in JSON.
         *
         *
         * [1] https://docs.google.com/document/d/1JYMdHmIv09RZA5KzHfs4GTndc1E12_gAiARmIgmKhkQ/edit#heading=h.iow5sqwhpuqh
         */
        if ((h[i].key.len == (sizeof("x-purge-options") - 1)) &&
                (ngx_strncmp(h[i].lowcase_key,
                            (u_char *) "x-purge-options",
                            h[i].key.len) == 0))
        {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "x-purge-options found, its value = \"%V\"", &h[i].value);

            set_default_op_type = 0;

            if ((h[i].value.len == (sizeof("invalidate") - 1)) &&
                    (ngx_strncmp(h[i].value.data, "invalidate",
                        h[i].value.len) == 0))
            {

                *flags |= NGX_MASK_FLAG_INVALIDATE;

            } else if ((h[i].value.len == (sizeof("delete") - 1)) &&
                    (ngx_strncmp(h[i].value.data, "delete",
                        h[i].value.len) == 0))
            {

                *flags |= NGX_MASK_FLAG_DELETE;

            }
            else if ((h[i].value.len == (sizeof("delete-recursive") - 1)) &&
                    (ngx_strncmp(h[i].value.data, "delete-recursive",
                        h[i].value.len) == 0))
            {
                *flags |= (NGX_MASK_FLAG_DELETE |
                    NGX_MASK_FLAG_RECURSIVE);

            } else if ((h[i].value.len == (sizeof("invalidate-recursive")
                            - 1)) &&
                    (ngx_strncmp(h[i].value.data, "invalidate-recursive",
                        h[i].value.len) == 0))
            {
                *flags |= (NGX_MASK_FLAG_INVALIDATE |
                    NGX_MASK_FLAG_RECURSIVE);

            } else {
                goto wrong_options_error;
            }

            break;
        }
    }

    /**
     * A default type is delete.
     */
    if (set_default_op_type) {
        *flags |= NGX_MASK_FLAG_DELETE;
    }

    if (!(*flags & (NGX_MASK_FLAG_DELETE |
                NGX_MASK_FLAG_INVALIDATE)))
    {
wrong_options_error:
        ngx_str_set(err,
                "the X-Purge-Options should be the one of: "
                "delete[-recursive], invalidate[-recursive]"
        );

        return NGX_MASKS_STORAGE_BAD_REQUEST;
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
    ngx_rbtree_node_t           *node, *next, *root, *sentinel;
    ngx_masks_rbtree_node_t *sub_n;
    ngx_rbtree_node_t           *sub_node, *sub_next, *sub_root, *sub_sentinel;
    ngx_slab_pool_t             *shpool;
    ngx_queue_t                 *q;
    ngx_mask_queue_t        *mask_queue;

    shpool = ms->shpool_;

    ngx_shmtx_lock(&shpool->mutex);

    sentinel = ms->sh_->sentinel_;
    root = ms->sh_->rbtree_->root;

    if (root == sentinel) {
        goto exit;
    }

    node = ngx_rbtree_min(root, sentinel);
    while (node)
    {
        next = ngx_rbtree_next(ms->sh_->rbtree_, node);
        n = (ngx_domain_rbtree_node_t *) node;

        sub_sentinel = n->value_.sentinel_;
        sub_root = n->value_.masks_->root;

        if (sub_sentinel != sub_root) {
            sub_node = ngx_rbtree_min(sub_root, sub_sentinel);
            while (sub_node)
            {
                sub_next = ngx_rbtree_next(n->value_.masks_, sub_node);
                sub_n = (ngx_masks_rbtree_node_t *) sub_node;

                while (!ngx_queue_empty(&sub_n->mask_queue_.queue_)) {
                    q = ngx_queue_head(&sub_n->mask_queue_.queue_);
                    ngx_queue_remove(q);
                    mask_queue = ngx_queue_data(q, ngx_mask_queue_t, queue_);
                    ngx_slab_free_locked(shpool, mask_queue);
                }

                ngx_rbtree_delete(n->value_.masks_, sub_node);
                ngx_slab_free_locked(shpool, sub_n->sn_.str.data);
                ngx_slab_free_locked(shpool, sub_n);

                sub_node = sub_next;
            }
        }

        ngx_slab_free_locked(shpool, n->value_.masks_);

        ngx_rbtree_delete(ms->sh_->rbtree_, node);
        ngx_slab_free_locked(shpool, n->sn_.str.data);
        ngx_slab_free_locked(shpool, n);

        node = next;
    }

exit:
    ngx_shmtx_unlock(&shpool->mutex);
}


static ngx_int_t
ngx_masks_storage_add_mask(ngx_masks_storage_t *ms, ngx_str_t *domain,
        ngx_str_t *mask, ngx_int_t flags, time_t purge_start_time,
        ngx_int_t is_restoring)
{
    ngx_masks_storage_shctx_t     *sh;
    ngx_slab_pool_t               *shpool;
    ngx_int_t                      rc;
    ngx_rbtree_node_t             *node;
    ngx_domain_rbtree_node_t      *qnode;
    time_t                         prev_purge_start_time;
    ngx_int_t                      prev_flags;
    ngx_mask_t                    *m;

    if (!ms || !domain || !mask) {
        ngx_log_error(NGX_LOG_WARN, ms->log_, 0,
                "masks storage: ngx_masks_storage_add_mask: "
                "got invalid val(s), ms = %p, domain = %p, mask = %p",
                ms, domain, mask);
        return NGX_MASKS_STORAGE_FAIL;
    }

    qnode = NULL;
    sh = ms->sh_;
    shpool = ms->shpool_;
    rc = NGX_MASKS_STORAGE_OK;
    prev_purge_start_time = 0;
    prev_flags = 0;

    ngx_shmtx_lock(&shpool->mutex);

    if ((is_restoring == 0) && sh->restoring_) {
        rc = NGX_MASKS_STORAGE_SERVICE_DISABLE;
        ngx_log_error(NGX_LOG_INFO, ms->log_, 0,
                "masks storage: restoring, rc = %d, is_restoring = %d, "
                "shared_mem->restoring_ = %d",
                rc, is_restoring, sh->restoring_);
        goto out;
    }

    node = ngx_masks_lookup_domain_unlocked(ms, domain);

    /** Domain not found, insert a new node */
    if (node == NULL) {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ms->log_, 0,
                "masks storage: domain \"%V\" NOT found in the storage, adding it",
                domain);

        node = ngx_masks_insert_domain_unlocked(ms, domain);

        if (node == NULL) {
            rc = NGX_MASKS_STORAGE_FAIL;
            ngx_log_error(NGX_LOG_ERR, ms->log_, 0,
                "masks storage: can't add \"%V\", the insert failed, rc = %d",
                domain, rc);
            goto out;
        }

    }
    /** Domain found. Update tree, if mask exists or insert if does not.
     *
     * What is update? It does update a purge_start_time_ and also saves
     * this information to the disk.
     *
     * What is insert? It does add a new element and also saves this
     * information to the disk.
     */
    else {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ms->log_, 0,
                "masks storage: domain \"%V\" found", domain);

        /** XXX
         * A full-scan should be replaced to tree (radix?) search
         * in the future.
         */
        qnode = (ngx_domain_rbtree_node_t *) node;

        m = ngx_masks_lookup_mask_unlocked(ms, qnode, mask, flags);
        if (m) {
            /** We have to have some limits here, or hackers may spam us
             */
            if (m->ref_count_ >
                    MASKS_STORAGE_PURGE_REF_COUNT_MAX)
            {
                rc = NGX_MASKS_STORAGE_LIMIT_REACHED;
                goto out;
            }

            prev_purge_start_time = m->purge_start_time_;
            m->purge_start_time_ = purge_start_time;
            prev_flags = m->flags_;
            m->flags_ = (flags | NGX_MASK_FLAG_COMMITED);
            ++m->ref_count_;


            if (is_restoring) {
                m->flags_ |= NGX_MASK_FLAG_COMMITED;

            } else if (ngx_masks_write_to_masks_in(ms, domain, m) != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, ms->log_, ngx_errno,
                    "masks storage: can't persist the mask while updating "
                    "domain = \"%V\", mask = \"%V\", purge_start_time = %d",
                    domain, mask, purge_start_time);

                /** Rollback changes */
                m->purge_start_time_ = prev_purge_start_time;
                m->flags_ = prev_flags;
                --m->ref_count_;

                rc = NGX_MASKS_STORAGE_FAIL;
                goto out;
            }

            rc = NGX_MASKS_STORAGE_OK;
            goto out;
        }
    }

    rc = ngx_masks_insert_mask_unlocked(ms, node, domain, mask, flags,
            purge_start_time, is_restoring);

    if (rc != NGX_MASKS_STORAGE_OK) {
        /** XXX We don't need rollback changes here, since it was added */
        goto out;
    }

out:
    ngx_shmtx_unlock(&shpool->mutex);
    return rc;
}


static ngx_int_t
ngx_masks_storage_exten_cmp(ngx_log_t *log, ngx_str_t *mask_,
        ngx_str_t *exten_)
{
    ngx_str_t mask, exten;

    mask = *mask_;
    exten = *exten_;

    /* Sometime exten could be 0, and this means it could be matched.
     *
     * See an issue: NCCS-680
     * {{{
     */
    if ((exten.len == 0 && mask.len != 0) ||
            (mask.len == 0 && exten.len != 0))
    {
        return NGX_DECLINED;
    }

    if (mask.len == 0 && exten.len == 0) {
        return NGX_OK;
    }
    /* }}} */

    /** Remove *[.](EXT) */
    if (mask.data[0] == '*') {
        ++mask.data;
        --mask.len;
    }

    /** Remove .(EXT) */
    if (mask.data[0] == '.') {
        ++mask.data;
        --mask.len;
    }

    /** Remove .(EXT) */
    if (exten.data[0] == '.') {
        ++exten.data;
        --exten.len;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
            "masks storage: "
            "ngx_masks_storage_exten_cmp() mask = \"%V\" ~ exten = \"%V\" "
            " mask len = %d ~ exten len = %d",
            &mask, &exten, mask.len, exten.len);

    if ((mask.len == exten.len) &&
            (ngx_strncmp(mask.data, exten.data, exten.len) == 0))
    {
        return NGX_OK;
    }

    return NGX_DECLINED;
}


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
    file.log = ms->log_;
    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY, 0, 0);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, ms->log_, ngx_errno,
                "masks storage: restoration failed, can't open a file, "
                "ms = %p, file = \"%V\"", ms, &file.name);
        return NGX_ERROR;
    }

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, ms->log_, ngx_errno,
                "masks storage: restoration failed, can't stat a file, "
                "ms = %p, file = \"%V\"", ms, &file.name);
        goto exit;
    }

    size = ngx_file_size(&fi);

    start = ngx_palloc(ms->pool_, size);
    if (!start) {
        goto exit;
    }

    end = start + size;

    n = ngx_read_file(&file, start, size, 0);

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, ms->log_, ngx_errno,
                "masks storage: restoration failed, can't read a file, "
                "ms = %p, file = \"%V\"", ms, &file.name);
        goto exit;
    }

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_EMERG, ms->log_, ngx_errno,
                "masks storage: restoration failed, can't read a file, "
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
        ngx_pfree(ms->pool_, start);
    }

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ms->log_, ngx_errno,
                ngx_close_file_n " \"%V\" failed", &file.name);
    }

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

    if (!ms || !dirname || !ms->pool_ || !ms->log_) {
        ngx_log_error(NGX_LOG_EMERG, ms->log_, 0,
                "masks storage: ngx_masks_storage_restore() got invalid input, "
                "ms = %p, path = %p", ms, dirname);
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&ms->shpool_->mutex);

    if (ms->sh_->restoring_ == 0) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ms->log_, 0,
                "masks storage: restored already, ms = %p, path = \"%V\"",
                ms, dirname);
        ngx_shmtx_unlock(&ms->shpool_->mutex);
        return NGX_DECLINED;
    }

    ngx_shmtx_unlock(&ms->shpool_->mutex);

    /** Restoring {{{ */
    ngx_log_error(NGX_LOG_INFO, ms->log_, 0,
            "masks storage: restoring, ms = %p, path = \"%V\"",
            ms, dirname);

    dirp = opendir((char *) get_dirname(dirname));
    if (!dirp) {
        ngx_log_error(NGX_LOG_ERR, ms->log_, ngx_errno,
                "background purge: can't open a directory = \"%s\" "
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

        /** Skip, if '.' and '..' */

        if ((dp->d_reclen == 1) && (dp->d_name[0] == '.')) {
            continue;
        }

        if ((dp->d_reclen == 2) && (dp->d_name[0] == '.') &&
                (dp->d_name[1] == '.'))
        {
            continue;
        }

        /**
         * Skip not files, and w/o permissions
         */
        if (access((char *) full_path, F_OK) == -1) {
            ngx_log_error(NGX_LOG_CRIT, ms->log_, ngx_errno,
                    "background purge: I/O error (restoring) probably, needs more "
                    "permissions for working with a file = \"%s\"", full_path);
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
            ngx_log_error(NGX_LOG_EMERG, ms->log_, ngx_errno,
                "masks storage: restoration failed, ms = %p, path = \"%V\"",
                ms, &full_path_str);
            closedir(dirp);
            return NGX_ERROR;
        }

        if (ngx_quit || ngx_terminate) {
            rc = NGX_ABORT;
            break;
        }
    }

    closedir(dirp);
    /** }}} */

    ngx_shmtx_lock(&ms->shpool_->mutex);
    ms->sh_->restoring_ = 0;
    ngx_shmtx_unlock(&ms->shpool_->mutex);

    ngx_log_error(NGX_LOG_INFO, ms->log_, 0,
            "masks storage: restored successfully, ms = %p, path = \"%V\"",
            ms, dirname);

    return rc;
}


static ngx_int_t
ngx_masks_storage_foreach(ngx_masks_storage_t *ms,
    void *data, ngx_int_t (*on_element)(void *, ngx_mask_t *, ngx_str_t *))
{
    ngx_domain_rbtree_node_t       *n;
    ngx_rbtree_node_t           *node, *root, *sentinel;
    ngx_masks_rbtree_node_t *sub_n;
    ngx_rbtree_node_t           *sub_node, *sub_root, *sub_sentinel;
    ngx_int_t                    rc;
    ngx_queue_t                 *q;
    ngx_mask_queue_t       *mqueue;

    if (!ms || !ms->sh_ || !ms->sh_->rbtree_) {
        return NGX_OK;
    }

    sentinel = ms->sh_->sentinel_;
    root = ms->sh_->rbtree_->root;

    ngx_shmtx_lock(&ms->shpool_->mutex);

    if (root == sentinel) {
        ngx_shmtx_unlock(&ms->shpool_->mutex);
        return NGX_OK;
    }

    for (node = ngx_rbtree_min(root, sentinel);
         node;
         node = ngx_rbtree_next(ms->sh_->rbtree_, node))
    {
        n = (ngx_domain_rbtree_node_t *) node;

        sub_sentinel = n->value_.sentinel_;
        sub_root = n->value_.masks_->root;

        if (sub_sentinel != sub_root) {
            for (sub_node = ngx_rbtree_min(sub_root, sub_sentinel);
                 sub_node;
                 sub_node = ngx_rbtree_next(n->value_.masks_, sub_node))
            {
                sub_n = (ngx_masks_rbtree_node_t *) sub_node;

                for (q = ngx_queue_head(&sub_n->mask_queue_.queue_);
                        q != ngx_queue_sentinel(&sub_n->mask_queue_.queue_);
                        q = ngx_queue_next(q))
                {
                    mqueue = ngx_queue_data(q, ngx_mask_queue_t, queue_);

                    rc = on_element(data, &mqueue->mask_, &n->sn_.str);
                    if (rc != NGX_OK) {
                        ngx_shmtx_unlock(&ms->shpool_->mutex);
                        return rc;
                    }
                }
            }
        }
    }

    ngx_shmtx_unlock(&ms->shpool_->mutex);

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
    pool = fw_ctx->r_->pool;
    tf = fw_ctx->temp_file;

    size = (sizeof("{'flags':,'mask':'','pst':,'domain':''},") - 1) +
                UINT32_STR_MAX + mask->mask_.len +
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
            "{\"flags\":%d,\"mask\":\"%V\",\"pst\":%T,\"domain\":\"%V\"},",
            mask->flags_, &mask->mask_, mask->purge_start_time_, domain);

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

    pool = ctx->r_->pool;
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
    if (!conf->masks_storage_) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "masks_storage: the module is off for \"%V\"", &r->uri);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
    if (tf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    tf->file.fd = NGX_INVALID_FILE;
    tf->file.log = r->connection->log;
    tf->path = conf->masks_storage_->tmp_path_;
    tf->pool = r->pool;
    tf->warn = "a folder dump response body is buffered to a temporary file";
    tf->log_level = 0;
    tf->persistent = 0;
    tf->clean = 1;

    ctx.r_ = r;
    ctx.temp_file = tf;

    rc = ngx_http_cache_purge_folder_writer_format(&ctx, "[", sizeof("[") - 1);
    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    start = tf->offset;

    rc = ngx_masks_storage_foreach(conf->masks_storage_, (void *) &ctx,
            &ngx_http_cache_purge_folder_writer);
    if (rc == NGX_ERROR) {
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
    if (!conf->masks_storage_) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "masks_storage: the module is off for \"%V\"", &r->uri);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_masks_storage_flush(conf->masks_storage_);

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

ngx_int_t
ngx_http_get_host_from_cachekey(ngx_http_request_t *r,
    ngx_str_t *request_host)
{
    ngx_str_t                  *cache_key;
    u_char                     *buf_start, *buf_end;
    u_char                     *pattern, *host_start;

    request_host->data = NULL;
    request_host->len = 0;

    if (r->cache && r->cache->keys.elts) {
        cache_key = r->cache->keys.elts;
        buf_start = cache_key->data;
        buf_end = cache_key->data + cache_key->len;
        if (cache_key->len < sizeof("://") - 1) {
            return NGX_ERROR;
        }
        pattern = ngx_strstrn(buf_start, "://", sizeof("://") - 1 - 1);
        if (!pattern) {
            return NGX_ERROR;
        }
        host_start = pattern + sizeof("://") - 1;
        for (buf_start = host_start; buf_start != buf_end; buf_start++) {
            if (*buf_start == '/') {
                request_host->data = host_start;
                request_host->len = buf_start - host_start;
                return NGX_OK;
            }
        }
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "ngx_http_get_host_from_cachekey() "
            "cache key does not have an host");

    return NGX_ERROR;
}


ngx_int_t
ngx_http_foreground_purge(ngx_http_request_t *r,
        ngx_http_cache_t *c, time_t now)
{
    ngx_masks_storage_shctx_t    *sh;
    ngx_slab_pool_t                  *shpool;
    ngx_domain_rbtree_node_t            *node;
    ngx_str_t                        *mask, domain, *url, url_path,
                                      mask_path, mask_rest, url_rest, temp_url;
    ngx_mask_t                   *v;
    time_t                            purge_start_time, cache_create_time;
    ngx_uint_t                        find_flag;
    ngx_masks_storage_t          *masks_storage;
    ngx_masks_storage_loc_conf_t *conf;
    ngx_core_conf_t                  *ccf;
    ngx_int_t                         mask_matched, cnt;
    ngx_masks_rbtree_node_t      *sub_node;
    ngx_queue_t                      *q;
    ngx_mask_queue_t             *mask_queue;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
            ngx_core_module);

    if (!ccf->master) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "masks_storage, foreground_purge, background_purge "
                "are not support with \"master_process off;\"");
        return NGX_DECLINED;
    }

    if ((!c) || (!c->node) ||
            (c->node->updating && c->updating) || (c->valid_sec < now))
    {
        return NGX_DECLINED;
    }

    /***
     * Slice purge (a metadata module) may re-call this module while it works.
     * That will be an issue, it will be forever loop. For avoiding this, this
     * module ignore all subrequests.
     */
    if (r != r->main) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "foreground purge: is subrequest: %s",
                (r != r->main ? "yes" : "no"));
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_masks_storage_module);

    /* The module is off */
    if (!conf->masks_storage_) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "masks_storage: the module is off for \"%V\"", &r->uri);
        return NGX_DECLINED;
    }

    /** Module is on, but the feature is off */
    if (!conf->foreground_purge_enable_) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "foreground purge: feature is off for \"%V\"", &r->uri);
        return NGX_DECLINED;
    }

    if ((r->method_name.len == (sizeof("PURGE") - 1)) &&
            (ngx_strncasecmp(r->method_name.data, (u_char *) "PURGE",
                             sizeof("PURGE") -1) == 0))
    {
        return NGX_DECLINED;
    }

    cache_create_time = c->date;

    masks_storage = conf->masks_storage_;
    v = NULL;
    purge_start_time = 0;
    sh = masks_storage->sh_;
    shpool = masks_storage->shpool_;
    url = &r->uri;
    find_flag = 0;
    ngx_str_set(&domain, "");

    if (ngx_http_get_host_from_cachekey(r, &domain)  == NGX_ERROR) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "foreground purge: failed get_host_from_cachekey");
        goto out;
    }

    ngx_shmtx_lock(&shpool->mutex);

    if (sh->restoring_) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "foreground purge: masks storage is restoring, skiping");
        goto out;
    }

    node = (ngx_domain_rbtree_node_t *)
        ngx_masks_lookup_domain_unlocked(masks_storage, &domain);
    if (!node) {
        /** This domain does not have any active purges */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "foreground purge: domain does not have any active purges, "
                "domain = \"%V\"", &domain);
        goto out;
    }

    temp_url.len = url->len;
    temp_url.data = url->data;
    cnt = next_path(&temp_url, 0);

    while (temp_url.len > 0) {
        sub_node = ngx_masks_get_mask_queue_unlocked(
                        masks_storage, node, &temp_url, 0);
        if (!sub_node) {
            goto next_path;
        }

        for (q = ngx_queue_head(&sub_node->mask_queue_.queue_);
             q != ngx_queue_sentinel(&sub_node->mask_queue_.queue_);
             q = ngx_queue_next(q))
        {
            mask_queue = ngx_queue_data(q, ngx_mask_queue_t, queue_);
            v = &mask_queue->mask_;

            if ((!v->mask_.data) || !(v->flags_ & NGX_MASK_FLAG_COMMITED)) {
                continue;
            }

            mask = &v->mask_;

            parse_path(mask, &mask_path, &mask_rest);
            parse_path(url, &url_path, &url_rest);

            mask_matched = 0;

            /** Match with a mask */
            if (v->flags_ & NGX_MASK_FLAG_RECURSIVE) {

                ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "foreground purge: compare recursive "
                    "masks url = \"%V\"(%d) ~ mask = \"%V\"(%d)",
                    &mask_path, mask_path.len, &url_path, url_path.len);

                /** Begins */
                if (mask_path.len <= url_path.len &&
                    ngx_strncmp(mask_path.data, url_path.data, mask_path.len)
                        == 0)
                {
                    mask_matched = 1;
                }

            /** and non recursive purge */
            } else {

                ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "foreground purge: compare non recursive "
                        "masks url = \"%V\"(%d) ~ mask = \"%V\"(%d), flags = %d",
                        &mask_path, mask_path.len, &url_path, url_path.len,
                        v->flags_);

                if (mask_path.len == url_path.len &&
                    ngx_strncmp(mask_path.data, url_path.data, url_path.len)
                        == 0)
                {
                    mask_matched = 1;
                }

            }

            if (mask_matched == 1) {

                /** Check *.EXT, if it is set. */
                if (v->flags_ & NGX_MASK_FLAG_PURGE_FILES_WITH_EXT) {

                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "foreground purge: compare exten storage exten = \"%V\" ~ "
                        "r->exten = \"%V\"", &mask_rest, &r->exten);

                    /** Match *.EXT */
                    if (ngx_masks_storage_exten_cmp(r->connection->log,
                                &mask_rest, &r->exten) == NGX_OK)
                    {
                        purge_start_time = v->purge_start_time_;
                    }
                }
                /** Matched, means we have to purge all files in the folder */
                else {
                    purge_start_time = v->purge_start_time_;
                }

                find_flag = 0;

                if (purge_start_time > 0 &&
                        cache_create_time <= purge_start_time)
                {
                    find_flag = 1;
                    c->valid_sec = now - 1;
                }

                if (!find_flag) {
                    /** searching next */
                } else {
                    goto out;
                }
            }
        } /** for */

next_path:
        cnt = next_path(&temp_url, cnt);
    }

out:
    ngx_shmtx_unlock(&shpool->mutex);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "foreground purge: \"%V\" - does purge, "
            "if purge_start_time = 0 means it will not "
            "be purged, cache_create_time: %T, purge_start_time: %T",
            &r->uri, cache_create_time, purge_start_time);

    if (find_flag) {
        return NGX_OK;
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_folder_cache_purge(ngx_http_request_t *r)
{
    ngx_str_t                         domain, mask, err;
    ngx_int_t                         rc, flags;
    time_t                            purge_start_time;
    ngx_masks_storage_loc_conf_t *conf;
    ngx_core_conf_t                  *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
            ngx_core_module);

    if (!ccf->master) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "masks_storage, foreground_purge, background_purge "
            "are not support with \"master_process off;\"");
        return NGX_MASKS_STORAGE_DENY;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_masks_storage_module);

    /**
     * The module is off
     */
    if (!conf->masks_storage_) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "masks_storage: the module is off for \"%V\"", &r->uri);
        return NGX_MASKS_STORAGE_DENY;
    }

    err.data = NULL;
    err.len = 0;

    conf->masks_storage_->r_ = r;
    conf->masks_storage_->log_ = r->connection->log;

    rc = ngx_masks_storage_parse_request(conf->masks_storage_, &domain,
            &mask, &flags, &purge_start_time, &err);
    if (rc != NGX_MASKS_STORAGE_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "masks_storage: can't parse request, rc = %d", rc);
        return rc;
    }

    rc = ngx_masks_storage_add_mask(conf->masks_storage_, &domain, &mask,
            flags, purge_start_time, 0);
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
#if defined (NGX_DEBUG)
    size_t                            i;
    ngx_table_elt_t                  *h;
    ngx_list_part_t                  *part;
    ngx_masks_storage_loc_conf_t *conf;
    ngx_core_conf_t                  *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
            ngx_core_module);

    if (!ccf->master) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "masks_storage, foreground_purge, background_purge "
            "are not support with \"master_process off;\"");
        return NGX_MASKS_STORAGE_SERVICE_DISABLE;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_masks_storage_module);

    /**
     * The module is off
     */
    if (!conf->masks_storage_) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "masks_storage: the module is off for \"%V\"", &r->uri);
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
#endif /* (NGX_DEBUG) */

    return NGX_MASKS_STORAGE_DENY;
}


ngx_int_t
ngx_http_folder_flush(ngx_http_request_t *r)
{
#if defined (NGX_DEBUG)
    size_t                            i;
    ngx_table_elt_t                  *h;
    ngx_list_part_t                  *part;
    ngx_masks_storage_loc_conf_t *conf;
    ngx_core_conf_t                  *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
            ngx_core_module);

    if (!ccf->master) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "masks_storage, foreground_purge, background_purge "
            "are not support with \"master_process off;\"");
        return NGX_MASKS_STORAGE_SERVICE_DISABLE;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_masks_storage_module);

    /**
     * The module is off
     */
    if (!conf->masks_storage_) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "masks_storage: the module is off for \"%V\"", &r->uri);
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
#endif /* (NGX_DEBUG) */

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
    ngx_str_t *domain, ngx_str_t *mask, ngx_int_t flags,
    time_t purge_start_time, ngx_int_t is_restoring)
{
    (void) is_restoring;

    ngx_full_mask_t *full_mask;

    full_mask = ngx_list_push(&ms->purger_queue_);

    if (!full_mask) {
        ngx_log_error(NGX_LOG_ERR, ms->log_, 0,
                "background purge: ngx_list_push() failed, ms = %p",
                ms);
        return NGX_MASKS_STORAGE_FAIL;
    }

    /** Domain */
    full_mask->domain_.len = domain->len;
    full_mask->domain_.data = ngx_palloc(ms->pool_,
            sizeof(u_char) * domain->len + 1 /* \0 - \0 */);
    if (!full_mask->domain_.data) {
        ngx_log_error(NGX_LOG_ERR, ms->log_, 0,
                "background purge: can't clone domain, ms = %p",
                ms);
        return NGX_MASKS_STORAGE_FAIL;
    }
    ngx_snprintf(full_mask->domain_.data, domain->len, "%V%Z", domain);

    /** Mask */
    full_mask->mask_.mask_.len = mask->len;
    full_mask->mask_.mask_.data = ngx_palloc(ms->pool_,
            sizeof(u_char) * mask->len + 1 /* \0 - \0 */);
    if (!full_mask->mask_.mask_.data) {
        ngx_log_error(NGX_LOG_ERR, ms->log_, 0,
                "background purge: can't clone mask, ms = %p",
                ms);
        return NGX_MASKS_STORAGE_FAIL;
    }
    ngx_snprintf(full_mask->mask_.mask_.data, mask->len, "%V%Z", mask);

    /** Flags */
    full_mask->mask_.flags_ = flags;

    /** Purge start time */
    full_mask->mask_.purge_start_time_ = purge_start_time;

    return NGX_MASKS_STORAGE_OK;
}


static inline void
ngx_masks_storage_purger_queue_free(ngx_masks_storage_t *ms,
        ngx_int_t clean_shared_memory)
{
    ngx_uint_t                   i, flags, flagssh;
    ngx_list_part_t             *part, *next;
    ngx_full_mask_t         *fm;
    ngx_domain_rbtree_node_t       *n;
    ngx_rbtree_node_t           *node;
    ngx_slab_pool_t             *shpool;
    ngx_str_t                   *mask, *masksh, *domain;
    ngx_int_t                    rc;
    ngx_masks_rbtree_node_t *sub_node;
    ngx_queue_t                 *q;
    ngx_mask_queue_t        *mask_queue;

    shpool = ms->shpool_;
    part = &ms->purger_queue_.part;
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

        if (clean_shared_memory) {

            ngx_shmtx_lock(&shpool->mutex);

            domain = &fm[i].domain_;

            node = (ngx_rbtree_node_t *)
                ngx_str_rbtree_lookup(ms->sh_->rbtree_, domain, ngx_crc32_long(
                            domain->data, domain->len));

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ms->log_, 0,
                    "background purge: %p domain = \"%V\"(%d), found = %s",
                    ms->sh_->rbtree_, domain, domain->len,
                    (node != NULL ? "yes" : "no"));

            if (!node) {
                goto shmtx_unlock;
            }

            n = (ngx_domain_rbtree_node_t *) node;
            mask = &fm[i].mask_.mask_;
            flags = fm[i].mask_.flags_;

            sub_node = ngx_masks_get_mask_queue_unlocked(ms, n, mask, 1);
            if (!sub_node) {
                goto shmtx_unlock;
            }

            for (q = ngx_queue_head(&sub_node->mask_queue_.queue_);
                 q != ngx_queue_sentinel(&sub_node->mask_queue_.queue_);
                 q = ngx_queue_next(q))
            {
                mask_queue = ngx_queue_data(q, ngx_mask_queue_t, queue_);
                masksh = &mask_queue->mask_.mask_;
                flagssh = mask_queue->mask_.flags_;


                rc = ngx_masks_compare(ms, mask, flags, masksh, flagssh);

                ngx_log_debug7(NGX_LOG_DEBUG_HTTP, ms->log_, 0,
                    "background purge: compare sh = \"%V\" (%d), flags = %d"
                    " ~ mask = \"%V\" (%d), flags = %d, is equal = %s",
                    masksh, masksh->len, flagssh, mask, mask->len, flags,
                    (rc == NGX_DECLINED) ? "yes" : "no");

                if (rc == NGX_DECLINED) {
                    continue;
                }

                --mask_queue->mask_.ref_count_;

                if (mask_queue->mask_.ref_count_ == 0 ||
                    /** This case is possible then shared memory has been
                     * corrupted */
                    mask_queue->mask_.ref_count_ > MASKS_STORAGE_PURGE_REF_COUNT_MAX)
                {
                    ngx_queue_remove(q);
                    ngx_slab_free_locked(shpool, mask_queue);
                    --n->value_.len_;
                }

                break;

            }

            if (ngx_queue_empty(&sub_node->mask_queue_.queue_)) {
                ngx_rbtree_delete(n->value_.masks_, &sub_node->sn_.node);
                ngx_slab_free_locked(shpool, sub_node->sn_.str.data);
                ngx_slab_free_locked(shpool, sub_node);
            }

            if (n->value_.len_ == 0) {
                ngx_slab_free_locked(shpool, n->value_.masks_);
                ngx_rbtree_delete(ms->sh_->rbtree_, node);
                ngx_slab_free_locked(shpool, n->sn_.str.data);
                ngx_slab_free_locked(shpool, n);
            }

shmtx_unlock:
            ngx_shmtx_unlock(&shpool->mutex);
        }

        if (fm[i].domain_.data) {
            ngx_pfree(ms->pool_, fm[i].domain_.data);
            fm[i].domain_.data = NULL;
        }

        if (fm[i].mask_.mask_.data) {
            ngx_pfree(ms->pool_, fm[i].mask_.mask_.data);
            fm[i].mask_.mask_.data = NULL;
        }
    }

    part = &ms->purger_queue_.part;
    next = part->next;
    ngx_pfree(ms->purger_queue_.pool, part->elts);
    part = next;
    while (part != NULL) {
        next = part->next;
        ngx_pfree(ms->purger_queue_.pool, part->elts);
        ngx_pfree(ms->purger_queue_.pool, part);
        part = next;
    }

    ngx_memzero(&ms->purger_queue_, sizeof(ngx_list_t));
}


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
    file.log = ms->log_;
    file.fd = ngx_open_file(filename, NGX_FILE_RDONLY, 0, 0);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, ms->log_, ngx_errno,
                "background purge: can't open a file, "
                "ms = %p, file = \"%V\"", ms, &file.name);
        return NGX_ERROR;
    }

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, ms->log_, ngx_errno,
                "background purge: can't stat a file, "
                "ms = %p, file = \"%V\"", ms, &file.name);
        goto exit;
    }

    size = ngx_file_size(&fi);

    start = ngx_palloc(ms->pool_, size);

    if (!start) {
        goto exit;
    }

    end = start + size;

    n = ngx_read_file(&file, start, size, 0);

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, ms->log_, ngx_errno,
                "background purge: can't read a file ",
                "ms = %p, file = \"%V\"", ms, &file.name);
        goto exit;
    }

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_EMERG, ms->log_, ngx_errno,
                "background purge: can't read a file "
                "returned only %z bytes instead of %uz ms = %p, file = \"%V\"",
                n, size, ms, &file.name);
        goto exit;
    }

    rc = ngx_deserialize_mask(ms, start, end,
            &ngx_masks_storage_purger_add_mask);
    if (rc == NGX_ERROR) {
        goto exit;
    }

exit:
    if (start) {
        ngx_pfree(ms->pool_, start);
    }

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        /** Warning? */
        ngx_log_error(NGX_LOG_ALERT, ms->log_, ngx_errno,
                "background purge: " ngx_close_file_n " \"%V\" failed",
                &file.name);
    }

    ngx_log_error(NGX_LOG_INFO, ms->log_, 0,
            "background purge: read purger queue, rc = %d", rc);

    return rc;
}


void ngx_dumb_timer(ngx_event_t *ev)
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

    if (++m->processed_files_ >= m->background_purger_files_) {
        do_sleep = 1;
    } else {
        elapsed = ngx_abs((ngx_msec_int_t) (ngx_current_msec - m->last_));
        do_sleep = elapsed >= m->background_purger_threshold_? 1 : 0;
    }

    if (do_sleep) {

        ngx_log_error(NGX_LOG_INFO, m->log_, 0,
                "background purge: slowdown for %T msec, last slowdown = %T",
                m->background_purger_sleep_, m->last_);

        ngx_memzero(&dumb_con, sizeof(ngx_connection_t));
        ev->handler = ngx_dumb_timer;
        ev->log = m->log_;
        ev->data = &dumb_con;
        dumb_con.fd = (ngx_socket_t) -1;

        ngx_add_timer(ev, m->background_purger_sleep_);
        ngx_process_events_and_timers(cycle);

        m->last_ = ngx_current_msec;
        m->processed_files_ = 0;
    }
}


static ngx_int_t
ngx_remove_file(ngx_tree_ctx_t *ctx, ngx_str_t *filename)
{
    static u_char cache_key[] = { LF, 'K', 'E', 'Y', ':', ' ' };
    static size_t header_size = sizeof(ngx_http_file_cache_header_t)
                    + sizeof(cache_key);

    ngx_str_t                         mask_path, mask_rest, domain, url, ext,
                                      url_path, url_rest;
    ngx_masks_storage_t              *m;
    ngx_int_t                         fd, rc, src;
    u_char                           *buf, *buf_start, *buf_end,
                                     *domain_start, *domain_end, *url_start,
                                     *url_end;
    ngx_http_file_cache_header_t     *h;
    ngx_list_part_t                  *part;
    ngx_full_mask_t                  *fm;
    time_t                            purge_start_time;
    ngx_uint_t                        i, buf_size;
    ngx_uint_t                        find_flag;
    ngx_uint_t                        find_invalidate_cnt;

    ngx_masks_storage_event_t        *masks_event;
    ngx_cycle_t                      *cycle;
    ngx_event_t                      *ev;

    masks_event = (ngx_masks_storage_event_t *) ctx->data;
    m = masks_event->masks_;
    cycle = masks_event->cycle_;
    ev = masks_event->ev_;

    ngx_log_error(NGX_LOG_INFO, m->log_, 0,
        "background purge: ngx_remove_file: at file \"%V\"", filename);

    rc = NGX_OK;
    purge_start_time = 0;
    find_invalidate_cnt = 0;

    fd = open((const char *) filename->data, O_RDWR | O_SYNC | O_NOFOLLOW);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_WARN, m->log_, ngx_errno,
                "background purge: ngx_remove_file: can't open a file "
                "\"%V\". Possible that nginx's cache manger did a remove",
                filename);
        return NGX_DECLINED;
    }

    buf_size = header_size + ngx_pagesize * 2;
    buf = (u_char *) ngx_pnalloc(m->pool_, buf_size);

    if (!buf) {
        ngx_log_error(NGX_LOG_CRIT, m->log_, 0,
                "background purger: ngx_remove_file: "
                "can't allocate an I/O buffer");
        rc = NGX_ABORT;
        goto exit;
    }

    rc = read(fd, buf, buf_size);
    if (rc == -1 || rc < (off_t) header_size) {
        ngx_log_error(NGX_LOG_INFO, m->log_, ngx_errno,
                "background purger: ngx_remove_file: can't read a file "
                "\"%V\", rc = %d, hs = %d",
                filename, rc, (ngx_int_t) header_size);
        rc = NGX_ABORT;
        goto exit;
    }

    h = (ngx_http_file_cache_header_t *) &buf[0];

    buf_start = &buf[0] + header_size;
    buf_end = buf_start + rc;

    rc = NGX_OK;

    if (h->version != NGX_HTTP_CACHE_VERSION) {
        /** This will be deleted by nginx */
        ngx_log_error(NGX_LOG_ERR, m->log_, 0,
                "background purger: ngx_remove_file: "
                "cache file \"%V\" version mismatch",
                filename);
        /** NGX_OK */
        rc = NGX_OK;
        goto exit;
    }

    /** Parse domain and URL {{{
     */

    /** Skip schema {{{ */
    if ((buf_end - buf_start) > (int) sizeof("http://") - 1
            && ngx_strncmp(buf_start, "http://", sizeof("http://") - 1) == 0)
    {
        buf_start = buf_start + (sizeof("http://") - 1);

    } else if ((buf_end - buf_start) > (int) sizeof("https://") - 1
            && ngx_strncmp(buf_start, "https://", sizeof("https://") - 1) == 0)
    {
        buf_start = buf_start + (sizeof("https://") - 1);

    } else if ((buf_end - buf_start) > (int) sizeof("://") -1
            && ngx_strncmp(buf_start, "://", sizeof("://") - 1) == 0)
    {
        buf_start = buf_start + (sizeof("://") - 1);

    } else {
        /** TODO searching :// in the string ?*/
    }
    /** }}} */

    domain_start = buf_start;
    domain_end = NULL;
    url_start = NULL;
    url_end = NULL;

    for ( ;buf_start != buf_end; ++buf_start) {

        if (!domain_end && (*buf_start == '/')) {
            domain_end = buf_start;
            url_start = buf_start;
        }

        if (domain_end && (*buf_start == '[')) {
            url_end = buf_start;
            break;
        }
    }

    if (!domain_end || !url_start || !url_end) {
        ngx_log_error(NGX_LOG_ERR, m->log_, 0,
            "background purger: ngx_remove_file: can't find domain or/and "
            "url in \"%V\", skiping", filename);
        /** NGX_OK */;
        rc = NGX_OK;
        goto exit;
    }

    domain.data = domain_start;
    domain.len = (size_t) (domain_end - domain_start);

    url.data = url_start;
    url.len = (size_t) (url_end - url_start);
    /** }}} */

    /** Searching in the purge queue
     */
    part = &m->purger_queue_.part;
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

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, m->log_, 0,
            "background purge: compare domains [Purge]\"%V\" ~ [Cache]\"%V\"",
            &fm[i].domain_, &domain);

        if (fm[i].domain_.len != domain.len
            || ngx_strncmp(fm[i].domain_.data, domain.data, domain.len) != 0)
        {
            continue;
        }

        parse_path(&fm[i].mask_.mask_, &mask_path, &mask_rest);
        parse_path(&url, &url_path, &url_rest);

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, m->log_, 0,
            "background purge: compare masks [Purge]\"%V\" (%d) ~ "
            "[Cache]\"%V\" (%d)",
            &mask_path, mask_path.len, &url_path, url_path.len);

        /** Match with a mask */
        if (/**
             * An issue: NCCS-667
             *
             * The bug cames from the first version of the background
             * purge. The first version worked recursively. Means
             * mask_path.len == url.len.
             */
            (mask_path.len == url_path.len &&
            ngx_strncmp(mask_path.data, url_path.data, mask_path.len) == 0) ||

            /** {delete, invalidate}-recursive */
            (fm[i].mask_.flags_ & NGX_MASK_FLAG_RECURSIVE &&
                mask_path.len <= url_path.len &&
                ngx_strncmp(mask_path.data, url_path.data, mask_path.len) == 0)
            )
        {
            /** *.EXT or it has a file case */
            if (fm[i].mask_.flags_ & NGX_MASK_FLAG_PURGE_FILES_WITH_EXT) {

                /** Match *.EXT */
                ext = extract_ext(&url_rest);

                ngx_log_debug4(NGX_LOG_DEBUG_HTTP, m->log_, 0,
                    "background purge: compare ext [P:%d]\"%V\" ~ [C:%d]\"%V\"",
                    mask_rest.len, &mask_rest, ext.len, &ext);

                if (ngx_masks_storage_exten_cmp(m->log_, &mask_rest,
                            &ext) == NGX_OK)
                {
                    purge_start_time = fm[i].mask_.purge_start_time_;
                }
            }
            /** Matched, means we have to purge all files in the folder */
            else {
                purge_start_time = fm[i].mask_.purge_start_time_;
            }

            ngx_log_debug5(NGX_LOG_DEBUG_HTTP, m->log_, 0,
                "background purge: \"%V\" purge_start (0 == not set) = %T, "
                "date = %T, queue purge start time = %T, is recursive = %s",
                &mask_path, purge_start_time, h->date,
                fm[i].mask_.purge_start_time_,
                ((fm[i].mask_.flags_ & NGX_MASK_FLAG_RECURSIVE) ?
                    "yes" : "no")
                );

            /** The cache will be purged.
             *
             * '<=' - because we are here, so purge it.
             */
            find_flag = 0;
            if (h->date <= purge_start_time) {

                find_flag = 1;

                ngx_log_debug4(NGX_LOG_DEBUG_HTTP, m->log_, 0,
                    "background purge: purge a file = \"%V\" "
                    "domain = \"%V\" url = \"%V\" options = %d",
                    filename, &domain, &url, fm[i].mask_.flags_);

                if ((fm[i].mask_.flags_ & NGX_MASK_FLAG_INVALIDATE) &&
                        (h->valid_sec > ngx_time()))
                {
                    /** Expire the cache
                     */
                    h->valid_sec = ngx_time() - 1;

                    src = (ngx_int_t) lseek(fd, 0, SEEK_SET);
                    if (src != 0 /** should be 0 */) {
                        ngx_log_error(NGX_LOG_ERR, m->log_, ngx_errno,
                                "background purge: can't lseek() to a file \"%V\" "
                                " flag = invalidate rc = %d",
                                filename, src);
                        rc = NGX_ABORT;
                        goto exit;
                    }

                    /**
                     * Even if it does corrupt the file nginx will fix the file.
                     * Nginx will pull the file from the origin.
                     */
                    src = (ngx_int_t) write(fd, (void *) h,
                            sizeof(ngx_http_file_cache_header_t));
                    if (src != sizeof(ngx_http_file_cache_header_t)) {
                        ngx_log_error(NGX_LOG_ERR, m->log_, ngx_errno,
                                "background purge: can't write() to a file \"%V\" "
                                " flag = invalidate rc = %d",
                                filename, src);
                        rc = NGX_ABORT;
                        goto exit;
                    }

                    /** fsync() may fail here, this is okay.
                     * Even if the file corrupted the file will be fixed by
                     * nginx.
                     */
                    fsync(fd);

                    ++m->invalidated_files_;

                    find_flag = 0;
                    find_invalidate_cnt++;

                } else if (fm[i].mask_.flags_ & NGX_MASK_FLAG_DELETE) {

                    if (remove_file(m->pool_, filename) == NGX_ERROR) {
                        ngx_log_error(NGX_LOG_ERR, m->log_, ngx_errno,
                                "background purge: can't remove a file \"%V\" "
                                " flag = delete",
                                filename);
                        rc = NGX_ABORT;
                        goto exit;
                    }

                    ++m->removed_files_;
                    if (find_invalidate_cnt > 0) {
                        m->invalidated_files_ -= find_invalidate_cnt;
                    }

                } else {
                    /** This case is almost imposible. But if it happened then
                     * we remove the file and say warning to the log
                     */
                    ngx_log_error(NGX_LOG_WARN, m->log_, 0,
                            "background purge: flag = UNKNOWN (%d) a file \"%V\"",
                            fm[i].mask_.flags_, filename);

                    if (remove_file(m->pool_, filename) == NGX_ERROR) {
                        ngx_log_error(NGX_LOG_ERR, m->log_, ngx_errno,
                                "background purge: can't remove a file \"%V\" "
                                " flag = UNKNOWN",
                                filename);
                        rc = NGX_ABORT;
                        goto exit;
                    }

                    ++m->removed_files_with_error_;
                    if (find_invalidate_cnt > 0) {
                        m->invalidated_files_ -= find_invalidate_cnt;
                    }
                }
            }

            if (!find_flag) {
                /** Searching next */
            } else {
                break;
            }
        }
    }

    ngx_background_purge_slowdown(m, cycle, ev);

exit:

    close(fd);

    if (buf) {
        ngx_pfree(m->pool_, buf);
    }

    /** Master has been restarted or terminated.
     */
    if (ngx_quit || ngx_terminate) {
        m->walk_tree_failed_ = 1;
        return NGX_ABORT;
    }

    /** The abort has been set by code, means something goes wrong.
     */
    if (rc == NGX_ABORT) {
        m->walk_tree_failed_ = 1;
    }

    ++m->processed_files_;

    return rc;
}


static ngx_int_t
ngx_walk_tree_stub(ngx_tree_ctx_t *ctx, ngx_str_t *filename)
{
    (void) ctx, (void) filename;
    return NGX_OK;
}


ngx_int_t
ngx_masks_storage_purger_is_off(void *ms)
{
    ngx_masks_storage_t *m = (ngx_masks_storage_t *) ms;
    if (!m || m->background_purger_off_ == 1) {
        return NGX_OK;
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_masks_storage_background_purge_init(void *ms, ngx_pool_t *pool,
        ngx_log_t *log, ngx_str_t *dirname)
{
    ngx_masks_storage_t *m = (ngx_masks_storage_t *) ms;

    if (!ms || !pool || !log || !dirname) {
        return NGX_ERROR;
    }

    m->log_ = log;
    m->pool_ = pool;

    return ngx_masks_storage_restore(m, dirname);
}


ngx_msec_t
ngx_masks_storage_background_purge(void *ms, ngx_pool_t *pool,
        ngx_log_t *log, ngx_str_t *dirname, ngx_cycle_t *cycle, ngx_event_t *ev)
{
    ngx_masks_storage_t          *m = (ngx_masks_storage_t *) ms;

    ngx_tree_ctx_t                    tree;
    ngx_uint_t                        i;
    ngx_int_t                         rc;
    ngx_path_t                      **path;
    ngx_masks_storage_event_t     masks_event;

    if (!ms || !pool || !log) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "background purge: invalid pointer ms = %p, poll = %p, log = %p",
                ms, pool, log);
        goto out;
    }

    m->log_ = log;
    m->pool_ = pool;

    path = ngx_cycle->paths.elts;

    m->removed_files_ = 0;
    m->processed_files_ = 0;
    m->invalidated_files_ = 0;
    m->removed_files_with_error_ = 0;
    m->walk_tree_failed_ = 0;
    m->last_ = 0;
    m->start_time_ = ngx_time();

    masks_event.masks_ = m;
    masks_event.cycle_ = cycle;
    masks_event.ev_ = ev;

    for (i = 0; i < ngx_cycle->paths.nelts; i++) {

        ngx_log_error(NGX_LOG_INFO, log, 0,
                "background purge: path = \"%V\", manager = %p",
                &path[i]->name, path[i]->manager);

        if (!path[i]->manager) {
            continue;
        }

        ngx_memset(&tree, 0, sizeof(ngx_tree_ctx_t));

        tree.data = (void *) &masks_event;
        tree.pre_tree_handler = &ngx_walk_tree_stub;
        tree.spec_handler = &ngx_walk_tree_stub;
        tree.post_tree_handler = &ngx_walk_tree_stub;
        tree.file_handler = &ngx_remove_file;
        tree.log = m->log_;

        rc = ngx_walk_tree(&tree, &path[i]->name);

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, m->log_, ngx_errno,
                    "background purge: can't read a path = \"%V\"",
                    &path[i]->name);
            goto out;
        }

        if (rc == NGX_ABORT || rc == NGX_DECLINED) {

            if (m->walk_tree_failed_) {
                ngx_log_error(NGX_LOG_ERR, m->log_, ngx_errno,
                    "background purge: can't purge a file, request failed");
                goto out;
            }

            break;
        }
    }

    /** All goes well, cleanup all resources, print some stats */
    ngx_log_error(NGX_LOG_INFO, m->log_, 0,
            "background purge: finished purge queue = \"%s\", "
            "processed files = %d, removed files = %d, "
            "invalidated files = %d, removed files with error = %d, "
            "exec. time (in sec) = %d",
             m->purger_filename_, m->processed_files_, m->removed_files_,
             m->invalidated_files_, m->removed_files_with_error_,
             ngx_time() - m->start_time_);

    if (ngx_masks_storage_remove_purger_file(m, dirname) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, m->log_, 0,
                "background purge: can't remove a file");
        goto out;
    }

    ngx_masks_storage_purger_queue_free(m, 1);
    return PURGER_DEFAULT_NEXT;

out:
    ngx_masks_storage_purger_queue_free(m, 0);
    return PURGER_DEFAULT_NEXT;
}


static ngx_int_t
ngx_masks_storage_old_purger_file(ngx_masks_storage_t *m,
    ngx_str_t *dirname)
{
    DIR             *dirp;
    struct dirent   *dp;
    u_char           full_path[PATH_MAX + 1];
    const u_char    *dirn;
    ngx_int_t        cnt;

    cnt = 0;

    dirn = get_dirname(dirname);

    dirp = opendir((char *) dirn);
    if (!dirp) {
        ngx_log_error(NGX_LOG_WARN, m->log_, 0,
                "background purge: can't open a directory = \"%s\"",
                dirn);
        return -1;
    }

    while ((dp = readdir(dirp)) != NULL) {

        ngx_snprintf(full_path, sizeof(full_path), "%s/%s%Z",
                dirn, dp->d_name);

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, m->log_, 0,
                "background purge: searching for masks.purger.PID files, "
                "current file = \"%s\", dirn = \"%s\", dp->d_name = \"%s\"",
                full_path, dirn, dp->d_name);

        /** Skip, if '.' and '..' */
        if ((dp->d_reclen >= 1) && (dp->d_name[0] == '.')) {
            continue;
        }

        if ((dp->d_reclen >= 2) && (dp->d_name[0] == '.') &&
                (dp->d_name[1] == '.'))
        {
            continue;
        }

        if ((dp->d_reclen > (sizeof(MASKS_PURGER) - 1)) &&
                (ngx_strncmp(dp->d_name, MASKS_PURGER,
                    sizeof(MASKS_PURGER) - 1) == 0))
        {
            if (is_regular_file(full_path)) {

                if (access((char *) full_path, F_OK) == -1) {
                    ngx_log_error(NGX_LOG_CRIT, m->log_, ngx_errno,
                        "background purge: I/O error (reading a purger queue file) "
                        "probably, needs more permissions for working with a file = "
                        "\"%s\"", full_path);
                    closedir(dirp);
                    return -2;
                }

                ngx_log_error(NGX_LOG_INFO, m->log_, 0,
                    "background purge: found a purge queue file = \"%s\"",
                    full_path);

                if (ngx_masks_storage_read_purger_queue(m, full_path) != NGX_OK) {
                    closedir(dirp);
                    return -3;
                }
                cnt++;
            }
        }
    }

    closedir(dirp);

    return cnt;
}


static ngx_int_t
ngx_masks_storage_remove_purger_file(ngx_masks_storage_t *m,
    ngx_str_t *dirname)
{
    DIR             *dirp;
    struct dirent   *dp;
    u_char           full_path[PATH_MAX + 1];
    const u_char    *dirn;

    dirn = get_dirname(dirname);

    dirp = opendir((char *) dirn);
    if (!dirp) {
        ngx_log_error(NGX_LOG_WARN, m->log_, 0,
                "background purge: can't open a directory = \"%s\"",
                dirn);
        return NGX_ERROR;
    }

    while ((dp = readdir(dirp)) != NULL) {

        ngx_snprintf(full_path, sizeof(full_path), "%s/%s%Z",
                dirn, dp->d_name);

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, m->log_, 0,
                "background purge: searching for masks.purger.PID files, "
                "current file = \"%s\", dirn = \"%s\", dp->d_name = \"%s\"",
                full_path, dirn, dp->d_name);

        /** Skip, if '.' and '..' */
        if ((dp->d_reclen >= 1) && (dp->d_name[0] == '.')) {
            continue;
        }

        if ((dp->d_reclen >= 2) && (dp->d_name[0] == '.') &&
                (dp->d_name[1] == '.'))
        {
            continue;
        }

        if ((dp->d_reclen > (sizeof(MASKS_PURGER) - 1)) &&
                (ngx_strncmp(dp->d_name, MASKS_PURGER,
                    sizeof(MASKS_PURGER) - 1) == 0))
        {
            if (remove((const char *) full_path) == -1) {
                ngx_log_error(NGX_LOG_ERR, m->log_, ngx_errno,
                        "background purge: can't remove a file = \"%s\"",
                        full_path);
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
    struct dirent   *dp;
    ngx_int_t        rc;
    u_char           full_path[PATH_MAX + 1];
    u_char           rename_path[PATH_MAX + 1];
    const u_char    *dirn;
    ngx_int_t        pid;
    ngx_int_t        cnt;

    if (!ms || !pool || !log) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "background purge: invalid pointer ms = %p, poll = %p, log = %p",
                ms, pool, log);
        return NGX_ERROR;
    }

    /** Already has a queue, continue work */
    if (m->purger_queue_.last && m->purger_queue_.last->nelts > 0) {
        ngx_log_error(NGX_LOG_INFO, m->log_, 0,
                "background purge: continue working, purger queue = %d",
                m->purger_queue_.last->nelts);
        return NGX_OK;
    }

    cnt = 0;
    m->log_ = log;
    m->pool_ = pool;

    dirn = get_dirname(dirname);

    ngx_snprintf(m->purger_filename_, sizeof(m->purger_filename_),
            "%s/%s%Z", dirn, MASKS_PURGER);

    rc = ngx_list_init(&m->purger_queue_, m->pool_, 100,
            sizeof(ngx_full_mask_t));
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, m->log_, 0,
                "background purge: can't allocate an queue, "
                "size = %d, ms = %p",
                100 * sizeof(ngx_full_mask_t), m);
        return NGX_ERROR;
    }

    /**
     * Has an old queue
     */

    rc = ngx_masks_storage_old_purger_file(m, dirname);
    if (rc > 0) {
        return NGX_OK;
    } else if (rc < 0) {
        ngx_log_error(NGX_LOG_WARN, m->log_, 0,
                "background purge: can't handle old purger file "
                "in directory = \"%s\"",
                dirn);
        goto error;
    }

    /**
     * Trying to get a next purger file
     */
    dirp = opendir((char *) dirn);
    if (!dirp) {
        ngx_log_error(NGX_LOG_WARN, m->log_, 0,
                "background purge: can't open a directory = \"%s\"",
                dirn);
        goto error;
    }

    while ((dp = readdir(dirp)) != NULL) {

        rc = NGX_DECLINED;

        ngx_snprintf(full_path, sizeof(full_path), "%s/%s%Z",
                dirn, dp->d_name);

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, m->log_, 0,
                "background purge: searching for masks.in.PID files, "
                "current file = \"%s\", dirn = \"%s\", dp->d_name = \"%s\"",
                full_path, dirn, dp->d_name);

        /** Skip, if '.' and '..' */
        if ((dp->d_reclen >= 1) && (dp->d_name[0] == '.')) {
            continue;
        }

        if ((dp->d_reclen >= 2) && (dp->d_name[0] == '.') &&
                (dp->d_name[1] == '.'))
        {
            continue;
        }

        if ((dp->d_reclen > (sizeof(MASKS_IN) - 1)) &&
                (ngx_strncmp(dp->d_name, MASKS_IN,
                    sizeof(MASKS_IN) - 1) == 0))
        {
            rc = NGX_OK;
        }

        if (rc == NGX_DECLINED) {
            continue;
        }

        /**
         * Skip not files and files w/o permissions
         */
        if (!is_regular_file(full_path)) {
            continue;
        }

        pid = ngx_masks_storage_get_pid(full_path);
        ngx_log_error(NGX_LOG_INFO, m->log_, 0,
                "background purge: found a masks file = \"%s\" pid=%d",
                full_path, pid);
        ngx_snprintf(rename_path, sizeof(rename_path),
            "%s.%d%Z", m->purger_filename_, pid);
        rc = (ngx_int_t) rename((char *) full_path, (char *) rename_path);
        if (rc == -1) {
            ngx_log_error(NGX_LOG_EMERG, m->log_, ngx_errno,
                "background purge: can't rename \"%s\" to \"%s\"",
                full_path, rename_path);
            closedir(dirp);
            goto error;
        }

        rc = ngx_masks_storage_read_purger_queue(m, rename_path);
        if (rc != NGX_OK) {
            closedir(dirp);
            goto error;
        }
        cnt++;
    }

    closedir(dirp);

    rc = NGX_DECLINED;
    if (cnt > 0) {
        rc = NGX_OK;
    }
    else if (cnt == 0) {
        ngx_masks_storage_purger_queue_free(m, 0);
    }
    return rc;

error:
    ngx_masks_storage_purger_queue_free(m, 0);
    return NGX_ERROR;
}

ngx_msec_t
ngx_masks_storage_purger_sleep(void *ms)
{
    ngx_masks_storage_t *m = (ngx_masks_storage_t *) ms;
    if (!m || m->background_purger_sleep_ == 0) {
        return MASKS_STORAGE_PURGER_SLEEP_DEFAULT;
    }
    return m->background_purger_sleep_;
}
/** }}} */

#else /* NGX_HTTP_CACHE */

static char *ngx_masks_storage_not_supported(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_masks_storage_commands[] = {

    { ngx_string("masks_storage"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_masks_storage_not_supported,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("foreground_purge"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIC_CONF|NGX_CONF_TAKE1,
      ngx_masks_storage_not_supported,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_masks_storage_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_masks_storage_module = {
    NGX_MODULE_V1,
    &ngx_masks_storage_module_ctx,      /* module context */
    ngx_masks_storage_commands,         /* module directives */
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

static char *
ngx_masks_storage_not_supported(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf)
{
    (void) cmd, (void) conf;

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "masks_storage, foreground_purge, background_purge "
            "are not support with \"--without-http-cache\"");

    return NGX_CONF_ERROR;
}

#endif /* NGX_HTTP_CACHE */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
