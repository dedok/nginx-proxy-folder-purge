
/**
 * (C)
 */

#ifndef NGX_MASKS_STORAGE_UTILS_H_
#define NGX_MASKS_STORAGE_UTILS_H_ 1


#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <nginx.h>
#include <ngx_core.h>
#include <ngx_string.h>


#if defined F_FULLFSYNC
# define fullsync(fd) fcntl((fd), F_FULLFSYNC)
#else
# define fullsync(fd) (fd)
#endif


#if ! defined(PATH_MAX)
# define PATH_MAX 4096
#endif /** PATH_MAX */


typedef struct ngx_string_list_arg {
  u_char *arg_, *end_;
} ngx_string_list_arg_t;


static inline ngx_string_list_arg_t ngx_string_list_get_next_arg_(
    u_char *it, u_char *end, u_char del);
#define ngx_string_list_get_next_arg(it, end) \
  ngx_string_list_get_next_arg_((it), (end), (u_char) ',')
static inline ngx_int_t open_append_only_file(ngx_str_t *file);
static inline ngx_int_t do_sync(ngx_int_t fd);
static inline ngx_int_t do_close(ngx_int_t fd);
static inline const u_char* get_dirname(ngx_str_t *path);
static inline ngx_int_t is_dir(u_char *path);
static inline ngx_int_t is_regular_file_(ngx_str_t *path);
static inline ngx_int_t is_regular_file(u_char *path);
static inline ssize_t file_size(ngx_int_t fd);
static inline ngx_int_t parse_path(ngx_str_t *str, ngx_str_t *path,
    ngx_str_t *rest);
static inline ngx_str_t extract_ext(ngx_str_t *ext);

static inline ngx_int_t parse_server(ngx_str_t *s, ngx_str_t *h,
        ngx_str_t *p);

static inline ngx_int_t remove_file(ngx_pool_t *pool, ngx_str_t *filename);

/** Implemetation {{{ */
static inline ngx_string_list_arg_t
ngx_string_list_get_next_arg_(u_char *it, u_char *end, u_char del)
{
    ngx_string_list_arg_t a = { .arg_ = it, .end_ = end };

    for ( ; it < end; ++it) {

        if (*it == del) {
            a.end_ = it;
            break;
        }

    }

    return a;
}


static inline ngx_int_t
open_append_only_file(ngx_str_t *file)
{
    u_char      name[PATH_MAX + 1];
    ngx_int_t   fd;

    ngx_memset(name, 0, sizeof(name));

    ngx_snprintf(name, sizeof(name) - 1, "%V", file);

    fd = open((const char * ) name,
                O_CREAT | O_WRONLY | O_APPEND | O_SYNC, 0644);

    if (fd == NGX_INVALID_FILE) {
        return NGX_INVALID_FILE;
    }

#if defined (F_NOCACHE)
    fcntl(fd, F_NOCACHE, 1);
#endif /* F_NOCACHE */

  return fd;
}


static inline ngx_int_t
do_sync(ngx_int_t fd)
{
    ngx_int_t rc;

    rc = fsync(fd);

    if (rc == -1) {
        return NGX_INVALID_FILE;
    }

    return fullsync(fd);
}


static inline ngx_int_t
do_close(ngx_int_t fd)
{
    /** XXX It can fail here, but this is OK only for
     * ngx_masks_storage.{h,c}! So, be careful */
    do_sync(fd);

    return close(fd);
}

/** XXX A 'path' should not have '/' at the end */
static inline const u_char*
get_dirname(ngx_str_t *path)
{
    static u_char dn[PATH_MAX + 1];

    if (!path || path->len == 0) {
        return (const u_char *) ".";
    }

    ngx_memset(dn, 0, sizeof(dn));

    if (path->data[path->len - 1] == '.') {
        ngx_snprintf(dn, sizeof(dn) - 1, "%V", path);
    }
    else {
        ngx_snprintf(dn, sizeof(dn) - 1, "%V.", path);
    }

    return &dn[0];
}


static inline ngx_int_t
is_dir(u_char *path)
{
    struct stat path_stat;

    if ((access((const char *) path, F_OK) == -1) ||
            (stat((const char *) path, &path_stat) == -1))
    {
        return 0;
    }

    return S_ISDIR(path_stat.st_mode);
}


static inline ngx_int_t
is_regular_file_(ngx_str_t *path)
{
    struct stat path_stat;

    if ((access((const char *) path->data, F_OK) == -1) ||
            (stat((const char *) path->data, &path_stat) == -1))
    {
        return 0;
    }

    return S_ISREG(path_stat.st_mode);
}


static inline ngx_int_t
is_regular_file(u_char *path)
{
    ngx_str_t path_ = { .data = path,
                        .len = ngx_strlen(path) };
    return is_regular_file_(&path_);
}


static inline ssize_t
file_size(ngx_int_t fd)
{
    struct stat st;
    if (fstat(fd, &st) == -1) {
        return -1;
    }
    return (ssize_t) st.st_size;
}


static inline ngx_int_t
parse_path(ngx_str_t *str, ngx_str_t *path, ngx_str_t *rest)
{
    /** XXX
     * rest & path have to have some values, or something will failed
     */
    path->data = str->data;
    path->len = str->len;

    ngx_str_set(rest, "");

    /** a folder can't have the rest */
    if ((path->len >= (sizeof("/") - 1)) &&
            (path->data[path->len - 1] == '/'))
    {
        return NGX_DECLINED;
    }

    --path->len;

    for (; ; --path->len) {

        if (path->data[path->len] == '/') {
            ++path->len;
            rest->len = str->len - path->len;
            rest->data = &path->data[path->len];
            break;
        }

        if (path->len == 0) {
            return NGX_DECLINED;
        }
    }

    return NGX_OK;
}


static inline ngx_int_t
next_path(ngx_str_t *str, ngx_int_t cnt)
{
    cnt++;

    if (str->data[str->len - 1] == '/') {
        if (cnt == 1) {
            return cnt;
        }
        str->len--;
    }

    while (str->len > 0) {
        str->len--;
        if (str->data[str->len] == '/') {
            str->len++;
            return cnt;
        }
    }

    return cnt;
}


/** This function works only with *.EXT syntax, it cretes for working inside
  * the masks storage (ngx_masks_storage.c)
  */
static inline ngx_str_t
extract_ext(ngx_str_t *ext)
{
    ngx_str_t ret;
    u_char *p, *e;

    if (!ext) {
        goto not_found;
    }

    p = ext->data + ext->len;
    e = ext->data;

    for (ret.len = 0; p != e; --p, ++ret.len) {

        if (*p == '/') {
            goto not_found;
        }

        if (*p == '.') {
            ret.data = p;
            return ret;
        }
    }

not_found:
    ret.data = (u_char *) "";
    ret.len = 0;

    return ret;
}


static inline ngx_int_t
parse_server(ngx_str_t *s, ngx_str_t *h, ngx_str_t *p)
{
    u_char *i, *e;

    if (s->len == 0 || !s->data) {
        return NGX_ERROR;
    }

    i = s->data;
    e = s->data + s->len;

    h->data = s->data;
    h->len = 0;
    p->len = s->len;

    for (; i != e; ++i, ++h->len, --p->len) {

        if (*i == ':') {
            ++i;
            --p->len;
            p->data = i;
            break;
        }
    }

    if (h->len == 0 || !p->data) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static inline
ngx_int_t remove_file(ngx_pool_t *pool, ngx_str_t *filename)
{
    char *p;

    if (!pool || !filename || !filename->len || !filename->data) {
        return NGX_ERROR;
    }

    /** a filename may not have \0 at the end, that will break unlink(3) */
    p = (char *) ngx_palloc(pool, filename->len + 1 /** \0 */);
    if (p == NULL){
        goto error_exit;
    }

    ngx_snprintf((u_char *) p, filename->len + 1, "%V%Z", filename);

    if (unlink(p) == - 1) {
        goto error_exit;
    }

    ngx_pfree(pool, p);

    return NGX_OK;

error_exit:

    if (p) {
        ngx_pfree(pool, p);
    }
    return NGX_ERROR;
}

/** }}} */

#endif /* NGX_MASKS_STORAGE_UTILS_H_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
