
/**
 * (C)
 */

#ifndef NGX_MASKS_STORAGE_UTILS_H_
#define NGX_MASKS_STORAGE_UTILS_H_ 1


#include <ngx_config.h>
#include <ngx_core.h>

#include <nginx.h>
#include <ngx_string.h>

#include <ngx_masks_storage.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>


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


static inline ngx_int_t open_append_only_file(ngx_str_t *file);
static inline const u_char* get_dirname(ngx_str_t *path);
static inline ngx_int_t is_dir(u_char *path);
static inline ngx_int_t is_regular_file(u_char *path);
static inline ngx_int_t parse_path(ngx_str_t *str, ngx_str_t *path,
    ngx_str_t *rest);

/** Implemetation {{{ */
static inline ngx_int_t
open_append_only_file(ngx_str_t *file)
{
    u_char  name[PATH_MAX + 1];
    ngx_memset(name, 0, sizeof(name));
    ngx_snprintf(name, sizeof(name) - 1, "%V", file);
    return open((const char *) name,
                O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0644);
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
    } else {
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
is_regular_file(u_char *path)
{
    struct stat path_stat;

    if (access((const char *) path, F_OK) == -1 ||
            stat((const char *) path, &path_stat) == -1)
    {
        return -1;
    }

    return S_ISREG(path_stat.st_mode);
}


static inline ngx_int_t
parse_path(ngx_str_t *str, ngx_str_t *path, ngx_str_t *rest)
{
    path->data = str->data;
    path->len = str->len;

    ngx_str_set(rest, "");

    /** a folder can't have the "rest" */
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


/** Read sorted directory contents quickly filtering out non-files if underlying
 * filesystem supports it.
 *
 * @return NULL-terminated array of (char*) NUL-terminated filenames from
 *         the directory. Basic filtering of files-only is made using
 *         struct dirent::d_type field */
char** ngx_masks_load_sorted_filenames(DIR *d, ngx_pool_t *pool);

/** Returns name of the next regular file from list of files matching specified prefix.
 *
 * @param d directory handle
 * @param names NULL-terminated array of NUL-terminated file names
 * @param prefix filename prefix to look for (not necessary NUL-terminated)
 * @param prefix_len length of the prefix
 * @oaram info optional pointer to struct stat which will be filled with file info
 *              if not NULL
 *
 * @returns next value of names pointing to the name of the regular file.
 */
char* get_regular_file_with_prefix(DIR *d, char ***names,
        const char *prefix, unsigned prefix_len, struct stat *info);

#endif /* NGX_MASKS_STORAGE_UTILS_H_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
