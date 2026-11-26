
/**
 * (C) BSD, Vas Soshnikov
 */

#include <ngx_masks_storage_utils.h>

#include <sys/file.h>


/**
 * Take the lock file of the masks storage without waiting.
 *
 * The lock makes it one background purger per masks storage, for example
 * while a new nginx and the old one are running together.
 *
 * @retval NGX_OK the lock is taken, it is held until the process exits
 * @retval NGX_BUSY another process holds the lock, m->lock_holder is its
 *         pid, or 0 when it is not known
 * @retval NGX_ERROR
 *
 * There is no lock at all when startup_lock_delay is switched off.
 */
ngx_int_t
ngx_masks_storage_try_lock_file(ngx_masks_storage_t *m)
{
    int         lock_fd, err;
    char        lock_path[PATH_MAX + 1];
    char        pid[32];
    ssize_t     len;

    if (m->background_purger_startup_lock_wait == 0) {
        return NGX_OK;
    }

    /* the name of the masks storage ends with a slash */
    ngx_snprintf((u_char *) lock_path, sizeof(lock_path),
                 "%V.lock%Z", &m->path->name);

    lock_fd = open(lock_path, O_RDWR | O_CREAT, 0644);
    if (lock_fd == -1) {
        ngx_log_error(NGX_LOG_ERR, m->log, ngx_errno,
                      "proxy_folder_purge: can't open or create the lock "
                      "file %s", lock_path);
        return NGX_ERROR;
    }

    if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        err = errno;

        m->lock_holder = 0;

        if (err == EWOULDBLOCK) {

            /* Try to read the pid of the process that holds the lock */
            len = pread(lock_fd, pid, sizeof(pid) - 1, 0);

            if (len > 0) {
                pid[len] = 0;

                m->lock_holder = ngx_atoi((u_char *) pid, len);

                if (m->lock_holder == NGX_ERROR) {
                    m->lock_holder = 0;
                }
            }

        } else {
            ngx_log_error(NGX_LOG_ERR, m->log, err,
                          "proxy_folder_purge: flock() on %s failed",
                          lock_path);
        }

        close(lock_fd);

        return err == EWOULDBLOCK ? NGX_BUSY : NGX_ERROR;
    }

    /*
     * Store our pid into the lock file
     */
    len = snprintf(pid, sizeof(pid), "%d", (int) ngx_getpid());
    if (write(lock_fd, pid, len) != len || ftruncate(lock_fd, len) != 0) {
        ngx_log_error(NGX_LOG_NOTICE, m->log, ngx_errno,
                      "proxy_folder_purge: can't store the pid in %s "
                      "(ignored)", lock_path);
    }

    /* NOTE: the descriptor is not closed on purpose: the lock is held
     *       until the process exits */
    ngx_log_error(NGX_LOG_NOTICE, m->log, 0,
                  "proxy_folder_purge: the lock %s is taken by pid %P",
                  lock_path, ngx_pid);

    return NGX_OK;
}



char*
get_regular_file_with_prefix(DIR *d, char ***names,
        const char *prefix, unsigned prefix_len, struct stat *info)
{
    int          dfd;
    struct stat  st_buf, *st;
    char        *name;

    st = info != NULL ? info : &st_buf;
    dfd = dirfd(d);

    while ((name = **names) != NULL) {
        ++*names;
        /* Don't care about length comparison because e->dname is NUL-terminated */
        if (memcmp(name, prefix, prefix_len) != 0) {
            continue;
        }

        /* Require entry to be regular file */
        if (fstatat(dfd, name, st, 0) == 0 && S_ISREG(st->st_mode)) {
            break;
        }
    }

    return name;
}


static int
names_cmp(const void *a, const void *b)
{
    return strcmp(*(const char**) a, *(const char **) b);
}


char**
ngx_masks_load_sorted_filenames(DIR *d, ngx_pool_t *pool)
{
    struct dirent  *e;
    ngx_array_t     names;
    char           **elt;
    char           *name;
    unsigned        len;


    if (ngx_array_init(&names, pool, 64, sizeof(char*)) != NGX_OK) {
        goto oom;
    }

    while ((e = readdir(d)) != NULL) {

        /* exclude special entries "." and ".." */
        if (e->d_name[0] == '.'
            && (e->d_name[1] == 0
                || (e->d_name[1] == '.' && e->d_name[2] == 0)))
        {
            continue;
        }

        switch (e->d_type) {
        case DT_REG:        /* accept regular files */
        case DT_LNK:        /* accept symlinks as they may point to regular files */
        case DT_UNKNOWN:    /* leave decision to the caller */
            break;
        default:
            continue;
        }

        elt = ngx_array_push(&names);
        if (elt == NULL) {
            goto oom;
        }
        len = strlen(e->d_name) + 1;
        name = ngx_palloc(pool, len);
        if (name == NULL) {
            goto oom;
        }
        memcpy(name, e->d_name, len);
        *elt = name;
    }

    /* Sort names */
    qsort(names.elts, names.nelts, sizeof(char*), names_cmp);

    elt = ngx_array_push(&names);
    if (elt == NULL) {
        goto oom;
    }

    *elt = NULL;
    return names.elts;

oom:
    return NULL;
}

