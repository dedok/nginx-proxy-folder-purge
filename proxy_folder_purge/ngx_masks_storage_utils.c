
/**
 * (C)
 */

#include <ngx_masks_storage_utils.h>

#include <sys/file.h>


#define LOCK_RETRY_INTERVAL_MS 500


/**
 * Acquire lock file of return an error
 */
ngx_int_t
ngx_masks_storage_acquire_lock_file(ngx_cycle_t *cycle,
                                    ngx_masks_storage_t *m, ngx_str_t *dirname)
{
    ngx_msec_t  start, now, till, elapsed;
    int         lock_fd;
    char        lock_path[PATH_MAX + 1];
    char        pid[32];
    ssize_t     len;

    if (m->background_purger_startup_lock_wait == 0) {
        return NGX_OK;
    }

    ngx_snprintf((u_char*) lock_path, sizeof(lock_path),
                 "%V/.lock%Z", dirname);

    lock_fd = open(lock_path, O_RDWR | O_CREAT, 0644);
    if (lock_fd == -1) {
        ngx_log_error(NGX_LOG_EMERG, m->log, ngx_errno,
                      "Unable to open/create lock file at %s", lock_path);
        return NGX_ERROR;
    }

    ngx_time_update();
    now = start = ngx_current_msec;
    till = ngx_current_msec + m->background_purger_startup_lock_wait * 1000u;

    while (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {

        now = ngx_current_msec;

        if (now >= till) {
            /*
             * Try to read pid of owning process from lock file
             */
            len = pread(lock_fd, pid, sizeof(pid) - 1, 0);
            if (len > 0) {
                pid[len] = 0;
            } else {
                strcpy(pid, "<unknown>");
            }

            close(lock_fd);

            ngx_log_error(NGX_LOG_EMERG, m->log, 0,
                          "Unable to acquire lock on file %s held by pid %s",
                          lock_path, pid);

            return NGX_ERROR;
        }

        elapsed = now + LOCK_RETRY_INTERVAL_MS < till ?
                        LOCK_RETRY_INTERVAL_MS :
                        till - now;
        usleep(elapsed * 1000u);

        ngx_process_events_and_timers(cycle);

        if (ngx_quit || ngx_terminate) {
            close(lock_fd);
            return NGX_ABORT;
        }

        now = ngx_current_msec;
    }

    /*
     * Store our pid into lock file
     */
    len = snprintf(pid, sizeof(pid), "%d", (int) getpid());
    if (write(lock_fd, pid, len) != len || ftruncate(lock_fd, len) != 0) {
        ngx_log_error(NGX_LOG_NOTICE, m->log, ngx_errno,
                      "Unable to store pid to %s (ignored)", lock_path);
    }

    /* NOTE: we don't close lock descriptor and rely on it being closed when
     *       process exits */
    elapsed = start - now;
    ngx_log_error(NGX_LOG_NOTICE, m->log, 0,
                  "Acquired lock on file %s in %u.%03us", lock_path,
                  elapsed / 1000u, elapsed % 1000u);

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

