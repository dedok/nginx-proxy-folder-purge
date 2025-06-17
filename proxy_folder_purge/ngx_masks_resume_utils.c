
/*
 * (C)
 */

#include "ngx_masks_resume_utils.h"

#define HASH_NONFATAL_OOM 1
#include "uthash.h"
#include "ngx_masks_storage.h"
#include "ngx_masks_fs_walker.h"

#include <inttypes.h>


/**
 * This suffix is being removed from pathnames when mathing against domains
 */
#define SPLITTED_SUFFIX "-splitted"
#define CHECKPOINT_NAME "/.bg-purge.checkpoint"
#define CHECKPOINT_TMP_NAME CHECKPOINT_NAME ".tmp"

static const char xdigits[] = "0123456789abcdef";


void
ngx_masks_save_checkpoint(ngx_masks_checkpoint_t *ck)
{
    int                 fd;
    unsigned            i;
    uint32_t            crc;
    char                crc_buf[32],
                        sha1_buf[sizeof(ck->checksum) * 2 +  1];
    static const char   eol[] = "\n";
    struct iovec        v[1 + 1 + 2 + 2];
    ssize_t             size, bytes;

    fd = open(ck->state_tmpname, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ngx_masks_save_checkpoint: open (%s) failed",
                ck->state_tmpname);
        return;
    }

    for (i = 0; i < sizeof(ck->checksum); i++) {
        sha1_buf[i * 2] = xdigits[(ck->checksum[i] >> 4) & 0xf];
        sha1_buf[i * 2 + 1] = xdigits[ck->checksum[i] & 0xf];
    }

    sha1_buf[sizeof(sha1_buf) - 1] = '\n';

    v[1].iov_base = sha1_buf;
    v[1].iov_len = sizeof(sha1_buf);
    v[2].iov_base = ck->cycle_path.data;
    v[2].iov_len = ck->cycle_path.len;
    v[3].iov_base = (void*)eol;
    v[3].iov_len = sizeof(eol) - 1;
    v[4].iov_base = ck->path_checkpoint.data;
    v[4].iov_len = ck->path_checkpoint.len;
    v[5].iov_base = (void*)eol;
    v[5].iov_len = sizeof(eol) - 1;

    ngx_crc32_init(crc);

    size = 0;
    for (i = 1; i < sizeof(v) / sizeof(*v); i++) {

        if (v[i].iov_len == 0) {
            continue;
        }

        ngx_crc32_update(&crc, v[i].iov_base, v[i].iov_len);
        size += v[i].iov_len;
    }

    ngx_crc32_final(crc);

    v[0].iov_len = snprintf(crc_buf, sizeof(crc_buf), "%" PRIu32 "\n", crc);
    v[0].iov_base = crc_buf;
    size += v[0].iov_len;

    do {
        bytes = writev(fd, v, sizeof(v) / sizeof(*v));
    } while (bytes == -1 && errno == EINTR);

    close(fd);

    if (size == bytes) {

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, ngx_errno,
                "ngx_masks_save_checkpoint: saving checkpoint: %s ~ %s",
                ck->state_tmpname, ck->state_fname);

        if (rename(ck->state_tmpname, ck->state_fname) == -1) {

            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                    "ngx_masks_save_checkpoint: rename() failed; "
                    "can't save checkpoint: %s ~ %s",
                    ck->state_tmpname, ck->state_fname);
        }
    } else {

        unlink(ck->state_tmpname);

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                "ngx_masks_save_checkpoint: writev() failed; "
                "can't save checkpoint: %s ~ %s",
                ck->state_tmpname, ck->state_fname);
    }
}


/** Match human-readable 10-base crc against actual crc.
 *
 * @param readable_crc NUL-terminated string with decimal representation of crc
 * @param buf buffer for which to calculate actual crc
 * @param len length of the buffer
 *
 * @retval 0 (false) actual crc doesn't match expected
 * @retval 1 crc matches
 */
static int
check_crc(const char *readable_crc, const void *buf, unsigned len)
{
    char            *eptr;
    uint32_t         expected_crc, actual_crc;
    unsigned long    val;

    errno = 0;
    val = strtoul(readable_crc, &eptr, 10);
    if (val == ULONG_MAX && errno == ERANGE) {
        return 0; /* conversion error */
    }

    if (val > UINT32_MAX) { /* number is too big for 32-bit integer */
        return 0;
    }

    expected_crc = (uint32_t) val;
    actual_crc = ngx_crc32_long((u_char*) buf, len);

    return expected_crc == actual_crc ? 1 : 0;
}


ngx_masks_checkpoint_t*
ngx_masks_load_checkpoint(ngx_str_t *masks_dir,
                          ngx_pool_t *pool, u_char cksum[20])
{
    int                         fd;
    unsigned                    i;
    ngx_masks_checkpoint_t     *ck;
    char                       *ptr, *p, *e;
    struct stat                 st;
    char                       *eol[4];
    ssize_t                     bytes;

    ck = ngx_pcalloc(pool, sizeof(*ck));
    if (ck == NULL) {
        return NULL;
    }

    /* Store original name */
    ck->state_fname = ptr = ngx_palloc(pool,
                                masks_dir->len + sizeof(CHECKPOINT_NAME));
    if (ck->state_fname == NULL) {
        return NULL;
    }

    memcpy(ptr, masks_dir->data, masks_dir->len);
    memcpy(ptr + masks_dir->len, CHECKPOINT_NAME, sizeof(CHECKPOINT_NAME));

    /* Make temporary name */
    ck->state_tmpname = ptr = ngx_palloc(pool,
                                masks_dir->len + sizeof(CHECKPOINT_TMP_NAME));
    if (ck->state_tmpname == NULL) {
        return NULL;
    }

    memcpy(ptr, masks_dir->data, masks_dir->len);
    memcpy(ptr + masks_dir->len, CHECKPOINT_TMP_NAME,
                        sizeof(CHECKPOINT_TMP_NAME));

    /* Load checkpoint data */
    fd = open(ck->state_fname, O_RDONLY);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, ngx_errno,
                "ngx_masks_load_checkpoint: open (%s) failed "
                "probably no old checkpoint file",
                ck->state_tmpname);
        return ck;
    }

    /* Ensure fname points to a regular file */
    if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode)) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                "ngx_masks_load_checkpoint: fstat (%s) not a regular file",
                ck->state_tmpname);
        close(fd);
        return NULL;
    }

    ptr = ngx_palloc(pool, st.st_size);
    if (ptr == NULL) {
        close(fd);
        return ck;
    }

    do {
        bytes = read(fd, ptr, st.st_size);
    } while (bytes == -1 && errno == EINTR);

    close(fd);

    if (bytes != st.st_size) {
        return ck;
    }

    for (i = 0, p = ptr, e = ptr + st.st_size; p < e; p++) {

        if (*p == '\n') {
            eol[i++] = p;
            if (i >= sizeof(eol) / sizeof(*eol)) {
                break;
            }
        }
    }

    if (p >= e) {
        return ck; /* not all EOLs found */
    }

    for (i = 1; i < sizeof(eol) / sizeof(*eol); i++) {
        if (eol[i - 1] + 1 == eol[i]) {
            return ck; /* some entries are empty */
        }
    }

    /* we've found all our eols, time to checksum */
    *eol[0] = 0;
    if (check_crc(ptr, eol[0] + 1,
                eol[sizeof(eol) / sizeof(*eol) - 1] - eol[0]) == 0)
    {
        return ck;
    }

    /* make all lines NUL-terminated */
    for (i = 1; i < sizeof(eol) / sizeof(*eol); i++) {
        *eol[i] = 0;
    }

    /* validate checksum in eol[1] */
    if (eol[1] - eol[0] != sizeof(ck->checksum) * 2 + 1) {
        return ck; /* does not look like SHA1 checksum */
    }

    for (i = 0; i < sizeof(ck->checksum); i++) {
        if (xdigits[(cksum[i] >> 4) & 0xf] != eol[0][1 + i * 2]
            || xdigits[cksum[i] & 0xf] != eol[0][1 + i * 2 + 1])
        {
            return ck; /* SHA1 masks digest mismatch */
        }
    }

    ck->cycle_path.data = (u_char*) eol[1] + 1;
    ck->cycle_path.len = eol[2] - eol[1] - 1;
    ck->path_checkpoint.data = (u_char*) eol[2] + 1;
    ck->path_checkpoint.len = eol[3] - eol[2] - 1;

    memcpy(ck->checksum, cksum, sizeof(ck->checksum));

    return ck;
}


ngx_str_t
ngx_masks_get_domain_from_path(ngx_str_t *path)
{
    u_char      *p, *pe;
    ngx_str_t    domain;

    for (pe = path->data + path->len - 1;
            pe != path->data && *pe == '/'; pe--) {}

    for (p = pe; p != path->data && *p != '/'; p--) {}

    pe++;

    if (*p == '/') {
        p++;
    }

    if (p + sizeof(SPLITTED_SUFFIX) - 1 < pe
        && memcmp(pe - sizeof(SPLITTED_SUFFIX) + 1,
                    SPLITTED_SUFFIX, sizeof(SPLITTED_SUFFIX) - 1) == 0)
    {
        pe -= sizeof(SPLITTED_SUFFIX) - 1;
    }

    domain.data = p;
    domain.len = pe - p;

    return domain;
}


static int
cmp_ngx_str(const void *a, const void *b)
{
    const ngx_str_t *lt = a,
                    *rt = b;
    return ngx_masks_path_cmp(lt->data, lt->len, rt->data, rt->len);
}


/** Check if two strings are exactly equal */
static int
str_equal(ngx_str_t *a, ngx_str_t *b)
{
    return a->len == b->len
            && memcmp(a->data, b->data, a->len) == 0;
}


/* See description in header */
ngx_array_t*
ngx_masks_prepare_paths(ngx_masks_storage_t *ms, ngx_array_t *paths,
        ngx_masks_checkpoint_t *checkpoint)
{
    ngx_uint_t       i;
    ngx_array_t     *prepared_paths;
    ngx_path_t      **path;
    ngx_str_t        domain;
    unsigned         checkpoint_len;
    ngx_str_t        dir_name, *dn;

    prepared_paths = ngx_array_create(ms->temp_pool, 16, sizeof(ngx_str_t));
    if (prepared_paths == NULL) {
        goto oom;
    }

    path = paths->elts;

    checkpoint_len = checkpoint != NULL ? checkpoint->cycle_path.len : 0;

    for (i = 0; i < paths->nelts; i++) {

        if (!path[i]->manager) {
            continue;
        }

        dir_name = path[i]->name;

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                "background purge: ngx_masks_prepare_paths: try path \"%V\"",
                &path[i]->name);

        /* Ignore paths not matching any masks domain */
        domain = ngx_masks_get_domain_from_path(&dir_name);

        if (ngx_masks_get_per_domain_purge_queue(ms, &domain) == NULL) {

            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                "background purge: ngx_masks_prepare_paths: skipping. "
                "Folder not matched with purged domain \"%V\" with domain \"%V\"",
                &path[i]->name, &domain);
            continue;
        }

        /* Strip any trailing '/' */
        while (dir_name.len != 0
                && dir_name.data[dir_name.len - 1] == '/')
        {
            dir_name.len--;
        }

        /* Check if path had already been processed */
        if (checkpoint_len != 0
            && ngx_masks_path_cmp(dir_name.data, dir_name.len,
                            checkpoint->cycle_path.data, checkpoint_len) < 0)
        {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "background purge: ngx_masks_prepare_paths: skipping "
                ", already visited path = \"%V\", dir name = \"%V\"",
                &path[i]->name, &dir_name);
            continue;
        }

        dn = ngx_array_push(prepared_paths);
        if (dn == NULL) {
            goto oom;
        }

        *dn = dir_name;
    }

    /* Finally, sort the paths */
    qsort(prepared_paths->elts, prepared_paths->nelts,
            sizeof(ngx_str_t), cmp_ngx_str);

    /* Now clear checkpoint if the very first path is not equal to ck->cycle_path */
    if (checkpoint != NULL && (prepared_paths->nelts == 0
                || !str_equal(prepared_paths->elts, &checkpoint->cycle_path)))
    {
        checkpoint->path_checkpoint.len = 0;
        checkpoint->path_checkpoint.data = NULL;
    }

    return prepared_paths;

oom:
    return NULL;
}


/** Select new mask per  */
ngx_mask_row_t*
ngx_masks_push_purge_mask(ngx_masks_storage_t *ms, ngx_str_t *domain)
{
#ifdef uthash_nonfatal_oom
#   undef uthash_nonfatal_oom
#endif
#define uthash_nonfatal_oom(add) goto oom
    ngx_int_t                    rc;
    ngx_masks_purge_queue_t     *q;

    HASH_FIND(hh, ms->per_domain_purge_masks, domain->data, domain->len, q);

    if (q != NULL) {
        return ngx_list_push(&q->purge_urls);
    }

    /* This domain is encountered for the first time */
    q = ngx_palloc(ms->temp_pool, sizeof(ngx_masks_purge_queue_t));
    if (q == NULL) {
        return NULL;
    }
    q->domain.data = ngx_palloc(ms->temp_pool, domain->len + 1);
    if (q->domain.data == NULL) {
        return NULL;
    }
    /* NUL-terminated domain */
    q->domain.len = domain->len;
    ngx_memcpy(q->domain.data, domain->data, domain->len);
    q->domain.data[domain->len] = 0;

    /* Initialize list */
    rc = ngx_list_init(&q->purge_urls, ms->temp_pool, 1,
                       sizeof(ngx_mask_row_t));
    if (rc != NGX_OK) {
        return NULL;
    }

    HASH_ADD_KEYPTR(hh, ms->per_domain_purge_masks,
                    q->domain.data, q->domain.len, q);

    return ngx_list_push(&q->purge_urls);

oom:
    return NULL;
}


ngx_list_t*
ngx_masks_get_per_domain_purge_queue(ngx_masks_storage_t *ms,
                                     ngx_str_t *domain)
{
    ngx_masks_purge_queue_t *q;

    HASH_FIND(hh, ms->per_domain_purge_masks, domain->data, domain->len, q);
    if (q != NULL) {
        return &q->purge_urls;
    }

    return NULL;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
