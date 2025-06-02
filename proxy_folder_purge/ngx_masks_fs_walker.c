
/*
 * (C)
 */

#include <ngx_masks_fs_walker.h>

#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>


/** Maximum depth that walker will descend into.
 * It could be infinite in theory, but I've chosen to allocate contiguous array
 * of inode_info_t structures for recursion protection and this is the size of
 * that array. */
#define MAX_DEPTH 32

/** Size of individual allocation block for memory pool. */
#define MEM_CHUNK_SIZE 8192


/** Array of these structures is used for protection against filesystem loops */
typedef struct {
    dev_t dev;
    ino_t ino;
} inode_info_t;


/** Contiguous area of memory that is inlinely-allocated */
typedef struct mem_chunk_s {
    unsigned size;
    unsigned capacity;
    STAILQ_ENTRY(mem_chunk_s) link;
    char data[0];
} mem_chunk_t;


static void* mem_chunk_drain(mem_chunk_t *c, unsigned size);


/** List of memory chunks. Can be part of free or allocated list. */
typedef STAILQ_HEAD(, mem_chunk_s) mem_chunk_list_t;


/** Reusable "memory pool" that shares free chunks. Used to avoid fragmentation
 * for allocation lots of small dirent-like structures. */
typedef struct {
    /** Allocated chunks. Last chunk may contain some free space. */
    mem_chunk_list_t chunks;
    /** Shared free chunks list. */
    mem_chunk_list_t *free_chunks;
} mem_stripe_t;


/** Cached directory entry name.
 * Note: it could also store dirent::d_type, but we're doing stat anyways. */
typedef struct {
    /** length of the name excluding NUL character */
    unsigned char namelen;
    /** NUL-terminated inlined name */
    char name[0];
} dir_entry_t;


/** Dynamically growing sorted array of dir_entry_t items. */
typedef struct {
    dir_entry_t **elts;
    unsigned size;
    unsigned capacity;
    /** Memory pool for allocating dents */
    mem_stripe_t pool;
} dir_contents_t;


/** "Stack" frame of directory walker*/
typedef struct {
    /** raw directory handle, used for openat when traversing.
     * "owned" by dh */
    int dfd;
    /** stdlib directory handle */
    DIR *dh;
    /** Alphabetically sorted files of this directory */
    dir_contents_t contents;
    /** Next index in contents->elts */
    unsigned entry;
    /** Length of the path prefix */
    unsigned path_prefix_len;
} dir_walker_frame_t;


static void mem_stripe_init(mem_stripe_t *ms, mem_chunk_list_t *free_chunks);
static void* mem_stripe_alloc(mem_stripe_t *ms, unsigned size);
static void mem_stripe_clear(mem_stripe_t *ms);

static int de_comparator(const void *a, const void *b);

static void dir_contents_init(dir_contents_t *dc, mem_chunk_list_t *free_chunks);
static dir_entry_t* dir_contents_add(dir_contents_t *dc, struct dirent *e);
static void dir_contents_reset(dir_contents_t *dc);
static int dir_contents_load(dir_contents_t *dc, DIR *d);


/** Initialize an empty directory contents.
 *
 * @param dc an uninitialized directory contents.
 * @param free_chunks shared free list for memory pools
 */
static void
dir_contents_init(dir_contents_t *dc, mem_chunk_list_t *free_chunks)
{
    if (dc == NULL || free_chunks == NULL) {
        ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0,
                "dir_contents_init: invalid pointers");
        return;
    }

    dc->elts = NULL;
    dc->size = 0;
    dc->capacity = 0;

    mem_stripe_init(&dc->pool, free_chunks);
}


/** Push new element into directory contents.
 *
 * @param dc an initialized directory contents.
 * @param e dirent structure received from readdir call */
static dir_entry_t*
dir_contents_add(dir_contents_t *dc, struct dirent *e)
{
    dir_entry_t     *de;
    dir_entry_t     **elts;
    unsigned         capacity;
    unsigned         namelen = strlen(e->d_name);

    if (namelen >= UCHAR_MAX) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "dir_contents_add: namelen(%d) >= UCHAR_MAX",
                (int) namelen);
        return NULL;
    }

    if (dc->size == dc->capacity) {
        capacity = dc->capacity + (dc->capacity > 1 ? dc->capacity >> 1 : 4);
        elts = realloc(dc->elts, capacity * sizeof(*elts));
        if (elts == NULL) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "dir_contents_add: namelen(%d) >= UCHAR_MAX",
                (int) namelen);
            return NULL;
        }

        dc->elts = elts;
        dc->capacity = capacity;
    }


    de = mem_stripe_alloc(&dc->pool, sizeof(dir_entry_t) + namelen + 1);
    if (de == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "dir_contents_add: mem_stripe_alloc: failed");
        return NULL;
    }

    de->namelen = namelen;
    memcpy(de->name, e->d_name, namelen + 1);

    dc->elts[dc->size++] = de;

    return de;
}


/** Reset an initialized directory contents to an empty state.
 *
 * @param dc an initialized directory contents
 */
static void
dir_contents_reset(dir_contents_t *dc)
{
    dc->size = 0;
    mem_stripe_clear(&dc->pool);
}


/** Load and sort all files from a directory handle.
 *
 * @param dc and initialized (and likely empty) directory contents
 * @param d directory handle
 */
static int
dir_contents_load(dir_contents_t *dc, DIR *d)
{

    struct dirent *e;

    for (;;) {

        e = NULL;
        errno = 0;

        /* note: readdir_r is deprecated! */
        e = readdir(d);

        if (e == NULL) {

            if (errno == 0) {
                break;
            }

            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, errno,
                    "dir_contents_load: failed");

            return errno;
        }

        if (e->d_name[0] == '.'
            && (e->d_name[1] == 0 ||
                (e->d_name[1] == '.' && e->d_name[2] == 0)))
        {
            continue;
        }

        dir_contents_add(dc, e);
    }

    if (dc->size > 0) {
        qsort(dc->elts, dc->size, sizeof(dc->elts), de_comparator);
    }

    return 0;
}


int
ngx_masks_path_cmp(const void *lt, unsigned ltl, const void *rt, unsigned rtl)
{
    int cmp;

    if (ltl < rtl) {
        cmp = memcmp(lt, rt, ltl);
        return cmp != 0 ? cmp : -1;
    }

    if (ltl > rtl) {
        cmp = memcmp(lt, rt, rtl);
        return cmp != 0 ? cmp : 1;
    }

    return memcmp(lt, rt, ltl);
}


/**
 * Lexicographical comparator of tho dir_entry_t entities.
 */
static int
de_comparator(const void *a, const void *b)
{
    const dir_entry_t *lt = *(const dir_entry_t**) a,
                      *rt = *(const dir_entry_t**) b;

    return ngx_masks_path_cmp(lt->name, lt->namelen, rt->name, rt->namelen);
}


/** Prepare an empty memory pool.
 *
 * @param ms memory pool
 * @param free_chunks external free list that will be shared across multiple
 *        pools
 */
static void
mem_stripe_init(mem_stripe_t *ms, mem_chunk_list_t *free_chunks)
{
    STAILQ_INIT(&ms->chunks);
    ms->free_chunks = free_chunks;
}


/** Allocate from "memory pool". O(1) complexity, but could invoke
 * system memory allocator.
 *
 * @implNote If size is greater that last chunk's free space, that free space
 *            will not be used for subsequent allocations.
 * @implNote size can be arbitrary, but large chunks will be allocated separately
 *           making free space of the current chunk "lost"
 *
 * @param ms memory pool
 * @param size number of bytes to allocate.
 *
 * @returns pointer to allocated memory block or NULL if allocation failed. */
static void*
mem_stripe_alloc(mem_stripe_t *ms, unsigned size)
{
    unsigned     capacity;
    mem_chunk_t *c = STAILQ_FIRST(&ms->chunks);

    if (c != NULL
        && c->size + size <= c->capacity)
    {
        return mem_chunk_drain(c, size);
    }

    if (size + sizeof(mem_chunk_t) > MEM_CHUNK_SIZE) {

        capacity = sizeof(mem_chunk_t) + size;
        c = malloc(capacity);
        if (c == NULL) {
            ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0,
                    "mem_stripe_alloc: malloc failed");
            return NULL;
        }

        c->capacity = capacity;

    } else if (STAILQ_EMPTY(&ms->chunks)
               || (STAILQ_FIRST(&ms->chunks)->size + size >
                    STAILQ_FIRST(&ms->chunks)->capacity))
    {
        if (!STAILQ_EMPTY(ms->free_chunks)) {

            c = STAILQ_FIRST(ms->free_chunks);
            STAILQ_REMOVE_HEAD(ms->free_chunks, link);

        } else {

            capacity = MEM_CHUNK_SIZE;
            c = malloc(capacity);
            if (c == NULL) {
                ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0,
                        "mem_stripe_alloc: malloc failed");
                return NULL;
            }

            c->capacity = capacity;
        }
    }

    c->size = offsetof(mem_chunk_t, data);

    STAILQ_INSERT_HEAD(&ms->chunks, c, link);

    return mem_chunk_drain(c, size);
}


/** Make pool empty by moving all chunks into shared free list. O(1) */
static void
mem_stripe_clear(mem_stripe_t *ms)
{
    STAILQ_CONCAT(ms->free_chunks, &ms->chunks);
}


/** "Allocate" size bytes from chunk assuming that chunk has
 * sufficient capacity. Not for public use.
 *
 * @param c memory chain
 * @param size number of bytes to allocate.
 *
 * @returns ALWAYS SUCCEEDS! pointer to the block of exactly size bytes. */
static void*
mem_chunk_drain(mem_chunk_t *c, unsigned size)
{
    void *ptr;

    ptr = c->data + c->size - offsetof(mem_chunk_t, data);
    c->size += size;

    return ptr;
}


/** Deallocate whole freelist */
static void
walker_cleanup(dir_walker_frame_t *stack, unsigned stack_sz,
               mem_chunk_list_t *free_list)
{
    unsigned         i;
    mem_chunk_t     *c;

    for (i = 0; i < stack_sz; i++) {
        dir_contents_reset(&stack[i].contents);
        free(stack[i].contents.elts);

        if (stack[i].dh != NULL) {
            closedir(stack[i].dh);
        }
    }

    while (!STAILQ_EMPTY(free_list)) {
        c = STAILQ_FIRST(free_list);
        STAILQ_REMOVE_HEAD(free_list, link);
        free(c);
    }
}


static const char*
skip_to_checkpoint(const char *checkpoint, dir_walker_frame_t *top)
{
    int          cmp, not_found;
    dir_entry_t *e;
    unsigned     l, h, cl, m;

    for (cl = 0; checkpoint[cl] != '/' && checkpoint[cl] != 0; cl++) {}

    /*
     * use binary search to look for checkpoint
     */
    l = top->entry;
    h = top->contents.size;
    cmp = 0;
    not_found = 1;

    while (l < h) {

        m = l + ((h - l) >> 1);
        not_found = 0;

        e = top->contents.elts[m];
        cmp = ngx_masks_path_cmp(e->name, e->namelen, checkpoint, cl);

        if (cmp < 0) {
            l = m + 1;
        } else if (cmp > 0) {
            h = m;
        } else {
            l = m;
            break;
        }
    }

    if (not_found == 1) {
        return NULL;
    }

    if (l >= top->contents.size || cmp > 0) {
        checkpoint = NULL;

    } else if (cmp == 0) {

        checkpoint += cl;

        /* skip path separator */
        if (*checkpoint == '/') {
            checkpoint++;
        }

        /* if last checkpoint path element matches current entry, that means
             * current entry had been fully processed, so we need to advance */
        if (*checkpoint == 0) {
            l++;
        }
    }

    top->entry = l;

    return checkpoint;
}


ngx_int_t
ngx_masks_walk_fs(const char *dirp, const char *checkpoint,
                  ngx_masks_fs_walker_file_pt on_file,
                  void *on_file_ctx,
                  ngx_masks_fs_walker_state_pt on_checkpoint,
                  void *on_checkpoint_ctx)
{
    int                     saved_errno;
    char                    path_buf[PATH_MAX];
    unsigned                i, p_start;
    unsigned                depth = 0;
    time_t                  last_checkpoint, ts;

    /* to keep track of the current hierarchy to avoid loops */
    inode_info_t            dinfo[MAX_DEPTH];
    dir_walker_frame_t      stack[MAX_DEPTH], *top = stack;
    mem_chunk_list_t        free_list;
    dir_entry_t            *e;

    /* Useful information about current entry */
    ngx_masks_fs_walker_ctx entry;

    STAILQ_INIT(&free_list);
    for (i = 0; i < MAX_DEPTH; i++) {
        dir_contents_init(&stack[i].contents, &free_list);
        stack[i].dh = NULL;
    }

    p_start = strlen(dirp);
    if (p_start == 0
        || p_start + 1 >= sizeof(path_buf))
    {
        return NGX_ERROR;
    }

    top->dh = opendir(dirp);
    if (top->dh == NULL) {
        return NGX_ERROR;
    }

    /* Initialize top frame */
    top->dfd = dirfd(top->dh);
    top->entry = 0;
    saved_errno = dir_contents_load(&top->contents, top->dh);

    /* Save root path with trailing slashes stripped. */
    while (p_start > 0 && dirp[p_start - 1] == '/') {
        p_start--;
    }

    memcpy(path_buf, dirp, p_start);
    path_buf[p_start++] = '/';
    path_buf[p_start] = 0;
    top->path_prefix_len = p_start;

    /* Ensure that top frame is a directory */
    if (fstat(top->dfd, &entry.info) != 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                "ngx_masks_walk_fs: fstat() failed at %s", 
                path_buf);
        goto errno_exit;
    }

    dinfo[0].dev = entry.info.st_dev;
    dinfo[0].ino = entry.info.st_ino;

    /* Setup initial entry contents */
    entry.full_path = path_buf;
    entry.h_name = entry.e_name = path_buf + p_start;
    entry.cfd = top->dfd;

    last_checkpoint = time(NULL);

    for (;;) {

        if (checkpoint && *checkpoint) {
            checkpoint = skip_to_checkpoint(checkpoint, top);
        }

        if (top->entry >= top->contents.size) {
            do  {
                closedir(top->dh);
                top->dh = NULL;
                dir_contents_reset(&top->contents);
                if (top == stack) {
                    goto done;
                }

                depth--;
                top--;
            } while (top->entry >= top->contents.size);

            ts = time(NULL);

            if (ts != last_checkpoint) {
                /* Construct name of the last fully processed dir */
                path_buf[top[1].path_prefix_len] = 0;
                on_checkpoint(on_checkpoint_ctx,
                              path_buf + stack[0].path_prefix_len);
                last_checkpoint = ts;
            }

            path_buf[top->path_prefix_len] = 0;
            entry.cfd = top->dfd;
            entry.e_name = path_buf + top->path_prefix_len;
            checkpoint = NULL;
        }

        e = top->contents.elts[top->entry];
        top->entry++;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                "ngx_masks_walk_fs: fstat at(%s/%s): %s", path_buf, e->name,
                strerror(errno));

        if (fstatat(top->dfd, e->name, &entry.info, 0) != 0) {
            continue;
        }

        if (S_ISDIR(entry.info.st_mode)) {

            if (depth + 1 >= MAX_DEPTH) {
                continue;
            }

            top[1].dfd = openat(top->dfd, e->name, O_RDONLY | O_DIRECTORY);
            if (top[1].dfd == -1) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ngx_masks_walk_fs: openat(%s/%s) failed: %s",
                    path_buf, e->name, strerror(errno));
                continue;
            }

            /* Protect against recursion */
            for (i = 0; i <= depth; i++) {

                if (entry.info.st_ino == dinfo[i].ino
                        && entry.info.st_dev == dinfo[i].dev)
                {
                    break;
                }
            }

            if (i <= depth) {
                /* We get here if recursion had been detected */
                close(top[1].dfd);
                continue;
            }

            /* Load new directory contents */
            top[1].dh = fdopendir(top[1].dfd);
            if (top[1].dh == NULL) {

                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ngx_masks_walk_fs: fdopendir(%s/%s) failed: %s",
                    path_buf, e->name, strerror(errno));

                close(top[1].dfd);
                top[1].dh = NULL;
                continue;
            }

            if (dir_contents_load(&top[1].contents, top[1].dh) != 0) {
                dir_contents_reset(&top[1].contents);
                closedir(top[1].dh);
                top[1].dh = NULL;
                continue;
            }

            memcpy(path_buf + top->path_prefix_len, e->name, e->namelen);
            path_buf[top->path_prefix_len + e->namelen] = '/';
            path_buf[top->path_prefix_len + e->namelen + 1] = 0;
            top[1].path_prefix_len = top->path_prefix_len + 1 + e->namelen;
            top[1].entry = 0;

            entry.cfd = top[1].dfd;
            entry.e_name = path_buf + top[1].path_prefix_len;

            top++;
            depth++;
            dinfo[depth].dev = entry.info.st_dev;
            dinfo[depth].ino = entry.info.st_ino;

        } else if (S_ISREG(entry.info.st_mode)) {

            memcpy(path_buf + top->path_prefix_len, e->name, e->namelen + 1);

            if (on_file(on_file_ctx, &entry) == NGX_ABORT) {
                goto aborted;
            }

            ts = time(NULL);
            if (ts != last_checkpoint) {
                on_checkpoint(on_checkpoint_ctx,
                              path_buf + stack[0].path_prefix_len);
                last_checkpoint = ts;
            }
        }
    }

done:
    walker_cleanup(stack, MAX_DEPTH, &free_list);
    return NGX_OK;

aborted:
    walker_cleanup(stack, MAX_DEPTH, &free_list);
    return NGX_ABORT;

errno_exit:
    /* Close all handles and release all memory while preserving errno */
    saved_errno = errno;
    walker_cleanup(stack, MAX_DEPTH, &free_list);
    errno = saved_errno;

    return NGX_ERROR;
}

