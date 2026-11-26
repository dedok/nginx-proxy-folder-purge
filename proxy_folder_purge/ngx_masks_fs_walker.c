
/*
 * (C) BSD, Vas Soshnikov
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

/** The state of a walk. It lives from ngx_masks_walker_start() up to
 * ngx_masks_walker_stop(), and may be kept between small portions of work. */
struct ngx_masks_walker_s {
    /** Callbacks, the arguments of ngx_masks_walker_start() */
    ngx_masks_fs_walker_file_pt        on_file;
    void                              *on_file_ctx;
    ngx_masks_fs_walker_state_pt       on_checkpoint;
    void                              *on_checkpoint_ctx;

    /** What is left of the checkpoint to skip, NULL when nothing is */
    const char                        *checkpoint;
    time_t                             last_checkpoint;

    /** Depth of the current directory and the current directory itself */
    unsigned                           depth;
    dir_walker_frame_t                *top;

    /** Length of the root path in path_buf, the trailing '/' included */
    unsigned                           path_start;

    /** Useful information about current entry */
    ngx_masks_fs_walker_ctx            entry;

    /* to keep track of the current hierarchy to avoid loops */
    inode_info_t                       dinfo[MAX_DEPTH];
    dir_walker_frame_t                 stack[MAX_DEPTH];
    mem_chunk_list_t                   free_list;
    char                               path_buf[PATH_MAX];
};


ngx_masks_walker_t *
ngx_masks_walker_start(const char *dirp, const char *checkpoint,
                       ngx_masks_fs_walker_file_pt on_file,
                       void *on_file_ctx,
                       ngx_masks_fs_walker_state_pt on_checkpoint,
                       void *on_checkpoint_ctx)
{
    unsigned              i;
    ngx_masks_walker_t   *w;

    if (dirp == NULL || on_file == NULL || on_checkpoint == NULL) {
        return NULL;
    }

    w = ngx_alloc(sizeof(ngx_masks_walker_t), ngx_cycle->log);
    if (w == NULL) {
        return NULL;
    }

    ngx_memzero(w, sizeof(ngx_masks_walker_t));

    w->on_file = on_file;
    w->on_file_ctx = on_file_ctx;
    w->on_checkpoint = on_checkpoint;
    w->on_checkpoint_ctx = on_checkpoint_ctx;

    STAILQ_INIT(&w->free_list);

    for (i = 0; i < MAX_DEPTH; i++) {
        dir_contents_init(&w->stack[i].contents, &w->free_list);
        w->stack[i].dh = NULL;
    }

    w->path_start = ngx_strlen(dirp);

    if (w->path_start == 0
        || w->path_start + 1 >= sizeof(w->path_buf))
    {
        ngx_free(w);
        return NULL;
    }

    /* Initialize top frame */
    w->top = &w->stack[0];
    w->top->entry = 0;

    w->top->dh = opendir(dirp);
    if (w->top->dh == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                "ngx_masks_walk_fs: opendir(%s) failed", dirp);
        goto failed;
    }

    w->top->dfd = dirfd(w->top->dh);

    (void) dir_contents_load(&w->top->contents, w->top->dh);

    /* Save root path with trailing slashes stripped. */
    while (w->path_start > 0 && dirp[w->path_start - 1] == '/') {
        w->path_start--;
    }

    ngx_memcpy(w->path_buf, dirp, w->path_start);
    w->path_buf[w->path_start++] = '/';
    w->path_buf[w->path_start] = 0;
    w->top->path_prefix_len = w->path_start;

    /* Ensure that top frame is a directory */
    if (fstat(w->top->dfd, &w->entry.info) != 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                "ngx_masks_walk_fs: fstat() failed at %s", w->path_buf);
        goto failed;
    }

    w->dinfo[0].dev = w->entry.info.st_dev;
    w->dinfo[0].ino = w->entry.info.st_ino;

    /* Setup initial entry contents */
    w->entry.full_path = w->path_buf;
    w->entry.h_name = w->entry.e_name = w->path_buf + w->path_start;
    w->entry.cfd = w->top->dfd;

    w->checkpoint = checkpoint;
    w->last_checkpoint = time(NULL);

    return w;

failed:

    walker_cleanup(w->stack, MAX_DEPTH, &w->free_list);
    ngx_free(w);

    return NULL;
}


ngx_int_t
ngx_masks_walker_step(ngx_masks_walker_t *w)
{
    unsigned               i;
    time_t                 ts;
    dir_entry_t           *e;
    dir_walker_frame_t    *top;

    top = w->top;

    if (w->checkpoint && *w->checkpoint) {
        w->checkpoint = skip_to_checkpoint(w->checkpoint, top);
    }

    if (top->entry >= top->contents.size) {
        do {
            closedir(top->dh);
            top->dh = NULL;
            dir_contents_reset(&top->contents);
            if (top == w->stack) {
                goto done;
            }

            w->depth--;
            top--;
        } while (top->entry >= top->contents.size);

        w->top = top;

        ts = time(NULL);

        if (ts != w->last_checkpoint) {
            /* Construct name of the last fully processed dir */
            w->path_buf[top[1].path_prefix_len] = 0;
            w->on_checkpoint(w->on_checkpoint_ctx,
                             w->path_buf + w->stack[0].path_prefix_len);
            w->last_checkpoint = ts;
        }

        w->path_buf[top->path_prefix_len] = 0;
        w->entry.cfd = top->dfd;
        w->entry.e_name = w->path_buf + top->path_prefix_len;
        w->checkpoint = NULL;
    }

    e = top->contents.elts[top->entry];
    top->entry++;

    if (fstatat(top->dfd, e->name, &w->entry.info, 0) != 0) {
        return NGX_OK;
    }

    if (S_ISDIR(w->entry.info.st_mode)) {

        if (w->depth + 1 >= MAX_DEPTH) {
            return NGX_OK;
        }

        top[1].dfd = openat(top->dfd, e->name, O_RDONLY | O_DIRECTORY);
        if (top[1].dfd == -1) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ngx_masks_walk_fs: openat(%s/%s) failed: %s",
                    w->path_buf, e->name, strerror(errno));
            return NGX_OK;
        }

        /* Protect against recursion */
        for (i = 0; i <= w->depth; i++) {

            if (w->entry.info.st_ino == w->dinfo[i].ino
                && w->entry.info.st_dev == w->dinfo[i].dev)
            {
                break;
            }
        }

        if (i <= w->depth) {
            /* We get here if recursion had been detected */
            close(top[1].dfd);
            return NGX_OK;
        }

        /* Load new directory contents */
        top[1].dh = fdopendir(top[1].dfd);
        if (top[1].dh == NULL) {

            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ngx_masks_walk_fs: fdopendir(%s/%s) failed: %s",
                    w->path_buf, e->name, strerror(errno));

            close(top[1].dfd);
            top[1].dh = NULL;
            return NGX_OK;
        }

        if (dir_contents_load(&top[1].contents, top[1].dh) != 0) {
            dir_contents_reset(&top[1].contents);
            closedir(top[1].dh);
            top[1].dh = NULL;
            return NGX_OK;
        }

        ngx_memcpy(w->path_buf + top->path_prefix_len, e->name, e->namelen);
        w->path_buf[top->path_prefix_len + e->namelen] = '/';
        w->path_buf[top->path_prefix_len + e->namelen + 1] = 0;
        top[1].path_prefix_len = top->path_prefix_len + 1 + e->namelen;
        top[1].entry = 0;

        w->entry.cfd = top[1].dfd;
        w->entry.e_name = w->path_buf + top[1].path_prefix_len;

        top++;
        w->top = top;
        w->depth++;
        w->dinfo[w->depth].dev = w->entry.info.st_dev;
        w->dinfo[w->depth].ino = w->entry.info.st_ino;

    } else if (S_ISREG(w->entry.info.st_mode)) {

        ngx_memcpy(w->path_buf + top->path_prefix_len, e->name, e->namelen + 1);

        if (w->on_file(w->on_file_ctx, &w->entry) == NGX_ABORT) {
            return NGX_ABORT;
        }

        ts = time(NULL);
        if (ts != w->last_checkpoint) {
            w->on_checkpoint(w->on_checkpoint_ctx,
                             w->path_buf + w->stack[0].path_prefix_len);
            w->last_checkpoint = ts;
        }
    }

    return NGX_OK;

done:

    return NGX_DONE;
}


void
ngx_masks_walker_stop(ngx_masks_walker_t *w)
{
    if (w == NULL) {
        return;
    }

    walker_cleanup(w->stack, MAX_DEPTH, &w->free_list);

    ngx_free(w);
}


ngx_int_t
ngx_masks_walk_fs(const char *dirp, const char *checkpoint,
                  ngx_masks_fs_walker_file_pt on_file,
                  void *on_file_ctx,
                  ngx_masks_fs_walker_state_pt on_checkpoint,
                  void *on_checkpoint_ctx)
{
    ngx_int_t              rc;
    ngx_masks_walker_t    *w;

    w = ngx_masks_walker_start(dirp, checkpoint, on_file, on_file_ctx,
                               on_checkpoint, on_checkpoint_ctx);
    if (w == NULL) {
        return NGX_ERROR;
    }

    while ((rc = ngx_masks_walker_step(w)) == NGX_OK) {
        /* void */
    }

    ngx_masks_walker_stop(w);

    return rc == NGX_DONE ? NGX_OK : rc;
}
