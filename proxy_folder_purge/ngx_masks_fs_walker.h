
/*
 * (C)
 */

#ifndef NGX_MASKS_FS_WALKER_H
#define NGX_MASKS_FS_WALKER_H


#include <ngx_config.h>
#include <ngx_core.h>

#include <sys/stat.h>


typedef struct {
    struct stat   info;
    /** Current directory handle (where d_name belongs to),
     *  useful for openat and friends */
    int           cfd;
    /** Full path of the current entry */
    const char   *full_path;
    /** Path of the current entry relative to tree root */
    const char   *h_name;
    /** Directory entry name (NUL-terminated) */
    const char   *e_name;
} ngx_masks_fs_walker_ctx;


/** Callback executed for each file encountered */
typedef ngx_int_t (*ngx_masks_fs_walker_file_pt)(void *data, ngx_masks_fs_walker_ctx *entry);
/** Callback that is periodically executed */
typedef void (*ngx_masks_fs_walker_state_pt)(void *data, const char *checkpoint);


/** Walk filesystem tree in a predictable fashion

 * @implNote if there's a symlink somewhere in root that points outside
 *           of it, it will be visited, but implementation itself is robust
 *           towards filesystem loops
 *
 * @param dirp hierarchy root, MUST be a directory
 * @param checkpoint checkpoint received previously from ngx_masks_fs_walker_state_pt
 * @param on_file callback executed for each regular file encountered
 * @param on_file_ctx context supplied to on_file callback
 * @param on_checkpoint callback executed once in a second to save state than
 *        can be used to resume filesystem walking
 * @param on_checkpoint_ctx context supplied to on_checkpoint
 */
ngx_int_t ngx_masks_walk_fs(const char *dirp, const char *checkpoint,
                            ngx_masks_fs_walker_file_pt on_file, void *on_file_ctx,
                            ngx_masks_fs_walker_state_pt on_checkpoint, void *on_checkpoint_ctx);


/** Lexicographical comparison.
 *
 * @retval &lt;0 if lt should be before rt
 * @retval &gt;0 if lt should be after rt
 * @retval 0 if lt equals rt
 */
int ngx_masks_path_cmp(const void *lt, unsigned ltl, const void *rt, unsigned rtl);

#endif //NGINX_GCDN_NGX_MASKS_FS_WALKER_H
