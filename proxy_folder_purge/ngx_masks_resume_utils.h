
/*
 * (C)
 */

#ifndef NGX_MASKS_RESUME_UTILS_H
#define NGX_MASKS_RESUME_UTILS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_masks_storage.h"

/* Change this constant each time you introduce a change so you would
 * like to discard any existing checkpoints.
 * This is a part of SHA1 checksum of masks list */
#define NGX_MASKS_CKPOINT_MAGIC "ngx_masks_v0"

/** This structure holds resumal state of background purger fs walker. */
typedef struct {
    /** Element of ngx_cycle_t being processed. NUL-terminated. */
    ngx_str_t cycle_path;
    /** Checkpoint inside specified path. NUL-terminated. */
    ngx_str_t path_checkpoint;
    /** Filename of the state */
    const char *state_fname;
    /** Temporary file */
    const char *state_tmpname;
    /** Checksum of the masks list (see ngx_masks_storage_t::masks_sha1) */
    u_char checksum[20];
} ngx_masks_checkpoint_t;

/** Save checkpoint state to disk.
 *
 * @param ck checkpoint_t that will be saved
 */
void ngx_masks_save_checkpoint(ngx_masks_checkpoint_t *ck);

/** Extract "domain" part from path.
 * This works by extracting last path element and then removing
 * optional suffix "-splitted" from it
 *
 * @param path
 *
 * @return domain string pointing inside path */
ngx_str_t ngx_masks_get_domain_from_path(ngx_str_t *path);

/** Restore checkpoint state from file.
 *
 * @param cksum checksum that is matched against one in the file */
ngx_masks_checkpoint_t* ngx_masks_load_checkpoint(ngx_str_t *masks_dir,
        ngx_pool_t *pool, u_char cksum[20]);

/** Prepare sorted and normalized list of paths filtered by masks.
 * This function also modifies checkpoint->path_checkpoint if it detects that
 * passed roots does not contain checkpoint->cycle_path entry.
 *
 * @param ms big struct from which we're using only pool and per-domain purge queue
 * @param paths array of ngx_path_t items
 * @param checkpoint to resume operations from
 *
 * @retval NULL on error (this will be OOM error most likely)
 * @retval Empty array if there are no paths matching specified list of masks
 * @retval Non-empty sorted array of normalized paths to process */
ngx_array_t* ngx_masks_prepare_paths(ngx_masks_storage_t *ms, ngx_array_t *paths,
        ngx_masks_checkpoint_t *checkpoint);

/** Perform ngx_list_push on purge masks queue for specified domain and return
 * pointer to the newly inserted element. */
ngx_full_mask_t* ngx_masks_push_purge_mask(ngx_masks_storage_t *ms,
        ngx_str_t *domain);

/** Find purge masks queue for specified domain. */
ngx_list_t* ngx_masks_get_per_domain_purge_queue(ngx_masks_storage_t *ms,
                                                 ngx_str_t *domain);

#endif //NGINX_GCDN_NGX_MASKS_RESUME_UTILS_H
