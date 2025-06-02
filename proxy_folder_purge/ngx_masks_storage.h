

/**
 * (C)
 */

#ifndef NGX_MASKS_STORAGE_H_
#define NGX_MASKS_STORAGE_H_ 1


#include <ngx_config.h>
#include <ngx_core.h>

#include <nginx.h>
#include <ngx_http.h>
#include <ngx_sha1.h>

#define HASH_NONFATAL_OOM 1
#include "uthash.h"


#define MASKS_STORAGE_DIR     "/masks_storage/"
#define MASKS_IN              "masks.in."
#define MASKS_PURGER          "masks.purger"
#define ZONE_NAME             "__ngx_masks_storage"
#define LOG_HINT              " in proxy_folder_purge zone " ZONE_NAME
#define MASKS_STORAGE_MAGIC   "BEEF"
#define UINT32_STR_MAX        (sizeof("1867996680") - 1)
#define UINT64_STR_MAX        (sizeof("18446744073709551615") - 1)
#define MIN_ALLOWED_MASKS     "10"
#define MIN_ALLOWED_MASKS_NUM \
    ngx_atoi((u_char *) MIN_ALLOWED_MASKS, sizeof(MIN_ALLOWED_MASKS) - 1)
/** msec 10^-3 of a second */
#define PURGER_DEFAULT_NEXT 12 * 1000 /** 12 sec */


#define MASKS_STORAGE_PURGER_FILES_DEFAULT       100
#define MASKS_STORAGE_PURGER_SLEEP_DEFAULT       50
#define MASKS_STORAGE_PURGER_THRESHOLD_DEFAULT   20
#define MASKS_STORAGE_PURGE_REF_COUNT_MAX        1024
#define MASKS_STORAGE_PURGE_REF_COUNT_MAX_STR    "1024"
#define MASKS_STORAGE_PURGER_STARTUP_LOCK_WAIT   120
#define MASKS_STORAGE_MAX_PURGE_COMMAND_DELAY    3600 /*1 hour*/
#define MASKS_STORAGE_MAX_PURGE_COMMAND_AHEAD    300  /*5 mins*/


enum {
  NGX_MASKS_STORAGE_OK              = 1000,
  NGX_MASKS_STORAGE_FAIL            = 1001,
  NGX_MASKS_STORAGE_SERVICE_DISABLE = 1002,
  NGX_MASKS_STORAGE_BAD_REQUEST     = 1003,
  NGX_MASKS_STORAGE_LIMIT_REACHED   = 1004,
  NGX_MASKS_STORAGE_DENY            = 1005
};

/** A queue value */
typedef struct {
  /** A mask */
  ngx_str_t  mask;
  /** A start time of the purge request */
  time_t     purge_start_time;
  /** a reference count for having multy purge */
  uint32_t   ref_count;
} ngx_mask_t;


typedef struct {
  ngx_mask_t      mask;
  ngx_queue_t     queue;
} ngx_mask_queue_t;


/** A rbtree node */
typedef struct {

  /** A node, i.e. mask */
  ngx_str_node_t       sn;

  /** A value */
  ngx_mask_queue_t mask_queue;
} ngx_masks_rbtree_node_t;


/** The ngx_mask_t uses with shared memory rbtree only and rbtree stores
 *  domains. So, that means it will increase RAM usage, if we add a new field.
 *
 *  Hence, this structure needs for storing a mask in non-shared-memory structures
 *  (like: array, list, hash etc).
 */
typedef struct {
  /** crc32(a line content) */
  uint32_t        crc32;
  /** a stored domain */
  ngx_str_t       domain;
  /** a stored mask */
  ngx_mask_t      mask;
  /** Is the mask already purged? */
  ngx_int_t       purged:1;
} ngx_full_mask_t;


/** A rbtree node */
typedef struct {

  /** A node, i.e. domain */
  ngx_str_node_t sn;

  /** A value */
  struct {
    /** An array of the masks for a domain */
    ngx_rbtree_t         *masks;
    /** A reference to the tree sentinel */
    ngx_rbtree_node_t    *sentinel;
    /** Current number of active purges (i.e. elements)*/
    size_t                len;
    /** Max allowed purges */
    size_t                max;
  } value;

} ngx_domain_rbtree_node_t;


/** Red-Back tree for searching domains -> [masks] */
typedef struct {
  /** A reference to tree structure */
  ngx_rbtree_t         *rbtree;

  /** A reference to the tree sentinel */
  ngx_rbtree_node_t    *sentinel;

  /** Is the tree restored? */
  ngx_int_t             restoring:1;
} ngx_masks_storage_shctx_t;


/** Per-domain purge queue. */
typedef struct {
    /** Purge urls that belong to this specific domain */
    ngx_list_t                    purge_urls;
    /** Domain identifier.
     * NOTE: it could be inlined into hh, but that would make things
     * unnecessary complex */
    /** Hash table link with default name */
    ngx_str_t                     domain;
    UT_hash_handle                hh;
} ngx_masks_purge_queue_t;


typedef struct {
  /** Settings */
  ngx_str_t                      shm_name;
  ngx_str_t                      masks_purger;
  size_t                         max_allowed_masks_per_domain;

  ngx_str_t                      background_purger_server_host;
  ngx_str_t                      background_purger_server_port;
  ngx_uint_t                     background_purger_files;
  ngx_msec_t                     background_purger_sleep;
  ngx_msec_t                     background_purger_threshold;
  ngx_uint_t                     background_purger_startup_lock_wait; /* in seconds */
  ngx_int_t                      background_purger_off;

  /** Storage */
  ngx_masks_storage_shctx_t     *sh;
  ngx_slab_pool_t               *shpool;
  ngx_int_t                      masks_in_fd;
  ngx_int_t                      masks_purger_fd;

  ngx_masks_purge_queue_t        *per_domain_purge_masks;
  u_char                         purger_filename[PATH_MAX + 1];

  /** References */
  ngx_http_request_t            *r;
  ngx_log_t                     *log;
  ngx_path_t                    *path;
  ngx_path_t                    *tmp_path;
  ngx_pool_t                    *pool;

  /** The bakground purger {{{ */
  ngx_flag_t                     walk_tree_failed;

  /** stats */
  size_t                         removed_files;
  size_t                         processed_files;
  time_t                         start_time;
  ngx_msec_t                     last;
  /** }}} */

  /** State of masks checksum being accumulated */
  ngx_sha1_t                     masks_sha1_state;
  /** Checksum of loaded masks */
  u_char                         masks_sha1[20];
} ngx_masks_storage_t;


/** PURGE external API {{{ */
ngx_int_t ngx_http_foreground_purge(ngx_http_request_t *r,
        ngx_http_cache_t *c, time_t now);
ngx_int_t ngx_http_folder_cache_purge(ngx_http_request_t *r);
ngx_int_t ngx_http_folder_dump(ngx_http_request_t *r);
ngx_int_t ngx_http_folder_flush(ngx_http_request_t *r);
ngx_int_t ngx_http_folder_send_dump_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_folder_send_flush_handler(ngx_http_request_t *r);
ngx_int_t ngx_masks_storage_acquire_lock_file(ngx_cycle_t *cycle,
        ngx_masks_storage_t *m, ngx_str_t *dirname);
/** }}}*/

#endif /* NGX_MASKS_STORAGE_H_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
