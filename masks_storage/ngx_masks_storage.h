
/**
 * (C)
 */

#ifndef NGX_MASKS_STORAGE_H_
#define NGX_MASKS_STORAGE_H_ 1


#include <nginx.h>
#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_http.h>

#include <ngx_masks_storage_utils.h>


#define MASKS_STORAGE_DIR     "/masks_storage/"
#define MASKS_IN              "masks.in."
#define MASKS_PURGER          "masks.purger"
#define ZONE_NAME             "__ngx_masks_storage"
#define LOG_HINT              " in masks_storage zone " ZONE_NAME
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
#define MASKS_STORAGE_MAX_PURGE_COMMAND_DELAY    3600 /*1 hour*/
#define MASKS_STORAGE_MAX_PURGE_COMMAND_AHEAD    300  /*5 mins*/

enum ngx_mask_flags {
  NGX_MASK_FLAG_COMMITED                = 1 << 0,
  NGX_MASK_FLAG_PURGE_FOLDER            = 1 << 1,
  NGX_MASK_FLAG_PURGE_FILES             = 1 << 2,
  NGX_MASK_FLAG_PURGE_FILES_WITH_EXT    = 1 << 3,
  NGX_MASK_FLAG_DELETE                  = 1 << 4,
  NGX_MASK_FLAG_INVALIDATE              = 1 << 5,
  /* not used:
  NGX_MASK_FLAG_DUMP                    = 1 << 6,
  NGX_MASK_FLAG_FLUSH                   = 1 << 7,
  */
  NGX_MASK_FLAG_RECURSIVE               = 1 << 12,
};


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
  ngx_str_t  mask_;
  /** A masks's flags */
  ngx_int_t  flags_;
  /** A start time of the purge request */
  time_t     purge_start_time_;
  /** a reference count for having multy purge */
  uint32_t   ref_count_;
} ngx_mask_t;


typedef struct {
  ngx_mask_t  mask_;
  ngx_queue_t     queue_;
} ngx_mask_queue_t;

/** A rbtree node */
typedef struct {

  /** A node, i.e. mask */
  ngx_str_node_t       sn_;

  /** A value */
  ngx_mask_queue_t mask_queue_;
} ngx_masks_rbtree_node_t;

/** The ngx_mask_t uses with shared memory rbtree only and rbtree stores
 *  domains. So, that means it will increase RAM usage, if we add a new field.
 *
 *  Hence, this structure needs for storing a mask in non-shared-memory structures
 *  (like: array, list, hash etc).
 */
typedef struct {
  /** crc32(a line content) */
  uint32_t        crc32_;
  /** a stored domain */
  ngx_str_t       domain_;
  /** a stored mask */
  ngx_mask_t  mask_;
  /** Is the mask already purged? */
  ngx_int_t       purged_:1;
} ngx_full_mask_t;

/** A rbtree node */
typedef struct {

  /** A node, i.e. domain */
  ngx_str_node_t sn_;

  /** A value */
  struct {
    /** An array of the masks for a domain */
    ngx_rbtree_t         *masks_;
    /** A reference to the tree sentinel */
    ngx_rbtree_node_t    *sentinel_;
    /** Current number of active purges (i.e. elements)*/
    size_t                len_;
    /** Max allowed purges */
    size_t                max_;
  } value_;

} ngx_domain_rbtree_node_t;


/** Red-Back tree for searching domains -> [masks] */
typedef struct {
  /** A reference to tree structure */
  ngx_rbtree_t         *rbtree_;

  /** A reference to the tree sentinel */
  ngx_rbtree_node_t    *sentinel_;

  /** Is the tree restored? */
  ngx_int_t             restoring_:1;
} ngx_masks_storage_shctx_t;


typedef struct {
  /** Settings */
  ngx_str_t                      shm_name_;
  ngx_str_t                      masks_purger_;
  size_t                         max_allowed_masks_per_domain_;

  ngx_str_t                      background_purger_server_host_;
  ngx_str_t                      background_purger_server_port_;
  ngx_uint_t                     background_purger_files_;
  ngx_msec_t                     background_purger_sleep_;
  ngx_msec_t                     background_purger_threshold_;
  ngx_int_t                      background_purger_off_;

  /** Storage */
  ngx_masks_storage_shctx_t *sh_;
  ngx_slab_pool_t               *shpool_;
  ngx_int_t                      masks_in_fd_;
  ngx_int_t                      masks_purger_fd_;
  ngx_list_t                     purger_queue_;
  u_char                         purger_filename_[PATH_MAX + 1];

  /** References */
  ngx_http_request_t            *r_;
  ngx_log_t                     *log_;
  ngx_path_t                    *path_;
  ngx_path_t                    *tmp_path_;
  ngx_pool_t                    *pool_;

  /** The bakground purger {{{ */
  ngx_flag_t                     walk_tree_failed_;

  /** stats */
  size_t                         removed_files_;
  size_t                         invalidated_files_;
  size_t                         processed_files_;
  size_t                         removed_files_with_error_;
  time_t                         start_time_;
  ngx_msec_t                     last_;
  /** }}} */
} ngx_masks_storage_t;


typedef struct {
  ngx_masks_storage_t           *masks_;
  ngx_cycle_t                   *cycle_;
  ngx_event_t                   *ev_;
} ngx_masks_storage_event_t;

/** PURGE external API {{{ */
ngx_int_t ngx_http_foreground_purge(ngx_http_request_t *r,
        ngx_http_cache_t *c, time_t now);
ngx_int_t ngx_http_folder_cache_purge(ngx_http_request_t *r);
ngx_int_t ngx_http_folder_dump(ngx_http_request_t *r);
ngx_int_t ngx_http_folder_flush(ngx_http_request_t *r);
ngx_int_t ngx_http_folder_send_dump_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_folder_send_flush_handler(ngx_http_request_t *r);
/** }}}*/

#endif /* NGX_MASKS_STORAGE_H_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
