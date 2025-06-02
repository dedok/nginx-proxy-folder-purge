
/**
 * (C)
 *
 * NGINX/core does not know about NGINX/http. Means this file is a hack which
 * allows use the masks storage in NGINX/core. Hence, the masks storage
 * depends on NGINX/http.
 *
 * Why we need this? The background purge is inside NGINX/core, it works there.
 */

#ifndef NGX_MASKS_STORAGE_CORE_API_H_
#define NGX_MASKS_STORAGE_CORE_API_H_ 1

#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>

ngx_int_t ngx_masks_storage_purger_is_off(void *ms);
ngx_int_t ngx_masks_storage_background_purge_init(ngx_cycle_t *cycle, void *ms,
        ngx_pool_t *pool, ngx_log_t *log, ngx_str_t *dirname);

ngx_msec_t ngx_masks_storage_background_purge(void *ms, ngx_pool_t *pool,
        ngx_log_t *log, ngx_str_t *dirname,
        ngx_cycle_t *cycle, ngx_event_t *ev);
ngx_int_t ngx_masks_storage_prepare_purger_queue(void *ms, ngx_pool_t *pool,
        ngx_log_t *log, ngx_str_t *dirname);
ngx_msec_t ngx_masks_storage_purger_sleep(void *ms);
#endif /* NGX_MASKS_STORAGE_CORE_API_H_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
