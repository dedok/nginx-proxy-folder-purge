
/**
 * (C) BSDv2
 *
 */

#ifndef NGX_MASKS_STORAGE_BACKGROUND_H_
#define NGX_MASKS_STORAGE_BACKGROUND_H_ 1

#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>

ngx_int_t ngx_masks_storage_background_purge_init(ngx_cycle_t *cycle, void *ms,
        ngx_str_t *dirname);
ngx_msec_t ngx_masks_storage_background_purge(void *ms, ngx_str_t *dirname);

#endif /* NGX_MASKS_STORAGE_BACKGROUND_H_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
