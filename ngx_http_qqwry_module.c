
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "qqwry.h"

typedef struct {
    void *data;
    ngx_int_t index;
} ngx_http_qqwry_ctx_t;

static char *ngx_http_qqwry(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_qqwry_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_command_t  ngx_http_qqwry_commands[] = {    
    { ngx_string("qqwry"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE23,
        ngx_http_qqwry,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL },
    
    ngx_null_command
};

static ngx_http_module_t  ngx_http_qqwry_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */
    
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    
    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_qqwry_module = {
    NGX_MODULE_V1,
    &ngx_http_qqwry_module_ctx,            /* module context */
    ngx_http_qqwry_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *
ngx_http_qqwry(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_log_error(NGX_LOG_ALERT, cf->cycle->log, 0, "ngx_http_qqwry");
    
    ngx_http_qqwry_ctx_t *qqwry;
    ngx_http_variable_t *var;
    ngx_str_t *value;
    ngx_str_t name;
    ngx_str_t path;
    
    qqwry = ngx_palloc(cf->pool, sizeof(ngx_http_qqwry_ctx_t));
    if (qqwry == NULL) {
        return NGX_CONF_ERROR;
    }
    
    value = cf->args->elts;
    name = value[1];
    name.len--;
    name.data++;

    if (cf->args->nelts == 4) {
        qqwry->index = ngx_http_get_variable_index(cf, &name);
        if (qqwry->index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }        
        name = value[2];
        name.len--;
        name.data++;
        
        path = value[3];        
    } else {
        qqwry->index = -1;
        path = value[2];
    }
    
    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }
    
    var->get_handler = ngx_http_qqwry_variable;
    var->data = (uintptr_t)qqwry;
    
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_qqwry_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_http_qqwry_variable");
    
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (void *)"Hello, World!";
    v->len = 10;
    
    return NGX_OK;    
}
