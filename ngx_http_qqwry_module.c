
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    void *data;
    ngx_int_t index;
} ngx_http_qqwry_ctx_t;

typedef struct {
    char *var1;
    char *var2;
} ngx_http_qqwry_result_t;

static char *ngx_http_qqwry(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_qqwry_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_qqwry_query(void *data, in_addr_t ip_addr, ngx_http_qqwry_result_t *ret);

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
    
    //
    
    FILE *fd;
    size_t len;
    void *buf;

    if (!(fd = fopen((char *)path.data, "rb"))) {
        return NGX_CONF_ERROR;
    }
    
    fseek(fd, 0, SEEK_END);
    len = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    
    buf = ngx_palloc(cf->pool, len);
    if (buf == NULL) {
        fclose(fd);
        return NGX_CONF_ERROR;
    }
    
    if (len != fread(buf, 1, len, fd)) {
        fclose(fd);
        return NGX_CONF_ERROR;
    }
    
    fclose(fd);
    
    qqwry->data = buf;
    
    //
    
    return NGX_CONF_OK;
}

static in_addr_t
ngx_http_qqwry_real_addr(ngx_http_request_t *r, ngx_http_qqwry_ctx_t *qqwry)
{
    struct sockaddr_in         *sin;
    ngx_http_variable_value_t  *v;
    
    if (qqwry->index == -1) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http qqwry started: %V", &r->connection->addr_text);
        
        if (r->connection->sockaddr->sa_family != AF_INET) {
            return 0;
        }
        
        sin = (struct sockaddr_in *) r->connection->sockaddr;
        return ntohl(sin->sin_addr.s_addr);
    }
    
    v = ngx_http_get_flushed_variable(r, qqwry->index);
    
    if (v == NULL || v->not_found) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http qqwry not found");
        
        return 0;
    }
    
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http qqwry started: %v", v);
    
    return ntohl(ngx_inet_addr(v->data, v->len));
}

static in_addr_t
ngx_http_qqwry_addr(ngx_http_request_t *r, ngx_http_qqwry_ctx_t *qqwry)
{
    u_char           *p, *ip;
    size_t            len;
    in_addr_t         addr;
    ngx_uint_t        i;
    ngx_table_elt_t  *xfwd;
    
    addr = ngx_http_qqwry_real_addr(r, qqwry);
    
    xfwd = r->headers_in.x_forwarded_for;
    
    if (xfwd == NULL) {
        return addr;
    }
    
    static uint32_t proxies_mask[] = {0xff000000, 0xfff00000, 0xffff0000};
    static uint32_t proxies_addr[] = {0x0A000000, 0xAC100000, 0xC0A80000};    
    
    for (i = 0; i < 3; i++) {
        if ((addr & proxies_mask[i]) == proxies_addr[i]) {            
            len = xfwd->value.len;
            ip = xfwd->value.data;
            
            for (p = ip + len - 1; p > ip; p--) {
                if (*p == ' ' || *p == ',') {
                    p++;
                    len -= p - ip;
                    ip = p;
                    break;
                }
            }
            
            return ntohl(ngx_inet_addr(ip, len));
        }
    }
    
    return addr;
}

static ngx_int_t
ngx_http_qqwry_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_qqwry_ctx_t *qqwry = (ngx_http_qqwry_ctx_t *)data;
    
    in_addr_t ip = ngx_http_qqwry_addr(r, qqwry);
    if (ip == 0) {
        v->not_found = 1;
        return NGX_ERROR;
    }
    
    ngx_http_qqwry_result_t result;
    ngx_http_qqwry_query(qqwry->data, ip, &result);
        
    ngx_int_t len = ngx_strlen(result.var1) + ngx_strlen(result.var2);
    v->data = ngx_pnalloc(r->pool, len + 2);
    if (v->data == NULL) {
        return NGX_ERROR;
    }
    v->len = len + 1;

    char *p = (char *)v->data;
    p = stpcpy(p, result.var1);
    *p = '|';
    p++;
    stpcpy(p, result.var2);
    
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;        
    
    ngx_log_debug1(NGX_LOG_ALERT, r->connection->log, 0, "ngx_http_qqwry_variable: %v, ", v);
    
    return NGX_OK;    
}

#define qqwry_read_uint32(X) ((uint32_t)*(uint8_t *)(X) |\
                              (uint32_t)*((uint8_t *)(X)+1)<<8 |\
                              (uint32_t)*((uint8_t *)(X)+2)<<16 |\
                              (uint32_t)*((uint8_t *)(X)+3)<<24)

#define qqwry_read_uint24(X) ((uint32_t)*(uint8_t *)(X) |\
                              (uint32_t)*((uint8_t *)(X)+1)<<8 |\
                              (uint32_t)*((uint8_t *)(X)+2)<<16)

#define qqwry_read_uint8(X)  (*(uint8_t *)(X))

#define qqwry_setpos(X,Y) ((uint8_t *)(X) + (Y))

static ngx_int_t
ngx_http_qqwry_query(void *data, in_addr_t ip, ngx_http_qqwry_result_t *result) {
    uint8_t *p = data;
    result->var1 = (char *)p;
    
    uint32_t idx_first = qqwry_read_uint32(p);
    uint32_t idx_last = qqwry_read_uint32(p + 4);    
    uint32_t idx_found = idx_last;
    
    unsigned int h = (idx_last - idx_first) / 7;
    unsigned int l = 0;
    unsigned int m;
    
    while (l <= h) {
        m = (l + h) / 2;
        p = qqwry_setpos(data, idx_first + m * 7);
        if (ip < qqwry_read_uint32(p)) {
            h = m - 1;
        } else {
            p = qqwry_setpos(data, qqwry_read_uint24(p + 4));
            if (ip > qqwry_read_uint32(p)) {
                l = m + 1;
            } else {
                /* found */
                idx_found = idx_first + m * 7;
                break;
            }
        }
    }    
    
    uint32_t record_offset;
    uint32_t country_offset;
    
    char *country;
    char *area;
    
    p = qqwry_setpos(data, idx_found + 4);
    record_offset = qqwry_read_uint24(p);
    p = qqwry_setpos(data, record_offset + 4);
    uint8_t flag;    
    switch (flag = qqwry_read_uint8(p)) {
        case 0x01:
            country_offset = qqwry_read_uint24(p + 1);
            p = qqwry_setpos(data, country_offset);
            switch (flag = qqwry_read_uint8(p)) {
                case 0x02:
                    /* Country information redirected again */
                    p = qqwry_setpos(data, qqwry_read_uint24(p + 1));
                    country = (char *)(p);
                    p = qqwry_setpos(data, country_offset + 4);
                    break;
                default:
                    country = (char *)(p);
                    p += strlen(country) + 1;
                    break;
            }            
            break;
        case 0x02:
            p = qqwry_setpos(data, qqwry_read_uint24(p + 1));
            country = (char *)(p);
            /* Skip 4 bytes ip and 4 bytes country offset */
            p = qqwry_setpos(data, record_offset + 8);
            break;
        default:
            country = (char *)(p);
            p += strlen(country) + 1;
            break;
    }
    
    /* Read area information */
    switch (flag = qqwry_read_uint8(p)) {
        case 0x00:
            area = NULL;
            break;
        case 0x01:
        case 0x02:
            p = qqwry_setpos(data, qqwry_read_uint24(p + 1));
            area = (char *)(p);
            break;
        default:
            area = (char *)(p);
            break;
    }
    
    result->var1 = country;
    result->var2 = area;
    
    return NGX_OK;
}
