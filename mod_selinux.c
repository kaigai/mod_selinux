/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "httpd.h"

#include "apr_signal.h"
#include "apr_strings.h"
#include "apr_thread_proc.h"
#include "ap_listen.h"
#include "ap_mpm.h"

#include "http_connection.h"
#include "http_request.h"
#include "http_log.h"
#include "http_protocol.h"

#include <unistd.h>
#include <selinux/selinux.h>
#include <selinux/context.h>

#define SELINUX_DOMAIN_MAP      1
#define SELINUX_DOMAIN_ENV      2
#define SELINUX_DOMAIN_VAL      3

typedef struct selinux_list selinux_list;
struct selinux_list
{
    selinux_list   *next;

    int             method;
    char            value[1];
};

typedef struct selinux_config selinux_config;
struct selinux_config
{
    const char     *dirname;
    selinux_list   *list;
    int             allow_caches;
};

module AP_MODULE_DECLARE_DATA selinux_module;

/*
 * do_set_domain
 *   It tries to replace the domain/range of the current context.
 */
static int
do_set_domain(security_context_t old_context, char *domain, server_rec *s)
{
    security_context_t  new_context;
    security_context_t  raw_context;
    context_t           context;
    char               *range;

    /*
     * Compute the new security context
     */
    context = context_new(old_context);
    if (!context) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                     "SELinux: context_new(\"%s\") failed",
                     old_context);
        return -1;
    }

    range = strchr(domain, ':');
    if (range)
        *range++ = '\0';

    if (domain && strcmp(domain, "*") != 0)
        context_type_set(context, domain);
    if (range  && strcmp(range, "*") != 0)
        context_range_set(context, range);

    if (range)
        *--range = ':';     /* fixup */

    new_context = context_str(context);
    if (!new_context) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                     "SELinux: context_str(\"%s:%s:%s:%s\") failed",
                     context_user_get(context),
                     context_role_get(context),
                     context_type_get(context),
                     context_range_get(context));
        context_free(context);
        return -1;
    }

    /*
     * If old_context == new_context, we don't need to do anything
     */
    if (selinux_trans_to_raw_context(new_context, &raw_context) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                     "SELinux: selinux_trans_to_raw_context(\"%s\") failed",
                     new_context);
        context_free(context);
        return -1;
    }
    context_free(context);

    if (!strcmp(old_context, raw_context)) {
        freecon(raw_context);
        return 1;
    }

    if (setcon_raw(raw_context) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                     "SELinux: setcon_raw(\"%s\") failed",
                     raw_context);
        freecon(raw_context);
        return -1;
    }

    freecon(raw_context);

    return 0;
}

/*
 * selinux_post_config
 *   allows us to drop categories on startup
 */
static const char *server_domain = NULL;

static int
selinux_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                    apr_pool_t *ptemp, server_rec *s)
{
    security_context_t  context;
    char   *domain;
    int     rc;

    if (!server_domain)
        return OK;

    if (getcon_raw(&context) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                     "SELinux: getcon_raw() failed");
        return DONE;
    }

    domain = apr_pstrdup(ptemp, server_domain);

    rc = do_set_domain(context, domain, s);
    if (rc < 0) {
        freecon(context);
        return DONE;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "SELinux: %s: %s/%s",
                 (rc == 0 ? "replace server domain"
                          : "no need to change server domain"),
                 context, server_domain);
    freecon(context);

    return OK;
}

/*
 * selinux_lookup_mapfile
 *
 *   It lookups a matched entry from the given configuration file,
 *   and returns 1 with a copied cstring, if found. Otherwise, it returns 0.
 */
static int
selinux_lookup_mapfile(request_rec *r, const char *filename, char **domain)
{
    const char *white_space = " \t\r\n";
    ap_configfile_t *filp;
    char buffer[MAX_STRING_LEN];
    apr_status_t status;
    char *user, *context, *pos;
    int lineno = 0;

    status = ap_pcfg_openfile(&filp, r->pool, filename);
    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, LOG_WARNING, status, r,
                      "Unable to open: %s", filename);
        return -1;
    }

    while (ap_cfg_getline(buffer, sizeof(buffer), filp) == 0) {
        lineno++;

        /* skip empty line */
        pos = strchr(buffer, '#');
        if (pos)
            *pos = '\0';

        user = strtok_r(buffer, white_space, &pos);
        if (!user)
            continue;
        context = strtok_r(NULL, white_space, &pos);
        if (!context || strtok_r(NULL, white_space, &pos)) {
            ap_log_rerror(APLOG_MARK, LOG_WARNING, 0, r,
                          "syntax error at %s:%d", filename, lineno);
            continue;
        }

        if (!strcmp(user, "*") ||
            (r->user && !strcmp(user, r->user)) ||
            (!r->user && !strcmp(user, "__anonymous__")))
        {
            *domain = apr_pstrdup(r->pool, context);
            ap_cfg_closefile(filp);

            return 1;
        }
    }
    /* not found */
    ap_cfg_closefile(filp);
    return 0;
}

/*
 * selinux_set_domain
 *
 *   It assigns an appropriate security context on the current
 *   working thread based on attributes of the given request.
 */
static int selinux_set_domain(request_rec *r)
{
    security_context_t  context;
    selinux_config *sconf;
    selinux_list   *entry;
    const char     *envval;
    char           *domain;
    int             rc = 0;

    sconf = ap_get_module_config(r->per_dir_config,
                                 &selinux_module);
    if (!sconf || !sconf->list)
        return 0;

    for (entry = sconf->list; !rc && entry; entry = entry->next)
    {
        switch (entry->method)
        {
        case SELINUX_DOMAIN_MAP:
            rc = selinux_lookup_mapfile(r, entry->value, &domain);
            break;

        case SELINUX_DOMAIN_ENV:
            envval = apr_table_get(r->subprocess_env, entry->value);
            if (envval) {
                domain = apr_pstrdup(r->pool, envval);
                rc = 1;
            }
            break;

        default: /* SELINUX_DOMAIN_VAL */
            domain = apr_pstrdup(r->pool, entry->value);
            rc = 1;
            break;
        }

        if (rc < 0)
            return -1;
    }

    /* no matched entry */
    if (rc == 0)
        return 0;

    if (getcon_raw(&context) < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "SELinux: getcon_raw() failed");
        return -1;
    }

    rc = do_set_domain(context, domain, r->server);
    if (rc < 0) {
        freecon(context);
        return -1;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "SELinux: %s: %s/%s (uri=%s dir=%s user=%s remote=%s)",
                  (rc == 0 ? "replace handler domain"
                           : "no need to change handler domain"),
                  context, domain,
                  r->uri, sconf->dirname, r->user,
                  r->connection->remote_ip);

    freecon(context);
    return 0;
}

/*
 * selinux_process_connection
 *
 *   It overrides the default handler (ap_process_http_connection)
 *   and launches a one-time thread to invoke the default one.
 */
static int __thread volatile am_worker = 0;

static void * APR_THREAD_FUNC
selinux_worker_handler(apr_thread_t *thread, void *data)
{
    request_rec *r = (request_rec *) data;
    int result;

    /* marks as the current context is worker thread */
    am_worker = 1;

    /* set security context */
    if (selinux_set_domain(r) < 0)
        apr_thread_exit(thread, HTTP_INTERNAL_SERVER_ERROR);

    /* invoke content handler */
    result = ap_run_handler(r);

    if (result == DECLINED)
        result = HTTP_INTERNAL_SERVER_ERROR;

    apr_thread_exit(thread, result);

    return NULL;
}

static int selinux_handler(request_rec *r)
{
    apr_threadattr_t *thread_attr;
    apr_thread_t *thread;
    apr_status_t rv, thread_rv;

    /*
     * If the hook is invoked under the worker context,
     * we simply skips this module.
     */
    if (am_worker)
        return DECLINED;

    apr_threadattr_create(&thread_attr, r->pool);
    /* 0 means PTHREAD_CREATE_JOINABLE */
    apr_threadattr_detach_set(thread_attr, 0);

    rv = apr_thread_create(&thread, thread_attr,
                           selinux_worker_handler,
                           r, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
                      "Unable to launch a one-time worker thread");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = apr_thread_join(&thread_rv, thread);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
                      "Unable to join the one-time worker thread");
        /* kill itself to clean up the thread */
        r->connection->aborted = 1;
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return thread_rv;
}

/*
 * selinux_post_read_request
 *   It disables contents caches, if not allowed explicitly.
 */
static int selinux_post_read_request(request_rec *r)
{
    selinux_config *sconf
        = ap_get_module_config(r->per_dir_config, &selinux_module);

    if (sconf && sconf->allow_caches < 1)
        r->no_cache = 1;

    return DECLINED;
}

/* ---------------------------------------
 * Apache/SELinux plus API routines
 */
static void selinux_hooks(apr_pool_t *p)
{
    if (is_selinux_enabled() < 1)
        return;

    ap_hook_post_config(selinux_post_config,
                        NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(selinux_post_read_request,
                              NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(selinux_handler,
                    NULL, NULL, APR_HOOK_REALLY_FIRST);
}

static void *selinux_create_dir(apr_pool_t *p, char *dirname)
{
    selinux_config *sconf
        = apr_pcalloc(p, sizeof(selinux_config));

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "selinux: create dir config at %s", dirname);

    sconf->dirname = apr_pstrdup(p, dirname);
    sconf->list = NULL;
	sconf->allow_caches = -1;

    return sconf;
}

static void *selinux_merge_conf(apr_pool_t *p, void *base, void *add)
{
    selinux_list *pos, *tmp, *cur = NULL;
    selinux_config *bconf = base;
    selinux_config *aconf = add;
    selinux_config *sconf
        = apr_pcalloc(p, sizeof(selinux_config));

    sconf->dirname = apr_pstrdup(p, aconf->dirname);

    if (aconf->list) {
        for (pos = aconf->list; pos; pos = pos->next) {
            tmp = apr_palloc(p, sizeof(*tmp) + strlen(pos->value));
            tmp->next = NULL;
            tmp->method = pos->method;
            strcpy(tmp->value, pos->value);

            if (!cur)
                sconf->list = tmp;
            else
                cur->next = tmp;

            cur = tmp;
        }
    }

	if (bconf->list) {
        for (pos = bconf->list; pos; pos = pos->next) {
            tmp = apr_palloc(p, sizeof(*tmp) + strlen(pos->value));
            tmp->next = NULL;
            tmp->method = pos->method;
            strcpy(tmp->value, pos->value);

            if (!cur)
                sconf->list = tmp;
            else
                cur->next = tmp;

            cur = tmp;
        }
    }

	sconf->allow_caches = (aconf->allow_caches < 0
						   ? bconf->allow_caches
						   : aconf->allow_caches);
	return sconf;
}

static const char *
set_server_domain(cmd_parms *cmd, void *mconfig, const char *v1)
{
    server_domain = apr_pstrdup(cmd->pool, v1);

    return NULL;
}

static const char *
set_method_domain(cmd_parms *cmd, void *mconfig,
                  int method, const char *v1)
{
    selinux_config *sconf = mconfig;
    selinux_list   *entry, *cur;

    entry = apr_palloc(cmd->pool, sizeof(selinux_list) + strlen(v1));
    entry->next = NULL;
    entry->method = method;
    strcpy(entry->value, v1);

    if (!sconf->list)
    {
        sconf->list = entry;
        return NULL;
    }

    for (cur = sconf->list; cur->next; cur = cur->next);

    cur->next = entry;

    return NULL;
}

static const char *
set_domain_map(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return set_method_domain(cmd, mconfig, SELINUX_DOMAIN_MAP, v1);
}

static const char *
set_domain_env(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return set_method_domain(cmd, mconfig, SELINUX_DOMAIN_ENV, v1);
}

static const char *
set_domain_val(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return set_method_domain(cmd, mconfig, SELINUX_DOMAIN_VAL, v1);
}

static const char *
set_allow_caches(cmd_parms *cmd, void *mconfig, int flag)
{
    selinux_config *sconf = mconfig;

    sconf->allow_caches = flag;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "selinuxAllowCaches = %s at '%s'",
                 flag ? "On" : "Off", sconf->dirname);
    return NULL;
}

static const command_rec selinux_cmds[] = {
    /* Global config */
    AP_INIT_TAKE1("selinuxServerDomain",
                  set_server_domain, NULL, RSRC_CONF | EXEC_ON_READ,
                  "Set domain of the daemon processes"),
    /* Per-dir config */
    AP_INIT_TAKE1("selinuxDomainMap",
                  set_domain_map, NULL, OR_OPTIONS,
                  "Set user/domain mapping file"),
    AP_INIT_TAKE1("selinuxDomainEnv",
                  set_domain_env, NULL, OR_OPTIONS,
                  "Set an environment variable to show a domain"),
    AP_INIT_TAKE1("selinuxDomainVal",
                  set_domain_val, NULL, OR_OPTIONS,
                  "Set a certain domain to be performed"),
    AP_INIT_FLAG("selinuxAllowCaches",
                 set_allow_caches, NULL, OR_OPTIONS,
                 "Allows contents caches"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA selinux_module = {
    STANDARD20_MODULE_STUFF,
    selinux_create_dir,     /* create per-directory config */
    selinux_merge_conf,     /* merge per-directory config */
    NULL,                   /* server config creator */
    NULL,                   /* server config merger */
    selinux_cmds,           /* command table */
    selinux_hooks,          /* set up other hooks */
};
