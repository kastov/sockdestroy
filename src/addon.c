#include <node_api.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "sock_destroy.h"

#ifdef UNSUPPORTED_PLATFORM

static napi_value kill_sockets_binding(napi_env env, napi_callback_info info) {
    (void)info;
    napi_throw_error(env, "ERR_UNSUPPORTED_PLATFORM",
        "sockdestroy: This module only works on Linux (kernel >= 4.5 with CAP_NET_ADMIN)");
    return NULL;
}

static napi_value has_cap_net_admin_binding(napi_env env, napi_callback_info info) {
    (void)info;
    napi_value result;
    napi_get_boolean(env, false, &result);
    return result;
}

#else /* Linux implementation */

/* Reject a deferred promise with a string error message.
 * Falls back to rejecting with undefined if error object creation fails (deep OOM). */
static void reject_with_message(napi_env env, napi_deferred deferred, const char *msg) {
    napi_value undefined;
    napi_get_undefined(env, &undefined);
    napi_value err_msg, error;
    if (napi_create_string_utf8(env, msg, NAPI_AUTO_LENGTH, &err_msg) == napi_ok &&
        napi_create_error(env, NULL, err_msg, &error) == napi_ok) {
        napi_reject_deferred(env, deferred, error);
    } else {
        napi_reject_deferred(env, deferred, undefined);
    }
}

/* Reject with a string error message and an errno property on the error object. */
static void reject_with_errno(napi_env env, napi_deferred deferred, const char *msg, int err_code) {
    napi_value undefined;
    napi_get_undefined(env, &undefined);
    napi_value err_msg, error;
    if (napi_create_string_utf8(env, msg, NAPI_AUTO_LENGTH, &err_msg) == napi_ok &&
        napi_create_error(env, NULL, err_msg, &error) == napi_ok) {
        napi_value code_val;
        if (napi_create_int32(env, err_code, &code_val) == napi_ok) {
            napi_set_named_property(env, error, "errno", code_val);
        }
        napi_reject_deferred(env, deferred, error);
    } else {
        napi_reject_deferred(env, deferred, undefined);
    }
}

/* Async worker data */
typedef struct {
    napi_async_work work;
    napi_deferred deferred;
    char *src_ip;      /* NULL if not provided */
    char *dst_ip;      /* NULL if not provided */
    int mode;          /* KILL_MODE_OR (0) or KILL_MODE_AND (1) */
    kill_result_t result;
} kill_work_t;

/* Execute in worker thread — no N-API calls allowed here */
static void kill_execute(napi_env env, void *data) {
    (void)env; /* unused */
    kill_work_t *w = (kill_work_t *)data;
    kill_sockets(w->src_ip, w->dst_ip, w->mode, &w->result);
}

/* Complete in main thread — resolve/reject the promise */
static void kill_complete(napi_env env, napi_status status, void *data) {
    kill_work_t *w = (kill_work_t *)data;

    if (status != napi_ok) {
        const char *msg = (status == napi_cancelled)
            ? "Operation cancelled"
            : "Async operation failed";
        reject_with_message(env, w->deferred, msg);
    } else if (w->result.error_code != 0) {
        reject_with_errno(env, w->deferred, w->result.error_msg, w->result.error_code);
    } else {
        napi_value result_obj;
        if (napi_create_object(env, &result_obj) == napi_ok) {
            napi_value killed_val, found_val, fde_val;
            bool props_ok =
                napi_create_int32(env, w->result.killed, &killed_val) == napi_ok &&
                napi_set_named_property(env, result_obj, "killed", killed_val) == napi_ok &&
                napi_create_int32(env, w->result.found, &found_val) == napi_ok &&
                napi_set_named_property(env, result_obj, "found", found_val) == napi_ok &&
                napi_create_int32(env, w->result.first_destroy_errno, &fde_val) == napi_ok &&
                napi_set_named_property(env, result_obj, "destroyErrno", fde_val) == napi_ok;

            if (props_ok) {
                napi_resolve_deferred(env, w->deferred, result_obj);
            } else {
                /* Partial object — reject with error rather than resolve with incomplete data */
                reject_with_message(env, w->deferred, "Failed to set result properties");
            }
        } else {
            /* OOM: reject rather than resolve with undefined (resolve would crash callers
               who destructure { killed, found } from the result) */
            reject_with_message(env, w->deferred, "Failed to create result object");
        }
    }

    /* Cleanup */
    napi_delete_async_work(env, w->work);
    free(w->src_ip);
    free(w->dst_ip);
    free(w);
}

/* Extract an IP string property from a NAPI object.
 * Returns: 0=absent/null, 1=found and allocated in *out_ip, -1=type error, -2=OOM.
 * On -1 or -2, a NAPI exception is thrown; caller must goto cleanup. */
static int extract_ip_string(napi_env env, napi_value obj, const char *key, char **out_ip) {
    bool has_key = false;
    napi_has_named_property(env, obj, key, &has_key);
    if (!has_key) return 0;

    napi_value val;
    napi_get_named_property(env, obj, key, &val);
    napi_valuetype type = napi_undefined;
    napi_typeof(env, val, &type);

    if (type == napi_string) {
        size_t len;
        napi_get_value_string_utf8(env, val, NULL, 0, &len);
        *out_ip = (char *)malloc(len + 1);
        if (!*out_ip) {
            char msg[64];
            snprintf(msg, sizeof(msg), "Failed to allocate memory for %s", key);
            napi_throw_error(env, NULL, msg);
            return -2;
        }
        napi_get_value_string_utf8(env, val, *out_ip, len + 1, NULL);
        return 1;
    }
    if (type != napi_undefined && type != napi_null) {
        char msg[48];
        snprintf(msg, sizeof(msg), "%s must be a string", key);
        napi_throw_type_error(env, NULL, msg);
        return -1;
    }
    return 0;
}

#define MODE_STR_MAXLEN 8

/* killSockets({ src?: string, dst?: string, mode?: string }) -> Promise<{ killed: number, found: number, destroyErrno: number }> */
static napi_value kill_sockets_binding(napi_env env, napi_callback_info info) {
    char *src_ip = NULL;
    char *dst_ip = NULL;
    kill_work_t *work_data = NULL;

    size_t argc = 1;
    napi_value argv[1];
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok) {
        return NULL;
    }

    if (argc < 1) {
        napi_throw_type_error(env, NULL, "Expected an object argument with src and/or dst properties");
        return NULL;
    }

    /* Check argument is object */
    napi_valuetype argtype = napi_undefined;
    napi_typeof(env, argv[0], &argtype);
    if (argtype != napi_object) {
        napi_throw_type_error(env, NULL, "Argument must be an object { src?: string, dst?: string }");
        return NULL;
    }

    /* Extract src */
    if (extract_ip_string(env, argv[0], "src", &src_ip) < 0) goto cleanup;

    /* Extract dst */
    if (extract_ip_string(env, argv[0], "dst", &dst_ip) < 0) goto cleanup;

    if (!src_ip && !dst_ip) {
        napi_throw_type_error(env, NULL, "At least one of src or dst must be provided");
        goto cleanup;
    }

    /* Extract mode (default: OR) */
    int mode = KILL_MODE_OR;
    napi_value mode_val;
    bool has_mode = false;
    napi_has_named_property(env, argv[0], "mode", &has_mode);
    if (has_mode) {
        napi_get_named_property(env, argv[0], "mode", &mode_val);
        napi_valuetype mode_type = napi_undefined;
        napi_typeof(env, mode_val, &mode_type);
        if (mode_type == napi_string) {
            char mode_str[MODE_STR_MAXLEN];
            napi_get_value_string_utf8(env, mode_val, mode_str, sizeof(mode_str), NULL);
            if (strcmp(mode_str, "and") == 0) {
                mode = KILL_MODE_AND;
            }
            /* anything else (including 'or') stays at KILL_MODE_OR */
        } else if (mode_type != napi_undefined && mode_type != napi_null) {
            napi_throw_type_error(env, NULL, "mode must be a string (\"or\" or \"and\")");
            goto cleanup;
        }
    }

    /* Create promise */
    napi_deferred deferred;
    napi_value promise;
    if (napi_create_promise(env, &deferred, &promise) != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create promise");
        goto cleanup;
    }

    /* Create async work */
    work_data = (kill_work_t *)calloc(1, sizeof(kill_work_t));
    if (!work_data) {
        reject_with_message(env, deferred, "Failed to allocate memory for async work");
        free(src_ip);
        free(dst_ip);
        return promise;
    }
    work_data->deferred = deferred;
    work_data->src_ip = src_ip;
    work_data->dst_ip = dst_ip;
    work_data->mode = mode;

    napi_value resource_name;
    napi_create_string_utf8(env, "killSockets", NAPI_AUTO_LENGTH, &resource_name);

    if (napi_create_async_work(env, NULL, resource_name, kill_execute, kill_complete, work_data, &work_data->work) != napi_ok) {
        reject_with_message(env, deferred, "Failed to create async work");
        free(src_ip);
        free(dst_ip);
        free(work_data);
        return promise;
    }

    if (napi_queue_async_work(env, work_data->work) != napi_ok) {
        napi_delete_async_work(env, work_data->work);
        reject_with_message(env, deferred, "Failed to queue async work");
        free(src_ip);
        free(dst_ip);
        free(work_data);
        return promise;
    }

    /* Success — ownership of src_ip and dst_ip transferred to work_data,
       which will be freed in kill_complete callback */
    src_ip = NULL;
    dst_ip = NULL;
    work_data = NULL;
    return promise;

/* NOTE: goto cleanup is only reachable before work_data is successfully queued.
 * Once napi_queue_async_work succeeds, kill_complete owns all resources. */
cleanup:
    free(src_ip);
    free(dst_ip);
    free(work_data);  /* NULL-safe: only reached before work_data queued */
    return NULL;
}

/* hasCapNetAdmin() -> boolean (synchronous) */
static napi_value has_cap_net_admin_binding(napi_env env, napi_callback_info info) {
    (void)info;
    int has_cap = has_cap_net_admin();
    napi_value result;
    if (napi_get_boolean(env, has_cap != 0, &result) != napi_ok)
        return NULL;
    return result;
}

#endif /* UNSUPPORTED_PLATFORM */

/* Module initialization */
static napi_value init(napi_env env, napi_value exports) {
    napi_value fn;
    if (napi_create_function(env, "killSockets", NAPI_AUTO_LENGTH, kill_sockets_binding, NULL, &fn) != napi_ok)
        return NULL;
    if (napi_set_named_property(env, exports, "killSockets", fn) != napi_ok)
        return NULL;

    napi_value cap_fn;
    if (napi_create_function(env, "hasCapNetAdmin", NAPI_AUTO_LENGTH, has_cap_net_admin_binding, NULL, &cap_fn) != napi_ok)
        return NULL;
    if (napi_set_named_property(env, exports, "hasCapNetAdmin", cap_fn) != napi_ok)
        return NULL;

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
