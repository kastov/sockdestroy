#ifndef SOCKDESTROY_SOCK_DESTROY_H
#define SOCKDESTROY_SOCK_DESTROY_H

#include <stdint.h>

/* Error message buffer size for kill_result_t */
#define KILL_ERROR_MSG_SIZE 256

/* Filter mode */
#define KILL_MODE_OR  0   /* Kill sockets matching src OR dst (default) */
#define KILL_MODE_AND 1   /* Kill sockets matching src AND dst */

/* Result of the kill operation */
typedef struct {
    int killed;              /* number of sockets successfully destroyed */
    int found;               /* number of sockets found matching the filter */
    int first_destroy_errno; /* first non-zero errno from SOCK_DESTROY, 0 if all succeeded or none attempted */
    int error_code;          /* 0 on success, errno on failure */
    char error_msg[KILL_ERROR_MSG_SIZE]; /* human-readable error message */
} kill_result_t;

/*
 * Kill TCP sockets matching the given filter criteria.
 *
 * @param src_ip   Source IP string (IPv4 or IPv6), or NULL to skip src filter
 * @param dst_ip   Destination IP string (IPv4 or IPv6), or NULL to skip dst filter
 * @param mode     KILL_MODE_OR (match src OR dst) or KILL_MODE_AND (match src AND dst)
 * @param result   Output result structure
 * @return 0 on success, -1 on error (check result->error_code and result->error_msg)
 */
int kill_sockets(const char *src_ip, const char *dst_ip, int mode, kill_result_t *result);

/*
 * Check if the current process has CAP_NET_ADMIN in its effective capability set.
 * Uses capget() syscall directly (no libcap dependency).
 *
 * @return 1 if CAP_NET_ADMIN is present, 0 otherwise (or on error).
 */
int has_cap_net_admin(void);

#endif /* SOCKDESTROY_SOCK_DESTROY_H */
