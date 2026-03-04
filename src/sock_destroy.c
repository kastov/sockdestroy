#ifndef UNSUPPORTED_PLATFORM

#include "sock_destroy.h"
#include "netlink.h"
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/capability.h>

/* Receive buffer size */
#define RECV_BUF_SIZE (64 * 1024)
#define RECV_BUF_MAX  (256 * 1024)

/* Fallback TCP state IDs for environments where headers do not expose them.
 * Values follow Linux enum tcp_state in include/net/tcp_states.h. */
#ifndef TCP_ESTABLISHED
#define TCP_ESTABLISHED 1
#endif
#ifndef TCP_SYN_SENT
#define TCP_SYN_SENT 2
#endif
#ifndef TCP_SYN_RECV
#define TCP_SYN_RECV 3
#endif
#ifndef TCP_FIN_WAIT1
#define TCP_FIN_WAIT1 4
#endif
#ifndef TCP_FIN_WAIT2
#define TCP_FIN_WAIT2 5
#endif
#ifndef TCP_TIME_WAIT
#define TCP_TIME_WAIT 6
#endif
#ifndef TCP_CLOSE
#define TCP_CLOSE 7
#endif
#ifndef TCP_CLOSE_WAIT
#define TCP_CLOSE_WAIT 8
#endif
#ifndef TCP_LAST_ACK
#define TCP_LAST_ACK 9
#endif
#ifndef TCP_LISTEN
#define TCP_LISTEN 10
#endif
#ifndef TCP_CLOSING
#define TCP_CLOSING 11
#endif

#define TCP_STATE_BIT(s) (1U << (s))
/* Active connection states for user-facing "drop active connections" behavior.
 * Deliberately excludes LISTEN/CLOSE/TIME_WAIT. */
#define TCPF_ACTIVE_STATES_BASE ( \
    TCP_STATE_BIT(TCP_ESTABLISHED) | \
    TCP_STATE_BIT(TCP_SYN_SENT) | \
    TCP_STATE_BIT(TCP_SYN_RECV) | \
    TCP_STATE_BIT(TCP_FIN_WAIT1) | \
    TCP_STATE_BIT(TCP_FIN_WAIT2) | \
    TCP_STATE_BIT(TCP_CLOSE_WAIT) | \
    TCP_STATE_BIT(TCP_LAST_ACK) | \
    TCP_STATE_BIT(TCP_CLOSING))
#ifdef TCP_NEW_SYN_RECV
#define TCPF_ACTIVE_STATES (TCPF_ACTIVE_STATES_BASE | TCP_STATE_BIT(TCP_NEW_SYN_RECV))
#else
#define TCPF_ACTIVE_STATES TCPF_ACTIVE_STATES_BASE
#endif

/* Apply NETLINK_RECV_TIMEOUT_SEC as SO_RCVTIMEO on a netlink socket fd.
 * On error, fills result->error_code / error_msg and returns -1. */
static int apply_recv_timeout(int fd, const char *sock_name, kill_result_t *result) {
    struct timeval tv = { .tv_sec = NETLINK_RECV_TIMEOUT_SEC, .tv_usec = 0 };
    int so_err = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (so_err < 0) {
        int e = errno;
        result->error_code = e;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to set receive timeout on %s: %s", sock_name, strerror(e));
        return -1;
    }
    return 0;
}

/* Parse IP string, returns address family (AF_INET or AF_INET6), stores binary in dst.
   Returns 0 on failure. */
static int parse_ip(const char *ip_str, uint32_t *dst, int *prefix_len) {
    /* Try IPv4 first */
    if (inet_pton(AF_INET, ip_str, dst) == 1) {
        *prefix_len = 32;
        return AF_INET;
    }
    /* Try IPv6 */
    if (inet_pton(AF_INET6, ip_str, dst) == 1) {
        *prefix_len = 128;
        return AF_INET6;
    }
    return 0;
}

/* Build bytecode filter for src and/or dst IP.
 * Returns total bytecode length, or -1 on error.
 * The bytecode is written into `buf` which must be large enough.
 *
 * For a single condition (src or dst), the bytecode is (mode is irrelevant):
 *   [bc_op: code=S_COND/D_COND, yes=op_len, no=op_len+4] [hostcond]
 *   Total: op_len bytes
 *
 * For two conditions with KILL_MODE_OR, we use INET_DIAG_BC_JMP for OR logic:
 *   [S_COND: yes=op_len, no=op_len+4] [JMP: code=1, yes=4, no=op_len+4] [D_COND: yes=op_len, no=op_len+4]
 *   Total: 2*op_len + 4 bytes
 *
 *   How the kernel bytecode VM (inet_diag_bc_run) evaluates OR mode:
 *     - If src MATCHES: advance by S_COND.yes (op_len) -> land on JMP
 *       -> JMP always takes "no" path -> advance by op_len+4 -> past end -> len=0 -> MATCH
 *     - If src FAILS: advance by S_COND.no (op_len+4) -> skip JMP, land on D_COND
 *       - If dst MATCHES: advance by D_COND.yes (op_len) -> past end -> len=0 -> MATCH
 *       - If dst FAILS: advance by D_COND.no (op_len+4) -> past end -> len<0 -> REJECT
 *
 * For two conditions with KILL_MODE_AND, no JMP — both must match:
 *   [S_COND: yes=op_len, no=2*op_len+4] [D_COND: yes=op_len, no=op_len+4]
 *   Total: 2*op_len bytes
 *
 *   How the kernel bytecode VM (inet_diag_bc_run) evaluates AND mode:
 *     - If src MATCHES: advance by S_COND.yes (op_len) -> land on D_COND
 *       - If dst MATCHES: advance by D_COND.yes (op_len) -> past end -> len=0 -> MATCH
 *       - If dst FAILS: advance by D_COND.no (op_len+4) -> past end -> len<0 -> REJECT
 *     - If src FAILS: advance by S_COND.no (2*op_len+4) -> past end -> len<0 -> REJECT
 */
static int build_bytecode(
    int family, int mode,
    const uint32_t *src_addr, int src_prefix,
    const uint32_t *dst_addr, int dst_prefix,
    uint8_t *buf, size_t buflen
) {
    int addr_len = (family == AF_INET6) ? 16 : 4;
    int hostcond_len = sizeof(struct inet_diag_hostcond) + addr_len;
    int op_len = sizeof(struct inet_diag_bc_op) + NLMSG_ALIGN(hostcond_len);
    if (op_len > UINT8_MAX) return -1;  /* op->yes is uint8_t */

    int has_src = (src_addr != NULL);
    int has_dst = (dst_addr != NULL);
    int jmp_len = sizeof(struct inet_diag_bc_op); /* 4 bytes */

    /* Total bytecode size:
     * - Single condition: op_len
     * - Two conditions (OR): op_len + jmp_len + op_len
     * - Two conditions (AND): op_len + op_len */
    int total_bytecode;
    if (has_src && has_dst) {
        if (mode == KILL_MODE_AND)
            total_bytecode = op_len + op_len;
        else
            total_bytecode = op_len + jmp_len + op_len;
    } else {
        total_bytecode = op_len;
    }

    if ((size_t)total_bytecode > buflen)
        return -1;

    int total = 0;

    if (has_src) {
        struct inet_diag_bc_op *op = (struct inet_diag_bc_op *)(buf + total);
        op->code = INET_DIAG_BC_S_COND;
        op->yes = (uint8_t)op_len;

        if (has_dst && mode == KILL_MODE_AND) {
            /* AND mode: on fail, jump past ALL remaining bytecode to reject.
             * Remaining after S_COND: D_COND (op_len bytes).
             * no = total_bytecode - current_offset + 4 = 2*op_len - 0 + 4 = 2*op_len + 4 */
            op->no = (uint16_t)(2 * op_len + 4);
        } else {
            /* OR mode or single condition:
             * On fail: jump past this condition + JMP. If OR mode, lands on D_COND.
             * If single condition, jumps past end = reject. */
            op->no = (uint16_t)(op_len + 4);
        }

        struct inet_diag_hostcond *hc = (struct inet_diag_hostcond *)(buf + total + sizeof(struct inet_diag_bc_op));
        hc->family = (uint8_t)family;
        hc->prefix_len = (uint8_t)src_prefix;
        hc->port = -1;
        memcpy(hc->addr, src_addr, addr_len);

        total += op_len;
    }

    /* Insert JMP for OR logic when both conditions present (OR mode only) */
    if (has_src && has_dst && mode != KILL_MODE_AND) {
        struct inet_diag_bc_op *jmp = (struct inet_diag_bc_op *)(buf + total);
        jmp->code = INET_DIAG_BC_JMP;
        jmp->yes = 4;                       /* must be >= 4 to pass kernel audit */
        jmp->no = (uint16_t)(op_len + 4);   /* skip past D_COND block -> accept */
        total += jmp_len;
    }

    if (has_dst) {
        struct inet_diag_bc_op *op = (struct inet_diag_bc_op *)(buf + total);
        op->code = INET_DIAG_BC_D_COND;
        op->yes = (uint8_t)op_len;
        op->no = (uint16_t)(op_len + 4);    /* jump past end = reject */

        struct inet_diag_hostcond *hc = (struct inet_diag_hostcond *)(buf + total + sizeof(struct inet_diag_bc_op));
        hc->family = (uint8_t)family;
        hc->prefix_len = (uint8_t)dst_prefix;
        hc->port = -1;
        memcpy(hc->addr, dst_addr, addr_len);

        total += op_len;
    }

    return total;
}

/* Send SOCK_DESTROY for a single socket identified by inet_diag_msg */
static int destroy_one_socket(netlink_sock_t *kill_sock, const struct inet_diag_msg *diag_msg, int protocol) {
    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 r;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = SOCK_DESTROY_SOCK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

    req.r.sdiag_family = diag_msg->idiag_family;
    req.r.sdiag_protocol = (uint8_t)protocol;
    req.r.id = diag_msg->id;

    int err = netlink_send(kill_sock, &req.nlh);
    if (err < 0)
        return err;

    /* Read ACK/error response — match sequence number */
    char ack_buf[NETLINK_ACK_BUF_SIZE];
    ssize_t len = netlink_recv_expected(kill_sock, ack_buf, sizeof(ack_buf), req.nlh.nlmsg_seq);
    if (len < 0)
        return (int)len;

    struct nlmsghdr *ack_nlh = (struct nlmsghdr *)ack_buf;
    if (!NLMSG_OK(ack_nlh, (int)len))
        return -EBADMSG;

    if (ack_nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *nlerr = (struct nlmsgerr *)NLMSG_DATA(ack_nlh);
        if (nlerr->error == 0)
            return 0; /* Success ACK */
        if (nlerr->error == -ENOENT)
            return 1; /* Socket already gone — skip silently */
        return nlerr->error; /* e.g. -EPERM, -EOPNOTSUPP → captured in first_destroy_errno */
    }

    return 0;
}

/* Perform one dump+destroy pass for a single address family.
 * dump_sock and kill_sock are caller-owned and must already be open.
 * recv_buf and recv_buf_size are caller-owned; on EMSGSIZE the pointer
 * and size are updated (via realloc) so subsequent passes see the grown buffer.
 * family    - AF_INET or AF_INET6 used as sdiag_family in the dump request.
 *             Also used as the address family in SOCK_DESTROY requests.
 * bc_family - AF_INET or AF_INET6 used to build the bytecode filter conditions.
 *             Normally equal to `family`. Set to AF_INET when family=AF_INET6 to
 *             match IPv4-mapped sockets (::ffff:x.x.x.x) via the kernel's
 *             cross-family inet_diag_bc_run() matching logic (iproute2/ss pattern).
 * src_addr and/or dst_addr may be NULL.
 * Returns 0 on success, -1 on error (fills error_code/error_msg in *out_error_*). */
static int dump_and_destroy(
    netlink_sock_t *dump_sock, netlink_sock_t *kill_sock,
    uint8_t **recv_buf, size_t *recv_buf_size,
    int family, int bc_family, int mode,
    const uint32_t *src_addr, int src_prefix,
    const uint32_t *dst_addr, int dst_prefix,
    int *out_found, int *out_killed,
    int *out_first_destroy_errno,
    int *out_error_code, char *out_error_msg, size_t error_msg_size
) {
    *out_found = 0;
    *out_killed = 0;
    *out_first_destroy_errno = 0;

    /* Build bytecode filter */
    uint8_t bc_buf[INET_DIAG_BC_MAX_LEN];
    memset(bc_buf, 0, sizeof(bc_buf));
    int bc_len = build_bytecode(
        bc_family, mode,
        src_addr, src_prefix,
        dst_addr, dst_prefix,
        bc_buf, sizeof(bc_buf)
    );
    if (bc_len < 0) {
        *out_error_code = EINVAL;
        snprintf(out_error_msg, error_msg_size,
                 "Failed to build bytecode filter");
        return -1;
    }

    /* Build dump request: nlmsghdr + inet_diag_req_v2 + NLA(bytecode) */
    uint8_t req_buf[INET_DIAG_REQ_MAX_LEN];
    memset(req_buf, 0, sizeof(req_buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)req_buf;
    struct inet_diag_req_v2 *r = (struct inet_diag_req_v2 *)NLMSG_DATA(nlh);

    r->sdiag_family = (uint8_t)family;
    r->sdiag_protocol = IPPROTO_TCP;
    r->idiag_states = TCPF_ACTIVE_STATES;
    /* id left zeroed for dump */

    int payload_len = sizeof(struct inet_diag_req_v2);

    /* Append bytecode as NLA */
    if (bc_len > 0) {
        struct nlattr *nla = (struct nlattr *)(req_buf + NLMSG_HDRLEN + NLMSG_ALIGN(payload_len));
        nla->nla_type = INET_DIAG_REQ_BYTECODE;
        nla->nla_len = (uint16_t)(NLA_HDRLEN + bc_len);
        memcpy((uint8_t *)nla + NLA_HDRLEN, bc_buf, bc_len);
        payload_len = NLMSG_ALIGN(payload_len) + NLA_ALIGN(NLA_HDRLEN + bc_len);
    }

    nlh->nlmsg_len = (uint32_t)(NLMSG_HDRLEN + payload_len);
    nlh->nlmsg_type = SOCK_DIAG_BY_FAMILY;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

    /* Send dump request */
    int err = netlink_send(dump_sock, nlh);
    if (err < 0) {
        *out_error_code = -err;
        snprintf(out_error_msg, error_msg_size,
                 "Failed to send dump request: %s", strerror(-err));
        return -1;
    }

    /* Receive and process dump responses */
    int done = 0;
    int killed = 0;
    int found = 0;

    while (!done) {
        ssize_t len = netlink_recv(dump_sock, *recv_buf, *recv_buf_size);
        if (len == -EMSGSIZE) {
            /* Buffer too small, double it (up to 256KB) */
            size_t new_size = *recv_buf_size * 2;
            if (new_size > RECV_BUF_MAX) {
                /* Give up */
                *out_error_code = EMSGSIZE;
                snprintf(out_error_msg, error_msg_size,
                         "Netlink message too large (>256KB)");
                return -1;
            }
            uint8_t *new_buf = realloc(*recv_buf, new_size);
            if (!new_buf) {
                *out_error_code = ENOMEM;
                snprintf(out_error_msg, error_msg_size,
                         "Failed to reallocate receive buffer");
                return -1;
            }
            /* Update caller's pointer and size so subsequent passes see the grown buffer */
            *recv_buf = new_buf;
            *recv_buf_size = new_size;
            continue;  /* retry with larger buffer */
        }
        if (len < 0) {
            *out_error_code = (int)(-len);
            snprintf(out_error_msg, error_msg_size,
                     "Failed to receive dump response: %s", strerror((int)(-len)));
            return -1;
        }

        struct nlmsghdr *resp_nlh;
        /* int is safe here: recv_buf_size <= 256KB which fits in int,
           and NLMSG_OK/NLMSG_NEXT operate on int lengths. */
        int remaining = (int)len;
        for (resp_nlh = (struct nlmsghdr *)*recv_buf;
             NLMSG_OK(resp_nlh, remaining);
             resp_nlh = NLMSG_NEXT(resp_nlh, remaining)) {

            if (resp_nlh->nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }

            if (resp_nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *nlerr = (struct nlmsgerr *)NLMSG_DATA(resp_nlh);
                if (nlerr->error != 0) {
                    *out_error_code = -nlerr->error;
                    snprintf(out_error_msg, error_msg_size,
                             "Dump error: %s", strerror(-nlerr->error));
                    return -1;
                }
                continue;
            }

            if (resp_nlh->nlmsg_type != SOCK_DIAG_BY_FAMILY)
                continue;

            /* Got a socket — destroy it */
            struct inet_diag_msg *diag_msg = (struct inet_diag_msg *)NLMSG_DATA(resp_nlh);
            found++;
            int ret = destroy_one_socket(kill_sock, diag_msg, IPPROTO_TCP);
            if (ret == 0)
                killed++;
            else if (ret < 0 && *out_first_destroy_errno == 0)
                *out_first_destroy_errno = -ret;  /* capture first destroy errno (e.g. EPERM) */
            /* ret == 1: skipped (ENOENT — socket already gone). */
        }
    }

    *out_found = found;
    *out_killed = killed;
    return 0;
}

int kill_sockets(const char *src_ip, const char *dst_ip, int mode, kill_result_t *result) {
    memset(result, 0, sizeof(*result));

    if (!src_ip && !dst_ip) {
        result->error_code = EINVAL;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "At least one of src or dst must be provided");
        return -1;
    }

    /* Parse IP addresses */
    uint32_t src_addr[4] = {0}, dst_addr[4] = {0};
    int src_family = 0, dst_family = 0;
    int src_prefix = 0, dst_prefix = 0;

    if (src_ip) {
        src_family = parse_ip(src_ip, src_addr, &src_prefix);
        if (src_family == 0) {
            result->error_code = EINVAL;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Invalid source IP address: %s", src_ip);
            return -1;
        }
    }

    if (dst_ip) {
        dst_family = parse_ip(dst_ip, dst_addr, &dst_prefix);
        if (dst_family == 0) {
            result->error_code = EINVAL;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Invalid destination IP address: %s", dst_ip);
            return -1;
        }
    }

    /* AND across different address families is impossible: a TCP socket
     * belongs to exactly one AF. No socket can have a pure IPv4 src
     * and a pure IPv6 dst (or vice versa). Return immediately.
     * This check must happen BEFORE opening sockets (no resources needed). */
    if (src_family && dst_family && src_family != dst_family && mode == KILL_MODE_AND) {
        result->found = 0;
        result->killed = 0;
        return 0;
    }

    /* Open two netlink sockets once for all passes */
    netlink_sock_t dump_sock, kill_sock;

    int err = netlink_open(&dump_sock);
    if (err < 0) {
        result->error_code = -err;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to open dump netlink socket: %s", strerror(-err));
        return -1;
    }

    /* Safety net: if kernel never sends NLMSG_DONE, don't block the worker thread forever */
    if (apply_recv_timeout(dump_sock.fd, "dump socket", result) < 0) {
        netlink_close(&dump_sock);
        return -1;
    }

    err = netlink_open(&kill_sock);
    if (err < 0) {
        result->error_code = -err;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to open kill netlink socket: %s", strerror(-err));
        netlink_close(&dump_sock);
        return -1;
    }

    /* Safety net: if kernel never sends an ACK for SOCK_DESTROY, don't block forever */
    if (apply_recv_timeout(kill_sock.fd, "kill socket", result) < 0) {
        netlink_close(&dump_sock);
        netlink_close(&kill_sock);
        return -1;
    }

    /* Allocate receive buffer once; passes may grow it via realloc */
    size_t recv_buf_size = RECV_BUF_SIZE;
    uint8_t *recv_buf = malloc(recv_buf_size);
    if (!recv_buf) {
        result->error_code = ENOMEM;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to allocate receive buffer");
        netlink_close(&dump_sock);
        netlink_close(&kill_sock);
        return -1;
    }

    int total_found = 0, total_killed = 0;
    int ret_val = 0;

    /* --- Primary passes --- */

    if (src_family && dst_family && src_family != dst_family) {
        /* Mixed IPv4/IPv6 OR: two separate passes, one per family.
         * Each pass has a single condition. */
        int found1 = 0, killed1 = 0, found2 = 0, killed2 = 0;
        int fde1 = 0, fde2 = 0;

        int ret = dump_and_destroy(&dump_sock, &kill_sock, &recv_buf, &recv_buf_size,
            src_family, src_family, KILL_MODE_OR,
            src_addr, src_prefix, NULL, 0,
            &found1, &killed1, &fde1,
            &result->error_code, result->error_msg, sizeof(result->error_msg));
        if (ret < 0) {
            total_found = found1;
            total_killed = killed1;
            result->first_destroy_errno = fde1;
            ret_val = -1;
            goto cleanup;
        }

        ret = dump_and_destroy(&dump_sock, &kill_sock, &recv_buf, &recv_buf_size,
            dst_family, dst_family, KILL_MODE_OR,
            NULL, 0, dst_addr, dst_prefix,
            &found2, &killed2, &fde2,
            &result->error_code, result->error_msg, sizeof(result->error_msg));
        if (ret < 0) {
            total_found = found1 + found2;
            total_killed = killed1 + killed2;
            result->first_destroy_errno = fde1 ? fde1 : fde2;
            ret_val = -1;
            goto cleanup;
        }

        total_found = found1 + found2;
        total_killed = killed1 + killed2;
        result->first_destroy_errno = fde1 ? fde1 : fde2;
    } else {
        /* Same family (or only one address specified): single pass with mode-aware bytecode */
        int family;
        if (src_family && dst_family)
            family = src_family; /* same family */
        else if (src_family)
            family = src_family;
        else
            family = dst_family;

        int found = 0, killed = 0;
        int fde = 0;
        int ret = dump_and_destroy(&dump_sock, &kill_sock, &recv_buf, &recv_buf_size,
            family, family, mode,
            src_ip ? src_addr : NULL, src_prefix,
            dst_ip ? dst_addr : NULL, dst_prefix,
            &found, &killed, &fde,
            &result->error_code, result->error_msg, sizeof(result->error_msg));

        total_found = found;
        total_killed = killed;
        result->first_destroy_errno = fde;

        if (ret < 0) {
            ret_val = -1;
            goto cleanup;
        }
    }

    /* --- IPv4-mapped IPv6 pass (best-effort) ---
     * For any IPv4 address in the filter, do an additional AF_INET6 dump pass
     * with the SAME AF_INET bytecode condition. The kernel's inet_diag_bc_run()
     * automatically handles cross-family matching: when entry->family == AF_INET6
     * and cond->family == AF_INET, the kernel checks if the address is v4-mapped
     * (::ffff:x.x.x.x) and matches the IPv4 portion. This is the iproute2/ss pattern.
     *
     * bc_family = AF_INET tells build_bytecode to create AF_INET conditions (4-byte addr).
     * family = AF_INET6 tells the dump request to query AF_INET6 sockets. */
    int has_ipv4_src = (src_family == AF_INET);
    int has_ipv4_dst = (dst_family == AF_INET);

    if (has_ipv4_src || has_ipv4_dst) {
        int mfound = 0, mkilled = 0;
        int mfde = 0;

        int ret = dump_and_destroy(&dump_sock, &kill_sock, &recv_buf, &recv_buf_size,
            AF_INET6, AF_INET, mode,
            has_ipv4_src ? src_addr : NULL, has_ipv4_src ? src_prefix : 0,
            has_ipv4_dst ? dst_addr : NULL, has_ipv4_dst ? dst_prefix : 0,
            &mfound, &mkilled, &mfde,
            &result->error_code, result->error_msg, sizeof(result->error_msg));

        /* Always accumulate partial results, even if the pass failed mid-iteration */
        total_found += mfound;
        total_killed += mkilled;

        /* Capture mapped pass destroy errno if primary passes had none */
        if (mfde && !result->first_destroy_errno)
            result->first_destroy_errno = mfde;

        /* Best-effort: if mapped pass fails (e.g. IPv6 disabled), ignore the error.
         * Clear error state that dump_and_destroy may have written. */
        if (ret < 0) {
            result->error_code = 0;
            result->error_msg[0] = '\0';
        }
    }

cleanup:
    free(recv_buf);
    netlink_close(&dump_sock);
    netlink_close(&kill_sock);

    result->found = total_found;
    result->killed = total_killed;
    return ret_val;
}

int has_cap_net_admin(void) {
    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0, /* current process */
    };
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

    memset(data, 0, sizeof(data));

    if (syscall(SYS_capget, &hdr, data) != 0)
        return 0; /* conservative: assume no capability on failure */

    /* CAP_NET_ADMIN = 12, in data[0] (caps 0-31) */
    return !!(data[0].effective & (1u << CAP_NET_ADMIN));
}

#endif /* UNSUPPORTED_PLATFORM */
