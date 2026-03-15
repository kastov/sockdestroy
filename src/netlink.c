#ifndef UNSUPPORTED_PLATFORM

#include "netlink.h"
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/socket.h>

/* Minimum buffer size to enable the recvmmsg batch path.
 * Smaller buffers use the simpler single-message recvmsg path. */
#define NETLINK_BATCH_MIN_BUFLEN 1024

/* Single-message receive with truncation-safe peek+consume semantics. */
static ssize_t netlink_recv_single(netlink_sock_t *ns, void *buf, size_t buflen) {
    struct sockaddr_nl src;
    struct iovec iov = { .iov_base = buf, .iov_len = buflen };
    struct msghdr msg = {
        .msg_name = &src,
        .msg_namelen = sizeof(src),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    /* MSG_PEEK | MSG_TRUNC: peek at the message without consuming it.
     * MSG_TRUNC makes recvmsg return the real message length even if
     * it exceeds the buffer, so we can detect truncation safely. */
    ssize_t len;
    do {
        len = recvmsg(ns->fd, &msg, MSG_PEEK | MSG_TRUNC);
    } while (len < 0 && errno == EINTR);
    if (len < 0)
        return -errno;

    if ((size_t)len > buflen) {
        /* Message is larger than buffer — still in the kernel queue
         * (MSG_PEEK did not consume it). Caller can realloc and retry. */
        return -EMSGSIZE;
    }

    /* Buffer is large enough — consume the message */
    iov.iov_base = buf;
    iov.iov_len = buflen;
    msg.msg_namelen = sizeof(src);
    msg.msg_flags = 0;
    do {
        len = recvmsg(ns->fd, &msg, 0);
    } while (len < 0 && errno == EINTR);
    if (len < 0)
        return -errno;

    return len;
}

static ssize_t netlink_pop_batch(netlink_sock_t *ns, void *buf, size_t buflen) {
    if (ns->batch_index >= ns->batch_count)
        return 0;

    int idx = ns->batch_index;
    ssize_t len = ns->batch_lens[idx];
    if (len < 0 || (size_t)len > buflen) {
        ns->batch_count = 0;
        ns->batch_index = 0;
        return -EMSGSIZE;
    }

    memcpy(buf, ns->batch_buf + ((size_t)idx * ns->batch_buflen), (size_t)len);
    ns->batch_index++;
    if (ns->batch_index >= ns->batch_count) {
        ns->batch_count = 0;
        ns->batch_index = 0;
    }

    return len;
}

static int netlink_ensure_batch_storage(netlink_sock_t *ns, size_t buflen) {
    if (ns->batch_buf && ns->batch_buflen == buflen)
        return 0;

    if (buflen == 0 || buflen > (SIZE_MAX / NETLINK_RECV_BATCH_VLEN))
        return -ENOMEM;

    size_t total = buflen * NETLINK_RECV_BATCH_VLEN;
    uint8_t *new_buf = (uint8_t *)realloc(ns->batch_buf, total);
    if (!new_buf)
        return -ENOMEM;

    ns->batch_buf = new_buf;
    ns->batch_buflen = buflen;
    ns->batch_count = 0;
    ns->batch_index = 0;
    return 0;
}

/* Fill ns->batch_* using recvmmsg.
 * Uses a truncation-safe two-step flow:
 *  1) Peek the first datagram with recvmsg(MSG_PEEK|MSG_TRUNC) to validate size.
 *  2) Batch-consume up to VLEN datagrams with recvmmsg (no MSG_PEEK).
 * If the first datagram exceeds buflen, -EMSGSIZE is returned and the
 * datagram remains in the kernel queue for caller-side buffer resize.
 * Post-consume validation catches any later datagrams that exceed buflen.
 */
static int netlink_fill_batch(netlink_sock_t *ns, size_t buflen) {
    if (netlink_ensure_batch_storage(ns, buflen) < 0)
        return -ENOMEM;

    /* Phase 1: peek the first datagram to validate its size. */
    struct sockaddr_nl peek_src;
    struct iovec peek_iov = {
        .iov_base = ns->batch_buf,
        .iov_len = buflen,
    };
    struct msghdr peek_msg = {
        .msg_name = &peek_src,
        .msg_namelen = sizeof(peek_src),
        .msg_iov = &peek_iov,
        .msg_iovlen = 1,
    };

    ssize_t peek_len;
    do {
        peek_len = recvmsg(ns->fd, &peek_msg, MSG_PEEK | MSG_TRUNC);
    } while (peek_len < 0 && errno == EINTR);

    if (peek_len < 0) {
        if (errno == ENOSYS || errno == EINVAL)
            return -ENOSYS;
        return -errno;
    }

    /* MSG_TRUNC causes recvmsg to return the real datagram size even when it
     * exceeds the buffer.  If it doesn't fit, leave it in the kernel queue. */
    if ((size_t)peek_len > buflen)
        return -EMSGSIZE;

    struct mmsghdr recv_msgs[NETLINK_RECV_BATCH_VLEN];
    struct iovec recv_iov[NETLINK_RECV_BATCH_VLEN];
    struct sockaddr_nl recv_src[NETLINK_RECV_BATCH_VLEN];
    for (int i = 0; i < NETLINK_RECV_BATCH_VLEN; i++) {
        uint8_t *slot = ns->batch_buf + ((size_t)i * ns->batch_buflen);
        memset(&recv_msgs[i], 0, sizeof(recv_msgs[i]));
        memset(&recv_src[i], 0, sizeof(recv_src[i]));
        recv_iov[i].iov_base = slot;
        recv_iov[i].iov_len = buflen;
        recv_msgs[i].msg_hdr.msg_name = &recv_src[i];
        recv_msgs[i].msg_hdr.msg_namelen = sizeof(recv_src[i]);
        recv_msgs[i].msg_hdr.msg_iov = &recv_iov[i];
        recv_msgs[i].msg_hdr.msg_iovlen = 1;
    }

    int recv_count;
    do {
        recv_count = recvmmsg(ns->fd, recv_msgs, NETLINK_RECV_BATCH_VLEN, MSG_WAITFORONE, NULL);
    } while (recv_count < 0 && errno == EINTR);

    if (recv_count < 0)
        return -errno;

    if (recv_count == 0)
        return -EAGAIN;

    for (int i = 0; i < recv_count; i++) {
        if ((size_t)recv_msgs[i].msg_len > buflen || (recv_msgs[i].msg_hdr.msg_flags & MSG_TRUNC)) {
            if (i == 0)
                return -EMSGSIZE;
            recv_count = i;
            break;
        }
        ns->batch_lens[i] = (ssize_t)recv_msgs[i].msg_len;
    }

    if (recv_count <= 0)
        return -EMSGSIZE;

    ns->batch_count = recv_count;
    ns->batch_index = 0;
    return 0;
}

int netlink_open(netlink_sock_t *ns) {
    struct sockaddr_nl addr;

    ns->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (ns->fd < 0)
        return -errno;

    ns->seq = 0;
    ns->batch_buf = NULL;
    ns->batch_buflen = 0;
    ns->batch_count = 0;
    ns->batch_index = 0;

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

    if (bind(ns->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int err = errno;
        close(ns->fd);
        ns->fd = -1;
        return -err;
    }

    return 0;
}

void netlink_close(netlink_sock_t *ns) {
    free(ns->batch_buf);
    ns->batch_buf = NULL;
    ns->batch_buflen = 0;
    ns->batch_count = 0;
    ns->batch_index = 0;

    if (ns->fd >= 0) {
        close(ns->fd);
        ns->fd = -1;
    }
}

int netlink_send(netlink_sock_t *ns, struct nlmsghdr *nlh) {
    struct sockaddr_nl dst;
    struct iovec iov = { .iov_base = nlh, .iov_len = nlh->nlmsg_len };
    struct msghdr msg = {
        .msg_name = &dst,
        .msg_namelen = sizeof(dst),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    memset(&dst, 0, sizeof(dst));
    dst.nl_family = AF_NETLINK;
    /* nl_pid = 0 means kernel */

    nlh->nlmsg_seq = ++ns->seq;

    ssize_t sent;
    do {
        sent = sendmsg(ns->fd, &msg, 0);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0)
        return -errno;
    return 0;
}

ssize_t netlink_recv(netlink_sock_t *ns, void *buf, size_t buflen) {
    ssize_t cached = netlink_pop_batch(ns, buf, buflen);
    if (cached != 0)
        return cached;

    if (buflen < NETLINK_BATCH_MIN_BUFLEN)
        return netlink_recv_single(ns, buf, buflen);

    int err = netlink_fill_batch(ns, buflen);
    if (err < 0) {
        if (err == -ENOSYS)
            return netlink_recv_single(ns, buf, buflen);
        return err;
    }

    return netlink_pop_batch(ns, buf, buflen);
}

#endif /* UNSUPPORTED_PLATFORM */
