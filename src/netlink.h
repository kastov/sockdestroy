#ifndef SOCKDESTROY_NETLINK_H
#define SOCKDESTROY_NETLINK_H

#ifdef UNSUPPORTED_PLATFORM

/* Minimal stubs for non-Linux platforms — just enough for addon.c to compile.
 * The JS wrapper will throw before any native function is called on non-Linux. */
#include <stdint.h>
typedef struct { int fd; uint32_t seq; } netlink_sock_t;

#else /* Linux */

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>

/* Netlink SOCK_DIAG protocol */
#ifndef NETLINK_SOCK_DIAG
#define NETLINK_SOCK_DIAG 4
#endif

/* Message types */
#ifndef SOCK_DIAG_BY_FAMILY  /* provided by <linux/sock_diag.h> via <linux/inet_diag.h> */
#define SOCK_DIAG_BY_FAMILY 20
#endif
#define SOCK_DESTROY_SOCK   21   /* our name; kernel defines SOCK_DESTROY=21 as enum in linux/sock_diag.h */

/* Bytecode filter ops — provided by <linux/inet_diag.h>; fallbacks for older headers */
#ifndef INET_DIAG_BC_JMP
#define INET_DIAG_BC_JMP      1
#endif
#ifndef INET_DIAG_BC_S_COND
#define INET_DIAG_BC_S_COND   7
#endif
#ifndef INET_DIAG_BC_D_COND
#define INET_DIAG_BC_D_COND   8
#endif

/* Inet diag request attribute type — provided by <linux/inet_diag.h>; fallback for older headers */
#ifndef INET_DIAG_REQ_BYTECODE
#define INET_DIAG_REQ_BYTECODE  1
#endif

/* Buffer and timeout constants */
#define NETLINK_MAX_RECV_RETRIES 3    /* max sequence-retry attempts in netlink_recv_expected */
#define NETLINK_RECV_TIMEOUT_SEC 3    /* SO_RCVTIMEO for dump and kill sockets */
#define NETLINK_ACK_BUF_SIZE     256  /* ACK response buffer in destroy_one_socket */
#define INET_DIAG_BC_MAX_LEN     256  /* max bytecode filter length */
#define INET_DIAG_REQ_MAX_LEN    512  /* max dump request buffer length */

/* TCP states bitmask — all states (ESTABLISHED, TIME_WAIT, CLOSE_WAIT, etc.) */
#define TCPF_ALL (~0U)

/* Address families */
#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* IP protocol — use enum from <netinet/in.h> to avoid macro/enum conflict */
#include <netinet/in.h>

/* NLM flags - define only if not already defined */
#ifndef NLM_F_REQUEST
#define NLM_F_REQUEST 0x01
#endif
#ifndef NLM_F_ACK
#define NLM_F_ACK    0x04
#endif
#ifndef NLM_F_ROOT
#define NLM_F_ROOT   0x100
#endif
#ifndef NLM_F_MATCH
#define NLM_F_MATCH  0x200
#endif
#ifndef NLM_F_DUMP
#define NLM_F_DUMP   (NLM_F_ROOT | NLM_F_MATCH)
#endif

/* NLMSG types */
#ifndef NLMSG_DONE
#define NLMSG_DONE   3
#endif
#ifndef NLMSG_ERROR
#define NLMSG_ERROR  2
#endif

/* NLMSG alignment macros */
#ifndef NLMSG_ALIGNTO
#define NLMSG_ALIGNTO 4U
#endif
#ifndef NLMSG_ALIGN
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#endif
#ifndef NLMSG_HDRLEN
#define NLMSG_HDRLEN ((int)NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#endif
#ifndef NLMSG_DATA
#define NLMSG_DATA(nlh) ((void*)(((char*)(nlh)) + NLMSG_HDRLEN))
#endif
#ifndef NLMSG_NEXT
#define NLMSG_NEXT(nlh, len) ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
    (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#endif
#ifndef NLMSG_OK
#define NLMSG_OK(nlh, len) ((len) >= (int)sizeof(struct nlmsghdr) && \
    (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
    (int)(nlh)->nlmsg_len <= (len) && \
    (nlh)->nlmsg_len <= (unsigned int)(len))
#endif

/* NLA (Netlink Attribute) macros */
#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4U
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif
#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif

/* nlattr is provided by <linux/netlink.h> */

/* Netlink socket wrapper */
typedef struct {
    int fd;
    uint32_t seq;
} netlink_sock_t;

/* Open a NETLINK_SOCK_DIAG socket. Returns 0 on success, -errno on error. */
int netlink_open(netlink_sock_t *ns);

/* Close netlink socket */
void netlink_close(netlink_sock_t *ns);

/* Send a netlink message. Returns 0 on success, -errno on error. */
int netlink_send(netlink_sock_t *ns, struct nlmsghdr *nlh);

/* Receive into buffer. Returns bytes received, or -errno on error. */
ssize_t netlink_recv(netlink_sock_t *ns, void *buf, size_t buflen);

/* Receive a netlink message, validating the sequence number.
 * Discards messages that don't match the expected sequence.
 * Returns bytes received on success, -errno on error. */
ssize_t netlink_recv_expected(netlink_sock_t *ns, void *buf, size_t buflen, uint32_t expected_seq);

#endif /* UNSUPPORTED_PLATFORM */
#endif /* SOCKDESTROY_NETLINK_H */
