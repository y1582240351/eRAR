#ifndef AFXDP_H
#define AFXDP_H

#include <errno.h>
#include <stdlib.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <sys/mman.h>

/* Flag indicating packet constitutes of multiple buffers*/
#define XDP_PKT_CONTD (1 << 0)
#define NUM_FRAMES (1024)
#define IS_EOP_DESC(options) (!((options) & XDP_PKT_CONTD))

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

static int opt_xsk_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
static u32 opt_umem_flags = 0;
static int opt_queue = 0;
static int opt_mmap_flags;
static bool opt_busy_poll = true;
static const char *opt_if = "ens3";
static u32 opt_batch_size = 2048;
struct xsk_socket_info *xsk;


struct xsk_ring_stats {
	unsigned long rx_frags;
	unsigned long rx_npkts;
	unsigned long tx_frags;
	unsigned long tx_npkts;
	unsigned long rx_dropped_npkts;
	unsigned long rx_invalid_npkts;
	unsigned long tx_invalid_npkts;
	unsigned long rx_full_npkts;
	unsigned long rx_fill_empty_npkts;
	unsigned long tx_empty_npkts;
	unsigned long prev_rx_frags;
	unsigned long prev_rx_npkts;
	unsigned long prev_tx_frags;
	unsigned long prev_tx_npkts;
	unsigned long prev_rx_dropped_npkts;
	unsigned long prev_rx_invalid_npkts;
	unsigned long prev_tx_invalid_npkts;
	unsigned long prev_rx_full_npkts;
	unsigned long prev_rx_fill_empty_npkts;
	unsigned long prev_tx_empty_npkts;
};

struct xsk_driver_stats {
	unsigned long intrs;
	unsigned long prev_intrs;
};

struct xsk_app_stats {
	unsigned long rx_empty_polls;
	unsigned long fill_fail_polls;
	unsigned long copy_tx_sendtos;
	unsigned long tx_wakeup_sendtos;
	unsigned long opt_polls;
	unsigned long prev_rx_empty_polls;
	unsigned long prev_fill_fail_polls;
	unsigned long prev_copy_tx_sendtos;
	unsigned long prev_tx_wakeup_sendtos;
	unsigned long prev_opt_polls;
};

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	struct xsk_ring_stats ring_stats;
	struct xsk_app_stats app_stats;
	struct xsk_driver_stats drv_stats;
	u32 outstanding_tx;
};

static void __exit_with_error(int error, const char *file, const char *func,
			      int line)
{
	fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func,
		line, error, strerror(error));

	exit(EXIT_FAILURE);
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, __LINE__)

static struct xsk_umem_info *xsk_configure_umem(void *buffer, u64 size)
{
	struct xsk_umem_info *umem;
	struct xsk_umem_config cfg = {
		/* We recommend that you set the fill ring size >= HW RX ring size +
		 * AF_XDP RX ring size. Make sure you fill up the fill ring
		 * with buffers at regular intervals, and you will with this setting
		 * avoid allocation failures in the driver. These are usually quite
		 * expensive since drivers have not been written to assume that
		 * allocation failures are common. For regular sockets, kernel
		 * allocated memory is used that only runs out in OOM situations
		 * that should be rare.
		 */
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = opt_xsk_frame_size,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = opt_umem_flags
	};
	int ret;

	umem = (struct xsk_umem_info*)calloc(1, sizeof(*umem));
	if (!umem)
		exit_with_error(errno);

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       &cfg);
	if (ret)
		exit_with_error(-ret);

	umem->buffer = buffer;
	return umem;
}


static void xsk_populate_fill_ring(struct xsk_umem_info *umem)
{
	int ret, i;
	u32 idx;

	ret = xsk_ring_prod__reserve(&umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS * 2, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
		exit_with_error(-ret);
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS * 2; i++)
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) =
			i * opt_xsk_frame_size;
	xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2);
}


static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem,
						    bool rx, bool tx)
{
	struct xsk_socket_config cfg;
	struct xsk_socket_info *xsk;
	struct xsk_ring_cons *rxr;
	struct xsk_ring_prod *txr;
	int ret;

	xsk = (struct xsk_socket_info*)calloc(1, sizeof(*xsk));
	if (!xsk)
		exit_with_error(errno);

	xsk->umem = umem;
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
    cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
	cfg.bind_flags = XDP_USE_NEED_WAKEUP;

	rxr = rx ? &xsk->rx : NULL;
	// txr = tx ? &xsk->tx : NULL;
	txr = NULL;
	ret = xsk_socket__create(&xsk->xsk, opt_if, opt_queue, umem->umem,
				 rxr, txr, &cfg);
	if (ret)
		exit_with_error(-ret);

	xsk->app_stats.rx_empty_polls = 0;
	xsk->app_stats.fill_fail_polls = 0;
	xsk->app_stats.copy_tx_sendtos = 0;
	xsk->app_stats.tx_wakeup_sendtos = 0;
	xsk->app_stats.opt_polls = 0;
	xsk->app_stats.prev_rx_empty_polls = 0;
	xsk->app_stats.prev_fill_fail_polls = 0;
	xsk->app_stats.prev_copy_tx_sendtos = 0;
	xsk->app_stats.prev_tx_wakeup_sendtos = 0;
	xsk->app_stats.prev_opt_polls = 0;

	return xsk;
}


// 如果需要使用busy poll，则使用需要调用该函数设置 socket
static void apply_setsockopt(struct xsk_socket_info *xsk)
{
	int sock_opt;

	if (!opt_busy_poll)
		return;

	sock_opt = 1;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_PREFER_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

	sock_opt = 20;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

	sock_opt = opt_batch_size;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL_BUDGET,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);
}


static void enter_xsks_into_map(int rank)
{
	int i, xsks_map;

    xsks_map = bpf_obj_get("/sys/fs/bpf/xsks_map"); // 这里需要换为我们的xsks_map
	if (xsks_map < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(xsks_map));
			exit(EXIT_FAILURE);
	}

	int fd = xsk_socket__fd(xsk->xsk);
	int ret;

	ret = bpf_map_update_elem(xsks_map, &rank, &fd, 0);
	if (ret) {
		fprintf(stderr, "ERROR: bpf_map_update_elem %d\n", i);
		exit(EXIT_FAILURE);
	}
}

static unsigned int rx_drop(struct xsk_socket_info *xsk, char* buffer)
{
	unsigned int rcvd, i, eop_cnt = 0;
	u32 idx_rx = 0, idx_fq = 0;
	int ret;
	u32 len = 0;

	rcvd = xsk_ring_cons__peek(&xsk->rx, opt_batch_size, &idx_rx);
	if (!rcvd) {
		if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
			xsk->app_stats.rx_empty_polls++;
			// printf("???\n");
			len = recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		return len;
	} else if (rcvd > 1) {
		printf("Warning in AF_XDP: recv more than one packet\n");
	}

	ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	while (ret != rcvd) {
		if (ret < 0)
			exit_with_error(-ret);
		if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
			xsk->app_stats.fill_fail_polls++;
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	}

	for (i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
		u64 addr = desc->addr;
		len = desc->len;
		// addr 对应的是在rx中的地址，这里是提取umem中的地址，实际操作就是使用掩码降低位掩盖，然后得到umem所对应的frame的首地址（offset）
		u64 orig = xsk_umem__extract_addr(addr);
		eop_cnt += IS_EOP_DESC(desc->options);

		addr = xsk_umem__add_offset_to_addr(addr);
		char *pkt = (char*)xsk_umem__get_data(xsk->umem->buffer, addr);

		memcpy(buffer, pkt, len);
		printf("xsk recv: %d\n", len);
		// hex_dump(pkt, len, addr);
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = orig;
	}

	xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
	xsk_ring_cons__release(&xsk->rx, rcvd);
	xsk->ring_stats.rx_npkts += eop_cnt;
	xsk->ring_stats.rx_frags += rcvd;
	return len;
}


static void xsk_cleanup(void)
{
	struct xsk_umem *umem = xsk->umem->umem;

	xsk_socket__delete(xsk->xsk);
	(void)xsk_umem__delete(umem);
}


static unsigned int xsk_init(char* buffer, int rank) {
    void *bufs = mmap(NULL, NUM_FRAMES * opt_xsk_frame_size,
		    PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | opt_mmap_flags, -1, 0);
	if (bufs == MAP_FAILED) {
		printf("ERROR: mmap failed\n");
		exit(EXIT_FAILURE);
	}

    struct xsk_umem_info *umem;
    umem = xsk_configure_umem(bufs, NUM_FRAMES * opt_xsk_frame_size);
    xsk_populate_fill_ring(umem);
    xsk = xsk_configure_socket(umem, true, true);
    apply_setsockopt(xsk);

    enter_xsks_into_map(rank);

	unsigned int len;
	// for (;;) {
		len = rx_drop(xsk, buffer);
		// if (len > 0) {
			// printf("afxdp recv len: %d\n", len);
			// break;
		// }
	// }
	xsk_cleanup();
	munmap(bufs, NUM_FRAMES * opt_xsk_frame_size);
	return len;
}

#endif