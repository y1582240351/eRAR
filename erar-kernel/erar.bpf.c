#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "erar.h"

#ifdef EBPF_SIMD
	extern int bpf_mm256add(int *arr1, u32 arr1__sz, const int *arr2, u32 arr2__sz) __ksym;
#endif

#define  ETH_P_IP 0x0800
#define  ETH_P_ARP 0x0806
#define  ETH_P_RARP 0x8035
#define  ETH_P_IPV6 0x86D

#define TC_ACT_UNSPEC -1
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define ALTER_BEGIN_PORT 18400
#define ALTER_PORT_RANGE 10

#define ETH_ALEN 6
#define tcp_hdrlen(tcp) (tcp->doff * 4)
#define udp_hdrlen(udp) ()
#define ipv4_hdrlen(ip) (ip->ihl * 4)

#define MAGIC_LEN 4
#define MIN_PAYLOAD_LEN MAGIC_LEN + sizeof(unsigned int) + sizeof(int) + sizeof(unsigned int) 

#define OP_REDUCESCATTER 0 
#define OP_ALLGATHER 1
#define OP_RESEND_RS 2
#define OP_RESEND_AG 3
#define OP_RESEND_INIT 4
#define OP_GEN_RESEND  5
#define OP_FINIAL 6
#define OP_FINISH 7
#define OP_REDUCESCATTER_EARLY 8
#define OP_FINISH_QUERY 9
#define OP_CLEAN 10
#define OP_CLEAN_QUERY 11
#define OP_FINISH_CLEAN 12

#define MAX_SOCKS 5
#define REDIRECT_DEV 2
#define RESEND_THRESHOLD_MS 100
#define MS_TO_NS 1000000

#define MIN(a,b) ((a)>(b))?(b):(a)
#define MAX(a,b) ((a)>(b))?(a):(b)


struct resend_key {
	int rank;
	u32 t;
	int op;
};


// port to mpi_rank_info, save the info of rank running in this machine
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct mpi_rank_info);
    __uint(max_entries, MAX_RANK_SIZE * 1024);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} mpi_rank_infos SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct data_blocks_buff);
	__uint(max_entries, MAX_RANK_SIZE * 1024);
} data_blocks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct mpi_tmp_buff);
	__uint(max_entries, MAX_RANK_SIZE * 1024);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} rank_tmp_buff SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 16);
	__type(key, u32);
	__type(value, u32);
} xdp_progs SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RANK_SIZE);
	__type(key, u32);
	__type(value, struct rank_net_info);
} net_infos SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, u64);
} time_arr SEC(".maps");

// 注意，这里的几个ring buffer是在假设一个node一个rank的情况下设置的，如果要单节点上运行多个rank，
// 需要针对不同的rank对这些ring buffer进行区分，例如使用 map in map
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} submit_rb SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct resend_key);
	__type(value, u64);
} resend_timestamp_map SEC(".maps");


struct resend_meta {
	// curr_rank's sendto
	u32 op;
	u32 t;
	u32 resend_op;
	// curr_rank generates curr packet, and set curr packet's rank to curr_rank's sendto.
	// but resend_rank equals to curr_rank's recvfrom. 
	// recvfrom -> curr_rank -> sendto
	u32 curr_rank; 
	u32 curr_sequence_id;
	u32 resend_t;
} __attribute__((aligned(4)));


static inline u16 compute_ip_checksum(struct iphdr *ip) {
    u32 csum = 0;
    u16 *next_ip_u16 = (u16 *)ip;

    ip->check = 0;
#pragma clang loop unroll(full)
    for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
        csum += *next_ip_u16++;
    }

	return ~((csum & 0xffff) + (csum >> 16));
}


static inline u32 rank_sequence_id_hash(u32 rank, u32 sequence_id) {
	return sequence_id * MAX_RANK_SIZE + rank;
}


#ifdef TC_INIT_PACKET
// attach at tc egress
SEC("ARStart")
int arstart_tc_main(struct __sk_buff *skb) {
	return TC_ACT_OK;
	void *data_end = (void*)(long)skb->data_end;
	void *data = (void*)(long)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return TC_ACT_OK;
	if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;
	if (udp + 1 > data_end) return TC_ACT_OK;

	// 由于这里是egress，所以我们计算port的时候使用是udp->dest
	int vaild_port_range = bpf_ntohs(udp->dest) - ALTER_BEGIN_PORT;
	if (vaild_port_range < 0 || vaild_port_range > ALTER_PORT_RANGE)
		return TC_ACT_OK;
	
	// 使用unsigned，防止符号拓展
	if (payload + MIN_PAYLOAD_LEN > data_end) return TC_ACT_OK;

	if (payload[0] != 0x42 || payload[1] != 0x60 || payload[2] != 0x80 || payload[3] != 0x02)
		return TC_ACT_OK;

	// union {
	// 	unsigned int addr;
	// 	unsigned char ip[4];
	// } ip_addr;
	// ip_addr.addr = ip->addrs.saddr;
	// bpf_printk("tc fetch src: %u.%u:%u", ip_addr.ip[2], ip_addr.ip[3], bpf_ntohs(udp->dest));
	// ip_addr.addr = ip->addrs.daddr;
	// bpf_printk("tc fetch dst1: %u.%u:%u", ip_addr.ip[0], ip_addr.ip[1], bpf_ntohs(udp->dest));
	// bpf_printk("tc fetch dst2: %u.%u:%u", ip_addr.ip[2], ip_addr.ip[3], bpf_ntohs(udp->dest));
	payload += MAGIC_LEN;

	unsigned int op = *(unsigned int*)payload;
	if (op != OP_REDUCESCATTER)
		return TC_ACT_OK;
	payload += sizeof(u32);

	unsigned short tot_len_old = ip->tot_len;
	// udp->check = 0;

	u32 rank = *((u32*)payload);
	payload += sizeof(int);
	// bpf_printk("TC ARStart rank: %u", rank);
	struct mpi_rank_info *rinfo = bpf_map_lookup_elem(&mpi_rank_infos, &rank);
	if (rinfo == NULL)
		bpf_printk("TC ARStart: Error look up map: %u", rank);
	if (!rinfo)
		return TC_ACT_OK;
	
	unsigned int t = *(unsigned int*)payload;
	payload += sizeof(unsigned int);

	int block_id = (rank - t + rinfo->size) % rinfo->size;
	if (block_id >= MAX_RANK_SIZE)
		return TC_ACT_OK;
	if (block_id < 0)
		return TC_ACT_OK;
    unsigned int block_count = rinfo->count;
	block_count *= sizeof(int);

	u32 ip_hdrlen = ipv4_hdrlen(ip);
	u32 hdr_offset = sizeof(struct ethhdr) + ip_hdrlen + sizeof(struct udphdr) + MAGIC_LEN + sizeof(unsigned int) + sizeof(int) + sizeof(unsigned int);
	u32 resize_len = hdr_offset + block_count;
	
	// 其实这个可以和下面xdp改port功能重复了，估计可以二选一
	__be16 dport = bpf_htons(rinfo->sendto + (u16)ALTER_BEGIN_PORT);
	bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + ip_hdrlen + offsetof(struct udphdr, dest), &dport, sizeof(dport), BPF_F_RECOMPUTE_CSUM);

	__be16 tot_len = bpf_htons(resize_len - sizeof(struct ethhdr));
	bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len), &tot_len, sizeof(tot_len), BPF_F_RECOMPUTE_CSUM);
	bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len), tot_len_old, tot_len, sizeof(tot_len));
	tot_len = bpf_htons(resize_len - sizeof(struct ethhdr) - ip_hdrlen);
	// bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + ip_hdrlen + offsetof(struct udphdr, len), &tot_len, sizeof(tot_len), BPF_F_RECOMPUTE_CSUM);
	rank = rinfo->sendto;

	bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + ip_hdrlen + sizeof(struct udphdr) + MAGIC_LEN + sizeof(unsigned int), &rank, sizeof(rank), BPF_F_RECOMPUTE_CSUM);

	// bpf_skb_change_tail(skb, resize_len, 0);
	bpf_printk("TC test");
	int send_len = block_count;
	if (send_len <= 0) {
		bpf_printk("TC error 0: %d, %d", send_len, MAX_BUF_SIZE);
		return TC_ACT_OK;
	}
	if (send_len >= MAX_BUF_SIZE) {
		bpf_printk("TC error 1: %d, %d", send_len, MAX_BUF_SIZE);
		return TC_ACT_OK;
	}
	bpf_printk("TC test 1");
	bpf_skb_store_bytes(skb, hdr_offset, blocks_buff->buff[block_id], send_len, BPF_F_RECOMPUTE_CSUM);
	// bpf_printk("TC: success: %u", bpf_ntohs(dport));
	bpf_printk("TC test 2");
	return TC_ACT_OK;
}
#endif


SEC("ReduceScatter")
int reduce_scatter_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = (char*)data + sizeof(struct ethhdr);
	struct udphdr *udp = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
	if (udp + 1 > data_end) return XDP_PASS;
	
	// 这里挂载的ingress，所以我们探究的应该是dest。
	int vaild_port_range = bpf_ntohs(udp->dest) - ALTER_BEGIN_PORT;
	if (vaild_port_range > ALTER_PORT_RANGE || vaild_port_range < 0)
		return XDP_PASS;
	
	if (payload + sizeof(struct arhdr) > data_end) {
		bpf_printk("XDP: Len to less");
		return XDP_DROP;
	}
	struct arhdr *arhdr = (struct arhdr*)payload;
	payload += sizeof(struct arhdr);
	if (arhdr->magic_num[0] != 0x42 || arhdr->magic_num[1] != 0x60  || arhdr->magic_num[2] != 0x80 || arhdr->magic_num[3] != 0x02) {
		bpf_printk("XDP: not magic num");
		return XDP_DROP;
	}

	if (arhdr->op == OP_ALLGATHER) {
		bpf_printk("XDP: dump to allgather");
		bpf_tail_call(ctx, &xdp_progs, XDP_ALLGATHER);
		return XDP_DROP;
	} else if (arhdr->op == OP_RESEND_AG || arhdr->op == OP_RESEND_RS || arhdr->op == OP_RESEND_INIT) {
		bpf_printk("XDP: Resend");
		bpf_tail_call(ctx, &xdp_progs, XDP_RESEND_FILTER);
		return XDP_DROP;
	} else if (arhdr->op == OP_GEN_RESEND) {
		// 事实上，下面的逻辑只有在测试的时候才会发生
		arhdr->op = OP_GEN_RESEND;
		struct resend_meta *meta;
		int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
		if (ret < 0) {
			bpf_printk("XDP Allgather: adjust meta failed");
			return XDP_ABORTED;
		}
		meta = (void*)(unsigned long)ctx->data_meta;
		data = (void *)(long)ctx->data; 
		if (meta + 1 > data) {
			bpf_printk("XDP Allgather: get meta in ctx failed");
			return XDP_ABORTED;
		}
		meta->op = OP_ALLGATHER;
		meta->t = 1;
		meta->curr_rank = 0;
		meta->resend_op = OP_RESEND_AG;
		meta->resend_t = 0;
		bpf_printk("XDP Allgather: resend");
		return XDP_PASS; // send to tc ingress: resend gen
	} else if (arhdr->op == OP_FINISH || arhdr->op == OP_FINISH_CLEAN) {
		bpf_printk("XDP: finish: %d", arhdr->op);
		bpf_tail_call(ctx, &xdp_progs, XDP_FINISH);
		return XDP_DROP;
	} else if (arhdr->op == OP_FINISH_QUERY) {
		bpf_printk("XDP: finish query");
		bpf_tail_call(ctx, &xdp_progs, XDP_FINISH_QUERY);
		return XDP_DROP;
	} else if (arhdr->op == OP_CLEAN) {
		bpf_printk("XDP: clean");
		bpf_tail_call(ctx, &xdp_progs, XDP_CLEAN);
		return XDP_DROP;
	} else if (arhdr->op == OP_CLEAN_QUERY) {
		bpf_printk("XDP: clean query");
		bpf_tail_call(ctx, &xdp_progs, XDP_CLEAN_QUERY);
		return XDP_DROP;
	} else if (arhdr->op != OP_REDUCESCATTER) {
		bpf_printk("XDP ReduceScatter: drop");
		return XDP_DROP;
	}

	if (arhdr->t == 0) {
		u64 kernel_time = bpf_ktime_get_ns();
		u32 key = 0;
		bpf_map_update_elem(&time_arr, &key, &kernel_time, BPF_ANY);
		bpf_printk("Init time: %llu", kernel_time);
	}

	u32 rank = arhdr->rank;
	u32 sequence_id = arhdr->sequence_id;
	unsigned int t = arhdr->t;
	u32 rank_sequence_id = rank_sequence_id_hash(rank, sequence_id);
	struct mpi_rank_info *rinfo = bpf_map_lookup_elem(&mpi_rank_infos, &rank_sequence_id);
	if (!rinfo) {
		struct mpi_tmp_buff *tmp_buff = bpf_map_lookup_elem(&rank_tmp_buff, &rank_sequence_id);
		if (!tmp_buff) {
			bpf_printk("XDP ReduceScatter: look up to rank_tmp_buff failed\n");
			return XDP_DROP;
		}
		if (tmp_buff->bitmap_rs & (1ull << t)) {
			bpf_printk("XDP ReduceScatter: this packet has recved before. rank: %d, t: %d", rank, t);
			return XDP_DROP;
		}
		__sync_fetch_and_or(&(tmp_buff->bitmap_rs), 1ull << t);
		int recv_block_id = (rank - t - 1 + MAX_RANK_SIZE) % MAX_RANK_SIZE;
		if (recv_block_id >= MAX_RANK_SIZE)
			return XDP_DROP;
		if (recv_block_id < 0)
			return XDP_DROP;
		int payload_size = ((u8*)data_end - payload) / sizeof(int);
		#pragma clang loop unroll(full)
		for (int i = 0; i < MIN(payload_size, MAX_BUF_SIZE); ++i) {
			if ((void*)(payload + i * sizeof(int) + sizeof(int)) > data_end) {
				break;
			}
			if (i >= MAX_BUF_SIZE) {
				break;
			}
			tmp_buff->buff[recv_block_id][i] = *((int*)(payload + i * sizeof(int)));
		}
		return XDP_DROP;
	}
	struct data_blocks_buff *blocks_buff = bpf_map_lookup_elem(&data_blocks, &rank_sequence_id);
	if (!blocks_buff) {
		bpf_printk("XDP: Error look up map: %u", rank);
		return XDP_DROP;
	}

	// 检查此前是否已经收到该数据包了
	if (rinfo->bitmap_rs & (1ull << t)) {
		bpf_printk("XDP ReduceScatter: this packet has recved before. rank: %d, t: %d", rank, t);
		return XDP_DROP;
	}

	// rinfo->bitmap_rs |= (1ull << t);
	__sync_fetch_and_or(&(rinfo->bitmap_rs), (1ull << t));
	// rinfo->bitmap_cnt += 1; // 不同packet对于info的更新可能会出现数据竞争
	__sync_fetch_and_add(&(rinfo->bitmap_cnt), 1);

	bpf_printk("XDP ReduceScatter: %d, %u", rank, t);

	int send_block_id = (rank - t + rinfo->size) % rinfo->size;
	int recv_block_id = (rank - t - 1 + rinfo->size) % rinfo->size;
	// bpf_printk("XDP RS %d, %d: fetch package.", send_block_id, recv_block_id);
	// bpf_printk("XDP test probe: %d, %d, %d", send_block_id, rank, t);
	if (recv_block_id >= MAX_RANK_SIZE)
		return XDP_DROP;
	if (recv_block_id < 0)
		return XDP_DROP;
	if (send_block_id >= MAX_RANK_SIZE)
		return XDP_DROP;
	if (send_block_id < 0)
		return XDP_DROP;
	// 或者我们不需要这么复杂，直接将block_count选为rinfo->early_segcount
    unsigned int block_count = rinfo->count;
	// bpf_printk("XDP test probe: %d, %d", send_block_id, recv_block_id);

	if ((void*)(payload + MIN(block_count, MAX_BUF_SIZE) * sizeof(int)) > data_end) {
		return XDP_DROP;
	}

	// bpf_printk("XDP RS %d: fetch package.", rank);
	#ifdef EBPF_SIMD
			bpf_mm256add(blocks_buff->buff[recv_block_id], MIN(payload_size, MAX_BUF_SIZE), payload, MIN(payload_size, MAX_BUF_SIZE));
	#else
		#pragma clang loop unroll(full)
		for (int i = 0; i < MIN(block_count, MAX_BUF_SIZE); ++i) {
			if ((void*)(payload + i * sizeof(int) + sizeof(int)) > data_end) {
				// bpf_printk("rank %d: XDP break 1: %d", rank, data_end-(void*)payload);
				break;
			}
			if (i >= MAX_BUF_SIZE) {
				// bpf_printk("rank %d: XDP break 2", rank);
				break;
			}
			// bpf_printk("XDP loop before: %d", *((int*)(payload + i * sizeof(int))));
			blocks_buff->buff[recv_block_id][i] += *((int*)(payload + i * sizeof(int)));
			*((int*)(payload + i * sizeof(int))) = (blocks_buff->buff[recv_block_id][i]);
			// bpf_printk("XDP loop after: %d", *((int*)(payload + i * sizeof(int))));
		}
	#endif

	// rinfo->bitmap_rs |= (1ull << t);
	// rinfo->bitmap_cnt += 1; // 不同packet对于info的更新可能会出现数据竞争

	if (rinfo->bitmap_cnt >= rinfo->size * 2 - 2) { 
		// bpf_printk("rank %d: XDP Allgather Finished: %d, %d", rank, (char*)data_end - (char*)udp, bpf_ntohs(udp->len));
		// udp->len += bpf_htons(MAX_PACKET_BUF_SIZE * (rinfo->size) * sizeof(int));
		// ip->tot_len += bpf_htons(MAX_PACKET_BUF_SIZE * (rinfo->size) * sizeof(int));
		// bpf_xdp_adjust_tail(ctx, MAX_PACKET_BUF_SIZE * (rinfo->size) * sizeof(int));
		// summit
		bpf_tail_call(ctx, &xdp_progs, XDP_SUMMIT);
		return XDP_DROP;
	}

#ifdef FAST_RESEND
	if (t > 0) {
		unsigned long long mask = 1ull << (t-1);
		// 只检查前一个数据包是否到达
		if (!(rinfo->bitmap_rs & mask)) {
			arhdr->op = OP_GEN_RESEND;
			struct resend_meta *meta;
			int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
			if (ret < 0) {
				bpf_printk("XDP Allgather: adjust meta failed");
				return XDP_ABORTED;
			}
			meta = (void*)(unsigned long)ctx->data_meta;
			data = (void *)(long)ctx->data;
			if (meta + 1 > data) {
				bpf_printk("XDP Allgather: get meta in ctx failed");
				return XDP_ABORTED;
			}
			if (t >= rinfo->size - 2) {
				meta->op = OP_ALLGATHER;
				meta->t = 0;
			} else {
				meta->op = OP_REDUCESCATTER;
				meta->t = t + 1;
			}
			meta->curr_rank = rank;
			meta->resend_op = OP_RESEND_RS;
			meta->resend_t = t - 1;
			bpf_printk("XDP ReduceScatter: Resend");
			return XDP_PASS; // send to tc ingress: resend gen
		}
	}
#endif

	if (t + 2 >= rinfo->size) {
		// bpf_printk("rank %d: XDP Finished", rank);
		arhdr->op = OP_ALLGATHER;
		arhdr->rank = rinfo->sendto;
		arhdr->t = 0;
		// bpf_tail_call(ctx, &xdp_progs, XDP_ALLGATHER);
		// return XDP_DROP;
	} else {
		arhdr->t += 1;
		arhdr->rank = rinfo->sendto;
	}

	u32 sendto = rinfo->sendto;
	struct rank_net_info* sendto_net_info = bpf_map_lookup_elem(&net_infos, &sendto);
	if (!sendto_net_info) {
		bpf_printk("XDP ReduceScatter Error: can't find sendto net info");
		return XDP_DROP;
	}

	udp->source = udp->dest;
	udp->dest = bpf_htons(ALTER_BEGIN_PORT + sendto);
	udp->check = 0; // computing udp checksum is not required
	
	u32 tmp = sendto_net_info->ip_addr.addr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp;

	// ip_addr.addr = ip->addrs.daddr;
	// bpf_printk("XDP sendto: %u.%u:%u", ip_addr.ip[2], ip_addr.ip[3], bpf_ntohs(udp->dest));
	
	u16 csum = compute_ip_checksum(ip);
	ip->check = csum;
	// 还要更新网卡地址,不然的话redirect的包会在网卡出口处丢弃
	// unsigned char tmp_mac[6];
	// __builtin_memcpy(tmp_mac, eth->h_source, 6);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	// __builtin_memcpy(eth->h_dest, tmp_mac, 6);
	__builtin_memcpy(eth->h_dest, sendto_net_info->mac_addr, ETH_ALEN);
	// bpf_printk("XDP1: dst mac: %x, %x, %x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
	// bpf_printk("XDP2: dst mac: %x, %x, %x", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

	bpf_printk("XDP Redirect: %u", ctx->ingress_ifindex);
	
	return bpf_redirect(ctx->ingress_ifindex, 0);
	// return XDP_TX;
	// return XDP_PASS;
}


SEC("AllGather")
int allgather_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = (char*)data;
	struct iphdr *ip = (char*)data + sizeof(struct ethhdr);
	struct udphdr *udp = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
	if (udp + 1 > data_end) return XDP_PASS;
	
	int vaild_port_range = bpf_ntohs(udp->dest) - ALTER_BEGIN_PORT;
	if (vaild_port_range > ALTER_PORT_RANGE || vaild_port_range < 0)
		return XDP_PASS;
	if (payload + sizeof(struct arhdr) > data_end) {
		bpf_printk("XDP: Len to less");
		return XDP_DROP;
	}
	struct arhdr *arhdr = payload;
	payload += sizeof(struct arhdr);
	if (arhdr->magic_num[0] != 0x42 || arhdr->magic_num[1] != 0x60  || arhdr->magic_num[2] != 0x80 || arhdr->magic_num[3] != 0x02) {
		bpf_printk("XDP: not magic num");
		return XDP_DROP;
	}
	if (arhdr->op != OP_ALLGATHER) {
		bpf_printk("XDP Allgahter: op don't match");
		return XDP_DROP;
	}

	u32 rank = arhdr->rank;
	u32 sequence_id = arhdr->sequence_id;
	u32 rank_sequence_id = rank_sequence_id_hash(rank, sequence_id);
	u32 t = arhdr->t;
	struct mpi_rank_info *rinfo = bpf_map_lookup_elem(&mpi_rank_infos, &rank_sequence_id);
	if (!rinfo) {
		bpf_printk("XDP Allgather: Error look up map mpi_rank_infos: %u", rank);
		return XDP_DROP;
	}
	struct data_blocks_buff *blocks_buff = bpf_map_lookup_elem(&data_blocks, &rank_sequence_id);
	if (!blocks_buff) {
		bpf_printk("XDP Allgather: Error look up map data_blocks: %u", rank);
		return XDP_DROP;
	}

	if (rinfo->bitmap_ag & (1ull << t)) {
		bpf_printk("XDP Allgather: this packet has recved before. rank: %d, t: %d", rank, t);
		return XDP_DROP;
	}
	bpf_printk("XDP Allgather: %d, %u", rank, t);


	unsigned int recv_block_id = (rank - t + rinfo->size) % rinfo->size;
	unsigned int send_block_id = (rank + 1 - t + rinfo->size) % rinfo->size;
	unsigned int block_count = rinfo->count;
	bpf_printk("XDP Allgather %d: fetch package.", recv_block_id);

	if ((void*)(payload + MIN(block_count, MAX_BUF_SIZE) * sizeof(int)) > data_end) {
		return XDP_DROP;
	}
	if (recv_block_id >= MAX_RANK_SIZE) {
		return XDP_DROP;
	}
	if (recv_block_id < 0) {
		return XDP_DROP;
	}
	if (send_block_id >= MAX_RANK_SIZE) {
		return XDP_DROP;
	}
	if (send_block_id < 0) {
		return XDP_DROP;
	}

	// rinfo->bitmap_ag |= (1ull << t);
	__sync_fetch_and_or(&(rinfo->bitmap_ag), (1ull << t));
	// rinfo->bitmap_cnt += 1;
	__sync_fetch_and_add(&(rinfo->bitmap_cnt), 1);
	// bpf_printk("XDP Allgather %d: fetch package.", rank);
	#pragma clang loop unroll(full)
	for (int i = 0; i < MIN(block_count, MAX_BUF_SIZE); ++i) {
		if ((void*)(payload + i * sizeof(int) + sizeof(int)) > data_end) {
			// bpf_printk("rank %d: XDP Allgather break 1: %d", rank, data_end-(void*)payload);
			break;
		}
		if (i >= MAX_BUF_SIZE) {
			// bpf_printk("rank %d: XDP Allgather break 2", rank);
			break;
		}
		// bpf_printk("XDP loop before: %d", *((int*)(payload + i * sizeof(int))));
		blocks_buff->buff[recv_block_id][i] = *((int*)(payload + i * sizeof(int)));
		// *((int*)(payload + i * sizeof(int))) = (blocks_buff->buff[send_block_id][i]); // 这一行或许是没有必要的
		// bpf_printk("XDP loop after: %d", *((int*)(payload + i * sizeof(int))));
	}

	// rinfo->bitmap_ag |= (1ull << t);
	// rinfo->bitmap_cnt += 1;

	// 如何检查bitmap是不是满了也是一个问题，或者我们不需要直接检查bitmap，而是使用一个计数器记录收到数据包的数量。
	if (rinfo->bitmap_cnt >= rinfo->size * 2 - 2) { 
		// bpf_printk("rank %d: XDP Allgather Finished: %d, %d", rank, (char*)data_end - (char*)udp, bpf_ntohs(udp->len));
		// udp->len += bpf_htons(MAX_PACKET_BUF_SIZE * (rinfo->size) * sizeof(int));
		// ip->tot_len += bpf_htons(MAX_PACKET_BUF_SIZE * (rinfo->size) * sizeof(int));
		// bpf_xdp_adjust_tail(ctx, MAX_PACKET_BUF_SIZE * (rinfo->size) * sizeof(int));
		// summit
		bpf_tail_call(ctx, &xdp_progs, XDP_SUMMIT);
		return XDP_DROP;
	}

#ifdef FAST_RESEND
	unsigned int prev_t = t == 0 ? (rinfo->size-2) : (t-1);
	unsigned long long bitmap = t == 0 ? rinfo->bitmap_rs : rinfo->bitmap_ag;
	unsigned long long mask = 1ull << (prev_t);
	
	// 只检查前一个数据包是否到达
	if (!(bitmap & mask)) {
		arhdr->op = OP_GEN_RESEND;
		struct resend_meta *meta;
		int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
		if (ret < 0) {
			bpf_printk("XDP Allgather: adjust meta failed");
			return XDP_ABORTED;
		}
		meta = (void*)(unsigned long)ctx->data_meta;
		data = (void *)(long)ctx->data; 
		if (meta + 1 > data) {
			bpf_printk("XDP Allgather: get meta in ctx failed");
			return XDP_ABORTED;
		} 
		meta->op = (t >= rinfo->size-2) ? OP_FINIAL : OP_ALLGATHER;
		meta->t = t + 1; // 这里还要检查一下，需不需要将当前数据包也发送出去（不是重传通知包）
		meta->curr_rank = rank;
		meta->resend_op = (t == 0) ? OP_RESEND_RS : OP_RESEND_AG;
		meta->resend_t = prev_t;
		bpf_printk("XDP Allgather: resend");
		return XDP_PASS; // send to tc ingress: resend gen
	}
#endif

	if (t >= rinfo->size-2) {
		bpf_printk("XDP Allgather: allgather finish rank: %d", rank);
		return XDP_DROP;
	}

	u32 sendto = rinfo->sendto;
	struct rank_net_info* sendto_net_info = bpf_map_lookup_elem(&net_infos, &sendto);
	if (!sendto_net_info) {
		bpf_printk("XDP ReduceScatter Error: can't find sendto net info");
		return XDP_DROP;
	}

	arhdr->t += 1;
	arhdr->rank = rinfo->sendto;
	udp->source = udp->dest;
	udp->dest = bpf_htons(ALTER_BEGIN_PORT + sendto);
	udp->check = 0; // computing udp checksum is not required
	
	u32 tmp = sendto_net_info->ip_addr.addr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp;
	
	u16 csum = compute_ip_checksum(ip);
	ip->check = csum;
	// 还要更新网卡地址,不然的话redirect的包会在网卡出口处丢弃
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, sendto_net_info->mac_addr, ETH_ALEN);

	// bpf_printk("rank %d: XDP Redirect", rank);
	
	return bpf_redirect(ctx->ingress_ifindex, 0);
	// return XDP_TX;
}


SEC("Summit")
int summit_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = (char*)data;
	struct iphdr *ip = (char*)data + sizeof(struct ethhdr);
	struct udphdr *udp = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
	if (udp + 1 > data_end) return XDP_PASS;
	
	int vaild_port_range = bpf_ntohs(udp->dest) - ALTER_BEGIN_PORT;
	if (vaild_port_range > ALTER_PORT_RANGE || vaild_port_range < 0)
		return XDP_PASS;

	if (payload + sizeof(struct arhdr) > data_end) {
		bpf_printk("XDP Summit: Len to less");
		return XDP_DROP;
	}
	// if (sizeof(struct arhdr) != MIN_PAYLOAD_LEN)
	// 	bpf_printk("XDP Summit: Error");
	struct arhdr *arhdr = (struct arhdr*)payload;
	payload += sizeof(struct arhdr);
	if (arhdr->magic_num[0] != 0x42 || arhdr->magic_num[1] != 0x60  || arhdr->magic_num[2] != 0x80 || arhdr->magic_num[3] != 0x02) {
		bpf_printk("XDP Summit: not magic num");
		return XDP_DROP;
	}

	u32 rank = arhdr->rank;
	u32 sequence_id = arhdr->sequence_id;
	u32 rank_sequence_id = rank_sequence_id_hash(rank, sequence_id);
	// if (rank != 0)
	// 	return XDP_DROP;
	struct mpi_rank_info *rinfo = bpf_map_lookup_elem(&mpi_rank_infos, &rank_sequence_id);
	if (!rinfo) {
		bpf_printk("XDP Summit: Error look up map rank_infos: %u", rank);
		return XDP_DROP;
	}
	// struct data_blocks_buff *blocks_buff = bpf_map_lookup_elem(&data_blocks, &rank_sequence_id);
	// if (!blocks_buff) {
	// 	bpf_printk("XDP Summit: Error look up map data_blocks: %u", rank);
	// 	return XDP_DROP;
	// }
	bpf_printk("XDP Summit: %d", rank);

	u32 count = rinfo->count;
	u32 offset = 0;
	struct submit_event *event = NULL;
	event = bpf_ringbuf_reserve(&submit_rb, sizeof(struct submit_event), 0);
	if (!event) {
		bpf_printk("XDP Summit: ring buffer reserve error");
		return XDP_DROP;
	}
	event->rank = rank;
	// #pragma clang loop unroll(full)
	// for (int i = 0; i < MIN(rinfo->size, MAX_RANK_SIZE); ++i) {
	// 	if (i >= MAX_RANK_SIZE) {
	// 		bpf_printk("XDP Summit: break 2");
	// 		break;
	// 	}
	// 	__builtin_memcpy(event->buff[i], blocks_buff->buff[i], MAX_PACKET_BUF_SIZE * sizeof(int));
	// }
	bpf_ringbuf_submit(event, 0);
	__sync_fetch_and_add(&(rinfo->submitted), 1);
	if (rinfo->finished == 1) {
		bpf_map_delete_elem(&mpi_rank_infos, &rank_sequence_id);
	}
	u64 kernel_time = bpf_ktime_get_ns();
	u32 key = 0;
	u64* start_time = (u64*)bpf_map_lookup_elem(&time_arr, &key);
	if (start_time)
		bpf_printk("Time in kernel: start: %llu; finish: %llu; total %llu.", *start_time, kernel_time, (kernel_time - *start_time)/1000);
	
	if (arhdr->t + 2 >= rinfo->size) {
		if (arhdr->op == OP_ALLGATHER) {
			return XDP_DROP;
		}
		arhdr->op = OP_ALLGATHER;
		arhdr->t = 0;
	} else {
		arhdr->t += 1;
	}
	u32 sendto = rinfo->sendto;
	struct rank_net_info* sendto_net_info = bpf_map_lookup_elem(&net_infos, &sendto);
	if (!sendto_net_info) {
		bpf_printk("XDP ReduceScatter Error: can't find sendto net info");
		return XDP_DROP;
	}
	arhdr->rank = sendto;
	udp->source = udp->dest;
	udp->dest = bpf_htons(ALTER_BEGIN_PORT + sendto);
	udp->check = 0; // computing udp checksum is not required
	
	u32 tmp = sendto_net_info->ip_addr.addr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp;

	// ip_addr.addr = ip->addrs.daddr;
	// bpf_printk("XDP sendto: %u.%u:%u", ip_addr.ip[2], ip_addr.ip[3], bpf_ntohs(udp->dest));
	
	u16 csum = compute_ip_checksum(ip);
	ip->check = csum;
	// 还要更新网卡地址,不然的话redirect的包会在网卡出口处丢弃
	// unsigned char tmp_mac[6];
	// __builtin_memcpy(tmp_mac, eth->h_source, 6);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	// __builtin_memcpy(eth->h_dest, tmp_mac, 6);
	__builtin_memcpy(eth->h_dest, sendto_net_info->mac_addr, ETH_ALEN);

	return bpf_redirect(ctx->ingress_ifindex, 0);
}


SEC("ResendFilter")
int resend_filter_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = (char*)data;
	struct iphdr *ip = (char*)data + sizeof(struct ethhdr);
	struct udphdr *udp = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
	if (udp + 1 > data_end) return XDP_PASS;

	if (payload + sizeof(struct arhdr) > data_end) {
		bpf_printk("XDP resend filter: Payload len to less");
		return XDP_DROP;
	}
	struct arhdr *arhdr = (struct arhdr*)payload;
	
	u32 rank = arhdr->rank;
	u32 sequence_id = arhdr->sequence_id;
	u32 rank_sequence_id = rank_sequence_id_hash(rank, sequence_id);
	struct mpi_rank_info *rinfo = bpf_map_lookup_elem(&mpi_rank_infos, &rank_sequence_id);
	if (!rinfo) {
		bpf_printk("XDP resend filter: Error look up map: %u", rank);
		return XDP_DROP;
	}
	bpf_printk("XDP ResendFilter: %d, %u", rank_sequence_id, arhdr->t);


	unsigned bitmap = arhdr->op == OP_RESEND_RS ? rinfo->bitmap_rs : rinfo->bitmap_ag;
	if (arhdr->op == OP_RESEND_INIT || (bitmap & (1ULL << (arhdr->t)))) {
		bpf_printk("XDP ResendFilter: Resend payload");
		if (arhdr->op == OP_RESEND_INIT)
			bpf_tail_call(ctx, &xdp_progs, XDP_RESEND_INIT);
		else if (arhdr->op == OP_RESEND_RS)
			bpf_tail_call(ctx, &xdp_progs, XDP_RESEND_RS);
		else if (arhdr->op == OP_RESEND_AG)
			bpf_tail_call(ctx, &xdp_progs, XDP_RESEND_AG);
		bpf_printk("XDP ResendFilter: resend payload error: op not match");
		return XDP_DROP;
	}

	struct resend_key key = {0};
	key.op = arhdr->op;
	key.rank = arhdr->rank;
	key.t = arhdr->t;
	u64 curr_timestamp = bpf_ktime_get_ns();
	u64* timestamp = bpf_map_lookup_elem(&resend_timestamp_map, &key);
	if (!timestamp) {
		bpf_map_update_elem(&resend_timestamp_map, &key, &curr_timestamp, BPF_ANY);
	} else {
		u64 time_diff = curr_timestamp - *timestamp;
		if (time_diff < RESEND_THRESHOLD_MS * MS_TO_NS) {
			return TC_ACT_SHOT;
		}
		bpf_map_update_elem(&resend_timestamp_map, &key, &curr_timestamp, BPF_ANY);
	}

	bpf_printk("XDP ResendFilter: ask to prev rank");

	arhdr->rank = rinfo->recvfrom;
	if (arhdr->t == 0 && arhdr->op == OP_RESEND_AG) {
		arhdr->op = OP_RESEND_RS;
		arhdr->t = rinfo->size - 2;
	} else if (arhdr->t == 0 && arhdr->op == OP_RESEND_RS) {
		arhdr->op = OP_RESEND_INIT;
	} else {
		arhdr->t -= 1;
	}

	u32 recvfrom = rinfo->recvfrom;
	struct rank_net_info* recvfrom_net_info = bpf_map_lookup_elem(&net_infos, &recvfrom);
	if (!recvfrom_net_info) {
		bpf_printk("XDP ReduceScatter Error: can't find sendto net info");
		return XDP_DROP;
	}

	udp->source = udp->dest;
	udp->dest = bpf_htons(ALTER_BEGIN_PORT + rinfo->recvfrom);
	udp->check = 0; // computing udp checksum is not required
	
	u32 tmp = recvfrom_net_info->ip_addr.addr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp;

	u16 csum = compute_ip_checksum(ip);
	ip->check = csum;
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest,recvfrom_net_info->mac_addr, ETH_ALEN);
	return bpf_redirect(ctx->ingress_ifindex, 0);
	// return XDP_TX;
}


SEC("ResendInit")
int resend_init_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = (char*)data;
	struct iphdr *ip = (char*)data + sizeof(struct ethhdr);
	struct udphdr *udp = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
	if (udp + 1 > data_end) return XDP_PASS;
	if (payload + sizeof(struct arhdr) > data_end) {
		bpf_printk("XDP ResendInit: Payload len to less");
		return XDP_DROP;
	}
	struct arhdr *arhdr = (struct arhdr*)payload;
	payload += sizeof(struct arhdr);

	u32 rank = arhdr->rank;
	u32 rank_sequence_id = rank_sequence_id_hash(rank, arhdr->sequence_id);
	struct mpi_rank_info *rinfo = bpf_map_lookup_elem(&mpi_rank_infos, &rank);
	if (!rinfo) {
		bpf_printk("XDP ResendInit: Error look up map rank_infos: %u", rank_sequence_id);
		return XDP_DROP;
	}
	struct data_blocks_buff *blocks_buff = bpf_map_lookup_elem(&data_blocks, &rank_sequence_id);
	if (!blocks_buff) {
		bpf_printk("XDP ResendInit: Error look up map data_blocks: %u", rank_sequence_id);
		return XDP_DROP;
	}
	unsigned int recv_block_id = rank;
	int block_count = rinfo->count;
	if ((void*)(payload + MIN(block_count, MAX_BUF_SIZE) * sizeof(int)) > data_end) {
		return XDP_DROP;
	}

	if (recv_block_id >= MAX_RANK_SIZE)
		return XDP_DROP;
	if (recv_block_id < 0)
		return XDP_DROP;

	#pragma clang loop unroll(full)
	for (int i = 0; i < MIN(block_count, MAX_BUF_SIZE); ++i) {
		if ((void*)(payload + i * sizeof(int) + sizeof(int)) > data_end) {
			break;
		}
		if (i >= MAX_BUF_SIZE) {
			break;
		}
		*((int*)(payload + i * sizeof(int))) = blocks_buff->buff[recv_block_id][i];
	}

	arhdr->op = OP_REDUCESCATTER;
	arhdr->rank = rinfo->sendto;
	arhdr->t = 0;

	u32 sendto = rinfo->sendto;
	struct rank_net_info* sendto_net_info = bpf_map_lookup_elem(&net_infos, &sendto);
	if (!sendto_net_info) {
		bpf_printk("XDP ReduceScatter Error: can't find sendto net info");
		return XDP_DROP;
	}

	udp->source = udp->dest;
	udp->dest = bpf_htons(ALTER_BEGIN_PORT + rinfo->sendto);
	udp->check = 0; // computing udp checksum is not required
	
	// 后续还要修改为recv的ip地址,这里的ip地址并不准确
	u32 tmp = sendto_net_info->ip_addr.addr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp;
	u16 csum = compute_ip_checksum(ip);
	ip->check = csum;

	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, sendto_net_info->mac_addr, ETH_ALEN);

	return bpf_redirect(ctx->ingress_ifindex, 0);
	// return XDP_TX;
}


SEC("ResendRS")
int resend_rs_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = (char*)data;
	struct iphdr *ip = (char*)data + sizeof(struct ethhdr);
	struct udphdr *udp = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
	if (udp + 1 > data_end) return XDP_PASS;
	if (payload + sizeof(struct arhdr) > data_end) {
		bpf_printk("XDP ResendRS: Payload len to less");
		return XDP_DROP;
	}
	struct arhdr *arhdr = (struct arhdr*)payload;
	payload += sizeof(struct arhdr);

	u32 rank = arhdr->rank;
	u32 sequence_id = arhdr->sequence_id;
	u32 rank_sequence_id = rank_sequence_id_hash(rank, sequence_id);
	u32 t = arhdr->t;
	struct mpi_rank_info *rinfo = bpf_map_lookup_elem(&mpi_rank_infos, &rank_sequence_id);
	if (!rinfo) {
		bpf_printk("XDP ResendRS: Error look up map rank_infos: %u", rank_sequence_id);
		return XDP_DROP;
	}
	struct data_blocks_buff *blocks_buff = bpf_map_lookup_elem(&data_blocks, &rank_sequence_id);
	if (!blocks_buff) {
		bpf_printk("XDP ResendRS: Error look up map data_blocks: %u", rank_sequence_id);
		return XDP_DROP;
	}
	unsigned int recv_block_id = (rank - t - 1 + rinfo->size) % rinfo->size;
	int block_count = rinfo->count;
	if ((void*)(payload + MIN(block_count, MAX_BUF_SIZE) * sizeof(int)) > data_end) {
		return XDP_DROP;
	}

	bpf_printk("XDP ResendRS: rank: %d, t: %u", rank_sequence_id, t);

	if (recv_block_id >= MAX_RANK_SIZE)
		return XDP_DROP;
	if (recv_block_id < 0)
		return XDP_DROP;

	#pragma clang loop unroll(full)
	for (int i = 0; i < MIN(block_count, MAX_BUF_SIZE); ++i) {
		if ((void*)(payload + i * sizeof(int) + sizeof(int)) > data_end) {
			break;
		}
		if (i >= MAX_BUF_SIZE) {
			break;
		}
		*((int*)(payload + i * sizeof(int))) = blocks_buff->buff[recv_block_id][i];
	}

	if (t + 2 >= rinfo->size) {
		// bpf_printk("rank %d: XDP Finished", rank);
		arhdr->op = OP_ALLGATHER;
		arhdr->rank = rinfo->sendto;
		arhdr->t = 0;
		// bpf_tail_call(ctx, &xdp_progs, XDP_ALLGATHER);
		// return XDP_DROP;
	} else {
		arhdr->op = OP_REDUCESCATTER;
		arhdr->t += 1;
		arhdr->rank = rinfo->sendto;
	}

	u32 sendto = rinfo->sendto;
	struct rank_net_info* sendto_net_info = bpf_map_lookup_elem(&net_infos, &sendto);
	if (!sendto_net_info) {
		bpf_printk("XDP ReduceScatter Error: can't find sendto net info");
		return XDP_DROP;
	}

	udp->source = udp->dest;
	udp->dest = bpf_htons(ALTER_BEGIN_PORT + sendto);
	udp->check = 0; // computing udp checksum is not required
	
	// 后续还要修改为recv的ip地址,这里的ip地址并不准确
	u32 tmp = sendto_net_info->ip_addr.addr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp;
	u16 csum = compute_ip_checksum(ip);
	ip->check = csum;

	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, sendto_net_info->mac_addr, ETH_ALEN);

	return bpf_redirect(ctx->ingress_ifindex, 0);
	// return XDP_TX;
}


SEC("ResendAG")
int resend_ag_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = (char*)data;
	struct iphdr *ip = (char*)data + sizeof(struct ethhdr);
	struct udphdr *udp = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
	if (udp + 1 > data_end) return XDP_PASS;
	if (payload + sizeof(struct arhdr) > data_end) {
		bpf_printk("XDP ResendAG: Payload len to less");
		return XDP_DROP;
	}
	struct arhdr *arhdr = (struct arhdr*)payload;
	payload += sizeof(struct arhdr);

	u32 rank = arhdr->rank;
	u32 sequence_id = arhdr->sequence_id;
	u32 rank_sequence_id = rank_sequence_id_hash(rank, sequence_id);
	u32 t = arhdr->t;
	struct mpi_rank_info *rinfo = bpf_map_lookup_elem(&mpi_rank_infos, &rank_sequence_id);
	if (!rinfo) {
		bpf_printk("XDP ResendAG: Error look up map rank_infos: %u", rank);
		return XDP_DROP;
	}
	struct data_blocks_buff *blocks_buff = bpf_map_lookup_elem(&data_blocks, &rank_sequence_id);
	if (!blocks_buff) {
		bpf_printk("XDP ResendAG: Error look up map data_blocks: %u", rank);
		return XDP_DROP;
	}
	unsigned int recv_block_id = (rank - t + rinfo->size) % rinfo->size;
	int block_count = rinfo->count;
	if ((void*)(payload + MIN(block_count, MAX_BUF_SIZE) * sizeof(int)) > data_end) {
		return XDP_DROP;
	}

	bpf_printk("XDP ResendAG: rank: %d, t: %u", rank_sequence_id, t);

	if (recv_block_id >= MAX_RANK_SIZE)
		return XDP_DROP;
	if (recv_block_id < 0)
		return XDP_DROP;

	#pragma clang loop unroll(full)
	for (int i = 0; i < MIN(block_count, MAX_BUF_SIZE); ++i) {
		if ((void*)(payload + i * sizeof(int) + sizeof(int)) > data_end) {
			break;
		}
		if (i >= MAX_BUF_SIZE) {
			break;
		}
		*((int*)(payload + i * sizeof(int))) = blocks_buff->buff[recv_block_id][i];
	}

	
	arhdr->t += 1;
	arhdr->rank = rinfo->sendto;
	arhdr->op = OP_ALLGATHER;

	u32 sendto = rinfo->sendto;
	struct rank_net_info* sendto_net_info = bpf_map_lookup_elem(&net_infos, &sendto);
	if (!sendto_net_info) {
		bpf_printk("XDP ReduceScatter Error: can't find sendto net info");
		return XDP_DROP;
	}

	udp->source = udp->dest;
	udp->dest = bpf_htons(ALTER_BEGIN_PORT + sendto);
	udp->check = 0; // computing udp checksum is not required
	
	// 后续还要修改为recv的ip地址,这里的ip地址并不准确
	u32 tmp = sendto_net_info->ip_addr.addr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp;
	u16 csum = compute_ip_checksum(ip);
	ip->check = csum;

	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, sendto_net_info->mac_addr, ETH_ALEN);

	return bpf_redirect(ctx->ingress_ifindex, 0);
	// return XDP_TX;
}


// attach in tc ingress
SEC("ResendGen")
int resendGen_main(struct __sk_buff *skb) {
	void *data_end = (void*)(long)skb->data_end;
	void *data = (void*)(long)skb->data;
	void *data_meta = (void*)(long)skb->data_meta;
	struct ethhdr *eth = (char*)data;
	struct iphdr *ip = (char*)data + sizeof(struct ethhdr);
	struct udphdr *udp = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
	struct resend_meta* meta = data_meta;

	if (ip + 1 > data_end) return TC_ACT_OK;
	if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;
	if (udp + 1 > data_end) return TC_ACT_OK;

	// 由于这里是egress，所以我们计算port的时候使用是udp->dest
	int vaild_port_range = bpf_ntohs(udp->dest) - ALTER_BEGIN_PORT;
	if (vaild_port_range < 0 || vaild_port_range > ALTER_PORT_RANGE)
		return TC_ACT_OK;
	
	// 使用unsigned，防止符号拓展
	if (payload + sizeof(struct arhdr) > data_end) return TC_ACT_OK;

	struct arhdr *arhdr = (struct arhdr*)payload;
	payload += sizeof(struct arhdr);
	if (arhdr->magic_num[0] != 0x42 || arhdr->magic_num[1] != 0x60  || arhdr->magic_num[2] != 0x80 || arhdr->magic_num[3] != 0x02) {
		return TC_ACT_OK;
	}
	if (arhdr->op != OP_GEN_RESEND)
		return TC_ACT_SHOT;

	if (meta + 1 > data) {
		bpf_printk("ResendGen Error: no meta data");
		return TC_ACT_SHOT;
	}

	int rank = meta->curr_rank;
	int sequence_id = meta->curr_sequence_id;
	int rank_sequence_id = rank_sequence_id_hash(rank, sequence_id);
	struct mpi_rank_info* rinfo = bpf_map_lookup_elem(&mpi_rank_infos, &rank_sequence_id);
	if (!rinfo) {
		bpf_printk("ResendGen: error in looking up bpf map");
		return TC_ACT_SHOT;
	}

	// resend packet
	unsigned char mac_src[6];
	u32 ip_src;
	u16 udp_src;
	arhdr->op = meta->resend_op;
	arhdr->t = meta->resend_t;
	arhdr->rank = rinfo->recvfrom;

	u32 recvfrom = rinfo->recvfrom;
	struct rank_net_info* recvfrom_net_info = bpf_map_lookup_elem(&net_infos, &recvfrom);
	if (!recvfrom_net_info) {
		bpf_printk("XDP ReduceScatter Error: can't find sendto net info");
		return XDP_DROP;
	}

	udp_src = udp->dest;
	udp->source = udp_src;
	udp->dest = bpf_htons(ALTER_BEGIN_PORT + rinfo->recvfrom);
	udp->check = 0;
	ip_src = ip->daddr;
	ip->saddr = ip_src;
	ip->daddr = recvfrom_net_info->ip_addr.addr;
	ip->check = compute_ip_checksum(ip);
	__builtin_memcpy(mac_src, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_source, mac_src, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, recvfrom_net_info->mac_addr, ETH_ALEN);
	int op = meta->op, t = meta->t;
	bpf_clone_redirect(skb, REDIRECT_DEV, 0);
	
	// 前面调用了 clone redirect，所以需要设置data_end的值
	if (op == OP_FINIAL)
		return TC_ACT_SHOT;
	data_end = (void*)(long)skb->data_end;
	data = (void*)(long)skb->data;
	eth = data;
	ip = data + sizeof(struct ethhdr);
	udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
	
	if (ip + 1 > data_end) return TC_ACT_SHOT;
	if (ip->protocol != IPPROTO_UDP) return TC_ACT_SHOT;
	if (udp + 1 > data_end) return TC_ACT_SHOT;
	if (payload + sizeof(struct arhdr) > data_end) { 
		bpf_printk("Error in tc ingress: resend gen, payload too less");
		return TC_ACT_SHOT; 
	}
	arhdr = (struct arhdr*)payload;

	// 原数据包直接转发出去
	arhdr->op = op;
	arhdr->rank = rinfo->sendto;
	arhdr->t = t;

	u32 sendto = rinfo->sendto;
	struct rank_net_info* sendto_net_info = bpf_map_lookup_elem(&net_infos, &sendto);
	if (!sendto_net_info) {
		bpf_printk("XDP ReduceScatter Error: can't find sendto net info");
		return XDP_DROP;
	}

	udp->source = udp_src;
	udp->dest = bpf_htons(ALTER_BEGIN_PORT + sendto);
	udp->check = 0; // computing udp checksum is not required
	u32 tmp = sendto_net_info->ip_addr.addr;
	ip->saddr = ip_src;
	ip->daddr = tmp;
	u16 csum = compute_ip_checksum(ip);
	ip->check = csum;
	__builtin_memcpy(eth->h_source, mac_src, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, sendto_net_info->mac_addr, ETH_ALEN);
	bpf_printk("TC ingress: resend gen: rank: %d, t: %u, op: %u", rank, t, op);
	return bpf_redirect(skb->ifindex, 0);
	// return XDP_TX;
}

// attach in tc egress
SEC("EarlyPacket")
int early_packet_main(struct __sk_buff *skb) {
	void *data_end = (void*)(long)skb->data_end;
	void *data = (void*)(long)skb->data;
	void *data_meta = (void*)(long)skb->data_meta;
	struct ethhdr *eth = (char*)data;
	struct iphdr *ip = (char*)data + sizeof(struct ethhdr);
	struct udphdr *udp = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
	struct resend_meta* meta = data_meta;

	if (ip + 1 > data_end) return TC_ACT_OK;
	if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;
	if (udp + 1 > data_end) return TC_ACT_OK;

	// 由于这里是egress，所以我们计算port的时候使用是udp->dest
	int vaild_port_range = bpf_ntohs(udp->dest) - ALTER_BEGIN_PORT;
	if (vaild_port_range < 0 || vaild_port_range > ALTER_PORT_RANGE)
		return TC_ACT_OK;
	
	// 使用unsigned，防止符号拓展
	if (payload + sizeof(struct arhdr) > data_end) return TC_ACT_OK;

	struct arhdr *arhdr = (struct arhdr*)payload;
	payload += sizeof(struct arhdr);
	if (arhdr->magic_num[0] != 0x42 || arhdr->magic_num[1] != 0x60  || arhdr->magic_num[2] != 0x80 || arhdr->magic_num[3] != 0x02) {
		return TC_ACT_OK;
	}
	if (arhdr->op != OP_REDUCESCATTER_EARLY)
		return TC_ACT_SHOT;
	
	u32 rank = arhdr->rank;
	u32 sequence_id = arhdr->sequence_id;
	u32 rank_sequence_id = rank_sequence_id_hash(rank, sequence_id);
	u32 t = arhdr->t;
	struct mpi_rank_info* rinfo = bpf_map_lookup_elem(&mpi_rank_infos, &rank_sequence_id);
	if (!rinfo) {
		bpf_printk("EarlyPacket: error in looking up bpf map rank_infos");
		return TC_ACT_SHOT;
	}
	struct data_blocks_buff *blocks_buff = bpf_map_lookup_elem(&data_blocks, &rank_sequence_id);
	if (!blocks_buff) {
		bpf_printk("EarlyPacket: error in looking up bpf map data_blocks");
		return TC_ACT_SHOT;
	}

	unsigned int recv_block_id = (rank - t - 1 + rinfo->size) % rinfo->size;
	int block_count = rinfo->count;
	if ((void*)(payload + MIN(block_count, MAX_BUF_SIZE) * sizeof(int)) > data_end) {
		return XDP_DROP;
	}

	bpf_printk("TC EarlyPacket: rank: %d, t: %u", rank_sequence_id, t);

	__sync_fetch_and_or(&(rinfo->bitmap_rs), (1ull << t));
	__sync_fetch_and_add(&(rinfo->bitmap_cnt), 1);

	if (recv_block_id >= MAX_RANK_SIZE)
		return XDP_DROP;
	if (recv_block_id < 0)
		return XDP_DROP;

	#pragma clang loop unroll(full)
	for (int i = 0; i < MIN(block_count, MAX_BUF_SIZE); ++i) {
		if ((void*)(payload + i * sizeof(int) + sizeof(int)) > data_end) {
			break;
		}
		if (i >= MAX_BUF_SIZE) {
			break;
		}
		blocks_buff->buff[recv_block_id][i] = *((int*)(payload + i * sizeof(int)));
	}

	if (t + 2 >= rinfo->size) {
		arhdr->op = OP_ALLGATHER;
		arhdr->rank = rinfo->sendto;
		arhdr->t = 0;
	} else {
		arhdr->op = OP_REDUCESCATTER;
		arhdr->t += 1;
		arhdr->rank = rinfo->sendto;
	}
	udp->check = 0;

	if (rinfo->bitmap_cnt >= rinfo->size * 2 - 2) {
		struct submit_event *event = NULL;
		event = bpf_ringbuf_reserve(&submit_rb, sizeof(struct submit_event), 0);
		if (event) {
			event->rank = rank;
			bpf_ringbuf_submit(event, 0);
		} else {
			bpf_printk("TC Summit: ring buffer reserve error in early packet process.");
		}
	}
	return TC_ACT_OK;
}

#ifdef FINISH
// 结束阶段，向recvfrom发送一个finish包，通知recvfrom自己的allreduce已经完成，可以释放本地map的资源了。
SEC("Finish")
int finish_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = (char*)data;
	struct iphdr *ip = (char*)data + sizeof(struct ethhdr);
	struct udphdr *udp = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
	if (udp + 1 > data_end) return XDP_PASS;
	if (payload + sizeof(struct arhdr) > data_end) {
		bpf_printk("XDP finish: Payload len to less");
		return XDP_DROP;
	}
	struct arhdr *arhdr = (struct arhdr*)payload;
	payload += sizeof(struct arhdr);

	u32 rank = arhdr->rank;
	u32 sequence_id = arhdr->sequence_id;
	u32 rank_sequence_id = rank_sequence_id_hash(rank, sequence_id);
	struct mpi_rank_info *rinfo = bpf_map_lookup_elem(&mpi_rank_infos, &rank_sequence_id);
	if (!rinfo) {
		bpf_printk("XDP finish: Error look up map: %u", rank);
		return XDP_DROP;
	}
	bpf_printk("XDP: finish, rank: %d", rank);
	rinfo->finished = 1;
	int is_clean = 0;
	if (rinfo->submitted == 1 && rinfo->finished == 1) {
		rinfo->valided = 0;
		rinfo->bitmap_cnt = 0;
		rinfo->bitmap_rs = 0;
		rinfo->bitmap_ag = 0;
		is_clean = 1;

		struct finish_event *event = NULL;
		event = bpf_ringbuf_reserve(&finish_rb, sizeof(struct finish_event), 0);
		if (!event) {
			bpf_printk("XDP Finish: finish ring buffer reserve error");
			return XDP_DROP;
		}
		event->rank = rank;
		bpf_ringbuf_submit(event, 0);
		bpf_printk("XDP finish: submit to finish_rb");
	}

	if (arhdr->op == OP_FINISH_CLEAN) {
		struct clean_event *event = NULL;
		event = bpf_ringbuf_reserve(&clean_rb, sizeof(struct clean_event), 0);
		if (!event) {
			bpf_printk("XDP finish: clean ring buffer reserve error");
			return XDP_DROP;
		}
		event->rank = rank;
		bpf_ringbuf_submit(event, 0);
		bpf_printk("XDP finish: submit to clean_rb");
	}

	if (!is_clean) {
		return XDP_DROP;
	}

	arhdr->op = OP_CLEAN;
	arhdr->rank = rinfo->recvfrom;

	udp->source = udp->dest;
	udp->dest = bpf_htons(ALTER_BEGIN_PORT + rinfo->recvfrom);
	udp->check = 0; // computing udp checksum is not required
	
	u32 tmp = rinfo->recvfrom_addr.addr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp;

	u16 csum = compute_ip_checksum(ip);
	ip->check = csum;
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, rinfo->recvfrom_mac, ETH_ALEN);
	return bpf_redirect(ctx->ingress_ifindex, 0);
}


SEC("FinishQuery")
int finish_query_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = (char*)data;
	struct iphdr *ip = (char*)data + sizeof(struct ethhdr);
	struct udphdr *udp = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
	if (udp + 1 > data_end) return XDP_PASS;
	if (payload + sizeof(struct arhdr) > data_end) {
		bpf_printk("XDP finish: Payload len to less");
		return XDP_DROP;
	}
	struct arhdr *arhdr = (struct arhdr*)payload;
	payload += sizeof(struct arhdr);

	u32 rank = arhdr->rank;
	u32 sequence_id = arhdr->sequence_id;
	u32 rank_sequence_id = rank_sequence_id_hash(rank, sequence_id);
	struct mpi_rank_info *rinfo = bpf_map_lookup_elem(&mpi_rank_infos, &rank_sequence_id);
	if (!rinfo) {
		bpf_printk("XDP finish: Error look up map: %u", rank);
		return XDP_DROP;
	}
	if (!rinfo->submitted) {
		return XDP_DROP;
	}

	arhdr->op = OP_FINISH;
	arhdr->rank = rinfo->recvfrom;

	udp->source = udp->dest;
	udp->dest = bpf_htons(ALTER_BEGIN_PORT + rinfo->recvfrom);
	udp->check = 0; // computing udp checksum is not required
	
	u32 tmp = rinfo->recvfrom_addr.addr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp;

	u16 csum = compute_ip_checksum(ip);
	ip->check = csum;
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, rinfo->recvfrom_mac, ETH_ALEN);
	return bpf_redirect(ctx->ingress_ifindex, 0);
}


SEC("Clean")
int clean_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = (char*)data;
	struct iphdr *ip = (char*)data + sizeof(struct ethhdr);
	struct udphdr *udp = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
	if (udp + 1 > data_end) return XDP_PASS;
	if (payload + sizeof(struct arhdr) > data_end) {
		bpf_printk("XDP clean: Payload len to less");
		return XDP_DROP;
	}
	struct arhdr *arhdr = (struct arhdr*)payload;
	payload += sizeof(struct arhdr);

	u32 rank = arhdr->rank;
	struct clean_event *event = NULL;
	event = bpf_ringbuf_reserve(&clean_rb, sizeof(struct clean_event), 0);
	if (!event) {
		bpf_printk("XDP Clean: clean ring buffer reserve error");
		return XDP_DROP;
	}
	event->rank = rank;
	bpf_ringbuf_submit(event, 0);
	bpf_printk("XDP clean: submit to clean_rb");
	return XDP_DROP;
}


SEC("CleanQuery")
int clean_query_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = (char*)data;
	struct iphdr *ip = (char*)data + sizeof(struct ethhdr);
	struct udphdr *udp = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = (char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
	if (udp + 1 > data_end) return XDP_PASS;
	if (payload + sizeof(struct arhdr) > data_end) {
		bpf_printk("XDP finish: Payload len to less");
		return XDP_DROP;
	}
	struct arhdr *arhdr = (struct arhdr*)payload;
	payload += sizeof(struct arhdr);

	u32 rank = arhdr->rank;
	u32 sequence_id = arhdr->sequence_id;
	u32 rank_sequence_id = rank_sequence_id_hash(rank, sequence_id);
	struct mpi_rank_info *rinfo = bpf_map_lookup_elem(&mpi_rank_infos, &rank_sequence_id);
	if (!rinfo) {
		bpf_printk("XDP finish: Error look up map: %u", rank);
		return XDP_DROP;
	}
	if (!rinfo->submitted || !rinfo->finished) {
		return XDP_DROP;
	}

	arhdr->op = OP_CLEAN;
	arhdr->rank = rinfo->recvfrom;

	udp->source = udp->dest;
	udp->dest = bpf_htons(ALTER_BEGIN_PORT + rinfo->recvfrom);
	udp->check = 0; // computing udp checksum is not required
	
	u32 tmp = rinfo->recvfrom_addr.addr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp;

	u16 csum = compute_ip_checksum(ip);
	ip->check = csum;
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, rinfo->recvfrom_mac, ETH_ALEN);
	return bpf_redirect(ctx->ingress_ifindex, 0);
}
#endif

#ifdef XDP_SUMMIT_AFXDP
SEC("Summit")
int summit_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	u8 *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
	if (udp + 1 > data_end) return XDP_PASS;
	
	int vaild_port_range = bpf_ntohs(udp->dest) - ALTER_BEGIN_PORT;
	if (vaild_port_range > ALTER_PORT_RANGE || vaild_port_range < 0)
		return XDP_PASS;

	if (payload + sizeof(struct arhdr) > data_end) {
		bpf_printk("XDP Summit: Len to less");
		return XDP_DROP;
	}
	if (sizeof(struct arhdr) != MIN_PAYLOAD_LEN)
		bpf_printk("XDP Summit: Error");
	struct arhdr *arhdr = (struct arhdr*)payload;
	payload += sizeof(struct arhdr);
	if (arhdr->magic_num[0] != 0x42 || arhdr->magic_num[1] != 0x60  || arhdr->magic_num[2] != 0x80 || arhdr->magic_num[3] != 0x02) {
		bpf_printk("XDP Summit: not magic num");
		return XDP_DROP;
	}

	u32 rank = arhdr->rank;
	struct mpi_rank_info *rinfo = bpf_map_lookup_elem(&mpi_rank_infos, &rank);
	if (!rinfo) {
		bpf_printk("XDP Summit: Error look up map: %u", rank);
		return XDP_DROP;
	}

	u32 count = rinfo->count;
	u32 offset = 0;
	// bpf_printk("XDP Summit: Begin copying to packet: %d, %d", (char*)data_end - (char*)udp, bpf_ntohs(udp->len));
	#pragma clang loop unroll(full)
	for (int i = 0; i < MIN(rinfo->size, MAX_RANK_SIZE); ++i) {
		// if (count <= 0)
		// 	return XDP_DROP;
		// if (count >= MAX_BUF_SIZE)
		// 	return XDP_DROP;
		if (payload > data_end || payload + MAX_PACKET_BUF_SIZE * sizeof(int) > data_end) {
			bpf_printk("XDP Summit: break 1");
			break;
		}
		if (i >= MAX_RANK_SIZE) {
			bpf_printk("XDP Summit: break 2");
			break;
		}
		// bpf_xdp_store_bytes(ctx, offset, rinfo->buff[i], count * sizeof(int));
		// bpf_probe_read_kernel(payload, count * sizeof(int), rinfo->buff[i]);
		__builtin_memcpy(payload, rinfo->buff[i], MAX_PACKET_BUF_SIZE * sizeof(int));
		payload += MAX_PACKET_BUF_SIZE * sizeof(int);

		// #pragma clang loop unroll(full)
		// for (int j = 0; j < MIN(rinfo->count, MAX_BUF_SIZE); ++j) {
		// 	offset = i * rinfo->size + j;
		// 	if ((void*)(payload + offset * sizeof(int) + sizeof(int)) > data_end) {
		// 		bpf_printk("rank %d: XDP Allgather break 1: %d", rank, data_end-(void*)payload);
		// 		return XDP_PASS;
		// 	}
		// 	if (j >= MAX_BUF_SIZE) {
		// 		bpf_printk("rank %d: XDP Allgather break 2", rank);
		// 		return XDP_DROP;
		// 	}
		// 	*((int*)(payload + offset * sizeof(int))) = (rinfo->buff[i][j]);
		// }
	}
	// bpf_printk("XDP Summit: After copying to packet: %d, %d", bpf_ntohs(ip->tot_len), rank);
	u16 csum = compute_ip_checksum(ip);
	ip->check = csum;
	u64 kernel_time = bpf_ktime_get_ns();
	u32 key = 0;
	u64* start_time = (u64*)bpf_map_lookup_elem(&time_arr, &key);
	if (start_time)
		bpf_printk("Time in kernel: start: %llu; finish: %llu; total %llu.", *start_time, kernel_time, (kernel_time - *start_time)/1000000);
		

	return bpf_redirect_map(&xsks_map, rank, XDP_DROP);
}
#endif



char __license[] SEC("license") = "GPL";