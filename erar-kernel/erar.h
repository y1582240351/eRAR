#ifndef ERAR_H
#define MPI_REDUCE_H

#define ARMPI_PROG_TC_SEND 0
#define ARMPI_PROG_TC_RESENDGEN 1
#define MAX_BLOCK_SIZE 16
#define MAX_RANK_SIZE 32
#define MAX_BUF_SIZE 1024
#define MAX_PACKET_BUF_SIZE 32
#define BITMAP_ELEM_SIZE (sizeof(unsigned long long) * 8)
#define BITMAP_LEN 3
#define BITMPA_SIZE (BITMAP_ELEM_SIZE * 3)
struct mpi_rank_info {
	int sendto; // send rank
	int recvfrom; // recv rank
	int size; // num of comm_ranks
	long count; // num of elems in a block
	// int elem_size;
	unsigned long long bitmap_rs;
	unsigned long long bitmap_ag;
	// unsigned int record; // record 记录的是arhdr中的t值，而bitmap记录的是那个block完成聚合，这个似乎有点问题，可以改进一下。
	unsigned int bitmap_cnt;
	int valided;
	int submitted;
	int finished;
	struct bpf_spin_lock lock;
};


struct rank_net_info {
	union {
        unsigned int addr;
        unsigned char ip[4];
    } ip_addr;
	unsigned char mac_addr[6];
};


// the header of allreduce payload
struct arhdr {
	unsigned char magic_num[4];
	unsigned int op;
	unsigned int rank;
	unsigned int sequence_id;
	unsigned int t; // the counter of gather-reduce and all-gather
} __attribute__((aligned(4)));

// struct allreduce_rank_bitmaps {
// 	unsigned long long bitmap_rs;
// 	unsigned long long bitmap_ag;
// 	// unsigned int record; // record 记录的是arhdr中的t值，而bitmap记录的是那个block完成聚合，这个似乎有点问题，可以改进一下。
// 	unsigned int bitmap_cnt;
// };

struct data_blocks_buff {
	int buff[MAX_RANK_SIZE][MAX_BUF_SIZE];
};

struct mpi_tmp_buff {
	unsigned long long bitmap_rs;
	int buff[MAX_RANK_SIZE][MAX_BUF_SIZE];
};

enum {
	XDP_ALLGATHER = 0,
	XDP_SUMMIT = 1,
	XDP_RESEND_FILTER = 2,
	XDP_RESEND_INIT = 3,
	XDP_RESEND_RS = 4,
	XDP_RESEND_AG = 5,
	XDP_FINISH = 6,
	XDP_FINISH_QUERY = 7,
	XDP_CLEAN = 8,
	XDP_CLEAN_QUERY = 9,
};

struct submit_event {
	// int buf[MAX_RANK_SIZE][MAX_BUF_SIZE];
	int rank;
};

struct finish_event {
	int rank;
};

struct clean_event {
	int rank;
};
#endif