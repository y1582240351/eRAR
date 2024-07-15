#ifndef EBPF_HELPER_H
#define EBPF_HELPER_H

#include "mpiimpl.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <time.h>

#define MAX_RANK_SIZE 32
#define MAX_BUF_SIZE 1024
#define MAX_REQUEST_SIZE 2048

#define OP_REDUCESCATTER 0
#define OP_ALLGATHER 1
#define OP_RESEND_RS 2
#define OP_RESEND_AG 3
#define OP_RESEND_INIT 4
#define OP_GEN_RESEND 5
#define OP_FINIAL 6
#define OP_FINISH 7
#define OP_REDUCESCATTER_EARLY 8
#define OP_FINISH_QUERY 9
#define OP_CLEAN 10
#define OP_CLEAN_QUERY 11

#define NOTRESEND 0
#define RESEND_RS 1
#define RESEND_AG 2

#define RESEND_INTERVAL 100000 // ms
#define QUERY_FINISH_INTERVAL 1000

#define FINISH_MSG_PORT 12890
#define FLOAT_BASE 100000000

#define MIN(a, b) ((a) > (b)) ? (b) : (a)
#define ALTER_BEGIN_PORT 18400

int curr_sequence_id = 0;
int is_float = false;

struct mpi_rank_info
{
    int sendto;   // send rank
    int recvfrom; // recv rank
    int size;     // num of comm_ranks
    long count;   // num of elems in a block
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

struct rank_net_info
{
    union
    {
        unsigned int addr;
        unsigned char ip[4];
    } ip_addr;
    unsigned char mac_addr[6];
};

struct data_blocks_buff
{
    int buff[MAX_RANK_SIZE][MAX_BUF_SIZE];
};

struct mpi_tmp_buff
{
    unsigned long long bitmap_rs;
    int buff[MAX_RANK_SIZE][MAX_BUF_SIZE];
};

// the header of allreduce payload
struct arhdr
{
    unsigned char magic_num[4];
    unsigned int op;
    unsigned int rank;
    unsigned int sequence_id;
    unsigned int t; // the counter of gather-reduce and all-gather
} __attribute__((aligned(4)));

static inline unsigned int rank_sequence_id_hash(unsigned int rank, unsigned int sequence_id)
{
    return sequence_id * MAX_RANK_SIZE + rank;
}

static bool rb_poll_done = false;
int submit_rank = 0;
static void int_exit(int sig)
{
    rb_poll_done = true;
}

struct submit_event
{
    // int buff[MAX_RANK_SIZE][MAX_BUF_SIZE];
    int rank;
};
static int event_handler(void *_ctx, void *data, size_t size)
{
    rb_poll_done = true;
    const struct submit_event *e = data;
    submit_rank = e->rank;
    // 这里还要修改，ring-buffer 中的结构体应该包含rank、sequence和用户态recvbuff的地址。其中recvbuff要先保存在rinfo中。
    return 0;
}

static bool finish_done = false;
struct finish_event
{
    int rank;
};
static int finish_handler(void *_ctx, void *data, size_t size)
{
    finish_done = true;
    return 0;
}

static bool clean_done = false;
struct clean_event
{
    int rank;
};
static int clean_handler(void *_ctx, void *data, size_t size)
{
    clean_done = true;
    return 0;
}

int blocks_buff_fd;
int ar_rank_infos_fd;
int mpi_rank_tmp_buff_fd;
int submit_rb_fd;
struct sockaddr_in sendAddr, recvAddr;
int init_sockfd;
int finish_socket_fd;
int listen_sockfd;
struct data_blocks_buff blocks_buff;

int has_initialed = false;
int init(int rank, int sendto, int recvfrom)
{
    ar_rank_infos_fd = bpf_obj_get("/sys/fs/bpf/mpi_rank_infos");
    if (ar_rank_infos_fd <= 0)
    {
        fprintf(stderr, "Error in bpf allreduce: error in obj get: /sys/fs/bpf/mpi_rank_infos\n");
        return 1;
    }
    blocks_buff_fd = bpf_obj_get("/sys/fs/bpf/data_blocks");
    if (blocks_buff_fd <= 0)
    {
        fprintf(stderr, "Error in bpf allreduce: error in obj get: /sys/fs/bpf/data_blocks\n");
        return 1;
    }

    int net_infos_fd = bpf_obj_get("/sys/fs/bpf/net_infos");
    if (net_infos_fd <= 0)
    {
        fprintf(stderr, "Error in bpf allreduce: error in obj get: /sys/fs/bpf/net_infos\n");
        return 1;
    }
    struct rank_net_info sendto_net_info = {0}, recv_net_info = {0};
    if (bpf_map_lookup_elem(net_infos_fd, &sendto, &sendto_net_info))
    {
        fprintf(stderr, "Error: bpf map lookup failed: net_infos, rank: %d, sendto: %d\n", rank, sendto);
        return 1;
    }

    if (bpf_map_lookup_elem(net_infos_fd, &recvfrom, &recv_net_info))
    {
        fprintf(stderr, "Error: bpf map lookup failed: net_infos, rank: %d, recvfrom: %d\n", rank, recvfrom);
        return 1;
    }


    mpi_rank_tmp_buff_fd = bpf_obj_get("/sys/fs/bpf/rank_tmp_buff");
    if (mpi_rank_tmp_buff_fd <= 0)
    {
        fprintf(stderr, "Error: bpf_obj_get failed: /sys/fs/bpf/rank_tmp_buff. rank: %d\n", rank);
        return 1;
    }

    submit_rb_fd = bpf_obj_get("/sys/fs/bpf/submit_rb");
    if (submit_rb_fd < 0)
    {
        fprintf(stderr, "Error: bpf_obj_get failed: /sys/fs/bpf/submit_rb. rank: %d\n", rank);
        return 1;
    }

    // 设置send地址和端口
    memset(&sendAddr, 0, sizeof(sendAddr));
    sendAddr.sin_family = AF_INET;
    sendAddr.sin_port = htons(ALTER_BEGIN_PORT + sendto);
    sendAddr.sin_addr.s_addr = sendto_net_info.ip_addr.addr;

    // 设置recv地址和端口
    memset(&recvAddr, 0, sizeof(recvAddr));
    recvAddr.sin_family = AF_INET;
    recvAddr.sin_port = htons(ALTER_BEGIN_PORT + recvfrom);
    recvAddr.sin_addr.s_addr = recv_net_info.ip_addr.addr;

    // init_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    // if (init_sockfd < 0)
    // {
    //     perror("socket creation failed");
    //     exit(EXIT_FAILURE);
    // }

    // listen_sockfd = alter_create_listen_socket(ALTER_BEGIN_PORT + rank);

    // finish_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    // if (finish_socket_fd == -1)
    // {
    //     fprintf(stderr, "BPF AllReduce Error: failed to create tcp socket when sending finish msg\n");
    //     exit(EXIT_FAILURE);
    // }
    // recvAddr.sin_port = htons(FINISH_MSG_PORT);
    // if (connect(finish_socket_fd, (struct sockaddr *)&recvAddr, sizeof(recvAddr)) == -1)
    // {
    //     fprintf(stderr, "BPF AllReduce Error: failed to connect to recvfrom rank when sending finish msg\n");
    //     exit(EXIT_FAILURE);
    // }
    // recvAddr.sin_port = htons(ALTER_BEGIN_PORT + recvfrom);

    

    return 0;
}

int alter_create_listen_socket(int port)
{
    int sockfd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t addr_len;
    int n;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("Error opening socket");
        exit(1);
    }

    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    // 绑定套接字到指定端口
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("Error on binding");
        exit(1);
    }
    return sockfd;
}

struct if_addrs
{
    unsigned int ip_addr;
    unsigned char mac_addr[6];
};

int get_first_zero_bitmap(unsigned long long bitmap, int limit)
{
    int bound = MIN(sizeof(bitmap) * 8, limit);
    for (int i = 0; i < bound; ++i)
    {
        if (((bitmap >> i) & 1) == 0)
        {
            return i;
        }
    }
    return -1;
}

#ifdef RANK_TOPO_BOOTSTRAP
void send_rank_ipaddr(int rank, int size, MPIR_Comm *comm, MPIR_Errflag_t *errflag, struct mpi_rank_info *info)
{
    struct ifaddrs *ifaddr, *ifa;
    char ip_address[INET_ADDRSTRLEN];
#define MAX_SEND_RANK_ADDR_BUF 1024
    struct if_addrs ip_s_buf = {0};
    struct if_addrs ip_r_buf = {0};
    int send_size = 0, send_to, recv_from;
    MPIR_Request *reqs_sendto[2]; /* one send and one recv per transfer */
    MPIR_Request *reqs_recvfrom[2];
    int tag, socket_fd;
    int mpi_errno = MPI_SUCCESS, mpi_errno_ret = MPI_SUCCESS;
    const char *if_name = "ens3";

    // get ip addr
    // 获取所有接口地址信息
    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    // 遍历接口地址
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
        {
            continue;
        }
        // 获取IPv4地址
        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        // 获取我们需要的接口
        if (addr->sin_family != AF_INET)
            continue;
        if (strcmp(ifa->ifa_name, if_name) == 0)
        {
            // printf("Rank %d: test1\n", rank);
            ip_s_buf.ip_addr = addr->sin_addr.s_addr;
            break;
        }
    }
    // 释放资源
    freeifaddrs(ifaddr);

    // get mac addr
    struct ifreq ifr;
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    ioctl(socket_fd, SIOCGIFHWADDR, &ifr);
    close(socket_fd);
#define MAC_ADDR_LEN 6
    memcpy(ip_s_buf.mac_addr, (unsigned char *)ifr.ifr_hwaddr.sa_data, MAC_ADDR_LEN);

    send_to = (rank + 1) % size;
    recv_from = (rank + size - 1) % size;
    mpi_errno = MPIR_Sched_next_tag(comm, &tag);

    mpi_errno = MPIC_Irecv(&ip_r_buf, sizeof(ip_r_buf), MPI_CHAR, send_to, tag, comm, &reqs_sendto[0]);
    if (MPI_SUCCESS != mpi_errno)
    {
        printf("Error in rank to ip addr: irecv: %d\n", rank);
    }
    mpi_errno = MPIC_Isend(&ip_s_buf, sizeof(ip_s_buf),
                           MPI_CHAR, recv_from, tag, comm, &reqs_sendto[1], errflag);
    if (MPI_SUCCESS != mpi_errno)
    {
        printf("Error in rank to ip addr: send: %d\n", rank);
    }
    mpi_errno = MPIC_Waitall(2, reqs_sendto, MPI_STATUSES_IGNORE, errflag);
    if (MPI_SUCCESS != mpi_errno)
    {
        printf("Error in rank to ip addr: wait_recv: %d\n", rank);
        memset(&ip_r_buf, 0, sizeof(ip_r_buf));
    }
    else
    {
        info->sendto_addr.addr = ip_r_buf.ip_addr;
        memcpy(info->sendto_mac, ip_r_buf.mac_addr, sizeof(ip_r_buf.mac_addr));
    }

    // get rank_recvfrom's ip and mac address
    mpi_errno = MPIC_Irecv(&ip_r_buf, sizeof(ip_r_buf), MPI_CHAR, recv_from, tag, comm, &reqs_recvfrom[0]);
    if (MPI_SUCCESS != mpi_errno)
    {
        printf("Error in rank to ip addr: irecv: %d\n", rank);
    }
    mpi_errno = MPIC_Isend(&ip_s_buf, sizeof(ip_s_buf),
                           MPI_CHAR, send_to, tag, comm, &reqs_recvfrom[1], errflag);
    if (MPI_SUCCESS != mpi_errno)
    {
        printf("Error in rank to ip addr: send: %d\n", rank);
    }
    mpi_errno = MPIC_Waitall(2, reqs_recvfrom, MPI_STATUSES_IGNORE, errflag);
    if (MPI_SUCCESS != mpi_errno)
    {
        printf("Error in rank to ip addr: wait_recv: %d\n", rank);
        memset(&ip_r_buf, 0, sizeof(ip_r_buf));
    }
    else
    {
        info->recvfrom_addr.addr = ip_r_buf.ip_addr;
        memcpy(info->recvfrom_mac, ip_r_buf.mac_addr, sizeof(ip_r_buf.mac_addr));
    }
}
#endif

int send_payload_packet(int sockfd, int rank, int sequence_id, const struct sockaddr *addr, int op, int t, unsigned int payload_size, const int *buff)
{
    unsigned char request[MAX_REQUEST_SIZE * sizeof(int)] = {0};
    // Magic_Num | op | rank | t | <data block> |
    int len = sizeof(struct arhdr);
    struct arhdr arhdr;
    arhdr.magic_num[0] = 0x42;
    arhdr.magic_num[1] = 0x60;
    arhdr.magic_num[2] = 0x80;
    arhdr.magic_num[3] = 0x02;
    arhdr.op = op;
    arhdr.t = t;
    arhdr.rank = rank;
    arhdr.sequence_id = sequence_id;
    memcpy(request, &arhdr, sizeof(struct arhdr));
    if (buff != NULL)
    {
        memcpy(request + len, buff, payload_size);
        len += payload_size;
    }
    if (sendto(sockfd, (const char *)request, len, 0, addr, sizeof(*addr)) < 0)
    {
        int err = errno;
        fprintf(stderr, "MPI rank %d, op %d: sendto failed, errno: %d (%s)\n", rank, op, err, strerror(err));
        exit(EXIT_FAILURE);
    }

    return 0;
}

void send_resend_packet(int rank, int sequence_id, struct mpi_rank_info *rinfo, struct sockaddr_in *resend_addr, int sockfd)
{
    struct arhdr arhdr;
    if (sockfd < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    int t = get_first_zero_bitmap(rinfo->bitmap_rs, rinfo->size - 1);
    if (t == -1)
    {
        t = get_first_zero_bitmap(rinfo->bitmap_ag, rinfo->size - 1);
        // if (t == -1 && rinfo->bitmap_cnt != rinfo->size * 2 - 2) {
        if (t == -1)
        {
            printf("MPI Resend unvalided. Rank: %d, t: %d, seq_id: %d\n", rank, t, sequence_id);
            return;
        }
        else if (t == 0)
        {
            arhdr.op = OP_RESEND_RS;
            arhdr.t = rinfo->size - 2;
        }
        else
        {
            arhdr.op = OP_RESEND_AG;
            arhdr.t = t - 1;
        }
        printf("MPI Resend AG. Rank: %d, t: %d, seq_id: %d\n", rank, t, sequence_id);
    }
    else if (t == 0)
    {
        arhdr.op = OP_RESEND_INIT;
        printf("MPI Resend Init. Rank: %d, t: %d, seq_id: %d\n", rank, t, sequence_id);
    }
    else
    {
        arhdr.op = OP_RESEND_RS;
        arhdr.t = t - 1;
        printf("MPI Resend RS. Rank: %d, t: %d, seq_id: %d\n", rank, t, sequence_id);
    }

    unsigned char request[MAX_REQUEST_SIZE * sizeof(int)] = {0};
    // Magic_Num | op | rank | t | <data block> |
    int len = sizeof(struct arhdr);

    arhdr.magic_num[0] = 0x42;
    arhdr.magic_num[1] = 0x60;
    arhdr.magic_num[2] = 0x80;
    arhdr.magic_num[3] = 0x02;
    arhdr.rank = rinfo->recvfrom;
    arhdr.sequence_id = sequence_id;
    memcpy(request, &arhdr, sizeof(struct arhdr));
    len += rinfo->count * sizeof(int);
    if (sendto(sockfd, (const char *)request, len, 0, (const struct sockaddr *)resend_addr, sizeof(*resend_addr)) < 0)
    {
        fprintf(stderr, "MPI rank %d: send resend_request packet failed: %s\n", rank, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

inline int recv_result(int sockfd, char *buffer, int recv_max_size, int rank)
{
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    ssize_t num_bytes = recvfrom(sockfd, buffer, recv_max_size, 0, (struct sockaddr *)&client_addr, &client_len);
    if (num_bytes < 0)
    {
        fprintf(stderr, "MPI rank %d: recvfrom failed\n", rank);
        exit(EXIT_FAILURE);
    }
    return num_bytes;
}

#ifdef TOPO_CONFIG_FILE
int paser_config(int rank, int src, int dst, struct mpi_rank_info *info)
{
    char *config_path = getenv("MPI_EBPF_ALLREDUCE");
    // printf("eBPF: %s\n", config_path);

    if (config_path != NULL)
    {
        FILE *file = fopen(config_path, "r");
        // printf("eBPF: %s\n", config_path);

        if (file == NULL)
        {
            fprintf(stderr, "EBPF failed to open configure file.\n");
            return 1;
        }

        char line[1000];
        int cnt = -1;
        // 这里读取配置文件还存在一些bug，后面需要继续看一下。
        while (fgets(line, 1000, file))
        {
            cnt += 1;
            if (cnt != src && cnt != dst)
            {
                continue;
            }
            line[strcspn(line, "\n")] = '\0';

            char *token;
            char *fields[10];
            int field_count = 0;

            token = strtok(line, ",");
            while (token != NULL && field_count < 10)
            {
                fields[field_count] = token;
                field_count++;
                token = strtok(NULL, ",");
            }

            if (cnt == dst)
            {
                info->sendto_addr.addr = inet_addr(fields[1]);
                sscanf(fields[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &info->sendto_mac[0], &info->sendto_mac[1], &info->sendto_mac[2],
                       &info->sendto_mac[3], &info->sendto_mac[4], &info->sendto_mac[5]);
            }
            if (cnt == src)
            {
                info->recvfrom_addr.addr = inet_addr(fields[1]);
                sscanf(fields[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &info->recvfrom_mac[0], &info->recvfrom_mac[1], &info->recvfrom_mac[2],
                       &info->recvfrom_mac[3], &info->recvfrom_mac[4], &info->recvfrom_mac[5]);
            }
        }
        fclose(file);
    }
    else
    {
        fprintf(stderr, "EBPF failed to get environment variable\n");
        return 1;
    }
    return 0;
}
#endif

int process_early_packet(int rank, struct mpi_rank_info *info, struct data_blocks_buff *blocks_buff, int sockfd)
{
    struct mpi_tmp_buff tmp = {0};
    unsigned int key = rank_sequence_id_hash(rank, curr_sequence_id);
    if (bpf_map_lookup_elem(mpi_rank_tmp_buff_fd, &key, &tmp))
    {
        fprintf(stderr, "Error in get tmp_buff\n");
        return 1;
    }
    if (tmp.bitmap_rs == 0)
    {
        return 0;
    }
    int bound = MIN(sizeof(tmp.bitmap_rs) * 8, info->size - 1);
    int packet_cnt = 0;
    for (int t = 0; t < bound; ++t)
    {
        if (tmp.bitmap_rs & (1ull << t))
        {
            packet_cnt += 1;
            int tmp_block_id = (rank - t - 1 + MAX_RANK_SIZE) % MAX_RANK_SIZE;
            int recv_block_id = (rank - t - 1 + info->size) % info->size;
            if (recv_block_id < MAX_RANK_SIZE)
            {
                int bound_i = MIN(info->count, MAX_BUF_SIZE);
                for (int i = 0; i < bound_i; ++i)
                {
                    tmp.buff[tmp_block_id][i] += blocks_buff->buff[recv_block_id][i];
                }
            }
            if (send_payload_packet(sockfd, rank, curr_sequence_id, &sendAddr, OP_REDUCESCATTER_EARLY, t, info->count * sizeof(int), tmp.buff[tmp_block_id]))
            {
                fprintf(stderr, "Error in send early packet\n");
                return 1;
            }
            // else
            // {
            //     printf("BPF Allreduce: Send earily. Rank: %d, t: %d\n", rank, t);
            // }
        }
    }

    // reset bpf tmp buff
    tmp.bitmap_rs = 0;
    bpf_map_update_elem(mpi_rank_tmp_buff_fd, &key, &tmp, BPF_ANY);

    return 0;
}

int poll_kernel_result(int nranks, MPI_Aint *cnts, MPI_Aint *displs, void *recvbuf, size_t extent)
{
    struct data_blocks_buff blocks_buff = {0};
    char *tmpsend = NULL;
    unsigned int key = rank_sequence_id_hash(submit_rank, curr_sequence_id);
    if (!bpf_map_lookup_elem(blocks_buff_fd, &key, &blocks_buff))
    {
        if (!is_float)
        {
            for (int i = 0; i < nranks; ++i)
            {
                tmpsend = ((char *)recvbuf) + displs[i] * extent;
                memcpy(tmpsend, blocks_buff.buff[i], cnts[i] * sizeof(int));
            }
        }
        else
        {
            float *buff_ptr;
            for (int i = 0; i < nranks; ++i)
            {
                int block_count = cnts[i];
                tmpsend = ((char *)recvbuf) + displs[i] * extent;
                buff_ptr = (float *)tmpsend;
                for (int j = 0; j < block_count; ++j)
                {
                    *buff_ptr = (float)(blocks_buff.buff[i][j]) / FLOAT_BASE;
                    buff_ptr += 1;
                }
                // memcpy(blocks_buff.buff[i], tmpsend, block_count * sizeof(int));
            }
        }
    }
    else
    {
        fprintf(stderr, "EBPF: Error in pulling submitted result.\n");
        return 1;
    }
    return 0;
}

int poll_rb(int op, int rank, int resend_rank, int resend_sockfd, const struct sockaddr *resendAddr, int max_resend)
{
    int err, *done = NULL, resend_times = 0;
    int key = rank_sequence_id_hash(rank, curr_sequence_id);
    ring_buffer_sample_fn handler;
    if (op == OP_FINIAL)
    {
        done = &rb_poll_done;
    }
    else
    {
        sprintf(stderr, "Error in poll ring buff: unvalid op: %d, rank: %d\n", op, rank);
        return 1;
    }

    struct timespec resend_start_time, resend_test_time;
    struct mpi_rank_info info = {0};

    struct ring_buffer *submit_rb;
    submit_rb = ring_buffer__new(submit_rb_fd, event_handler, NULL, NULL);
    if (!submit_rb)
    {
        fprintf(stderr, "Error: failed to create ring buffer. rank: %d\n", rank);
        ring_buffer__free(submit_rb);
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &resend_start_time);
    while (!(*done))
    {
        err = ring_buffer__consume(submit_rb);
        if (err == -EINTR)
        {
            err == 0;
            break;
        }
        if (err < 0)
        {
            printf("Error: polling ring buffer (op: %d, rank: %d): %d\n", op, rank, err);
            break;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &resend_test_time);
        long long elapsed_time = (resend_test_time.tv_sec - resend_start_time.tv_sec) * 1000LL +
                                 (resend_test_time.tv_nsec - resend_start_time.tv_nsec) / 1000LL;
        if (elapsed_time >= RESEND_INTERVAL)
        {
            if (op == OP_FINIAL)
            {
                if (!bpf_map_lookup_elem(ar_rank_infos_fd, &key, &info))
                {
                    // 查找bitmap，然后发送重传通知包。这里可以从低到高开始查
                    send_resend_packet(rank, curr_sequence_id, &info, resendAddr, resend_sockfd);
                    clock_gettime(CLOCK_MONOTONIC_RAW, &resend_start_time);
                }
                else
                {
                    fprintf(stderr, "Error: bpf map lookup failed when resending: rank %d, key: %d\n", rank, key);
                    exit(EXIT_FAILURE);
                }
            }
        }
    }
    *done = false;
    ring_buffer__free(submit_rb);
    return 0;
}


void send_finish_msg(int recvfrom_rank)
{
    int len = sizeof(struct arhdr);
    struct arhdr arhdr;
    arhdr.magic_num[0] = 0x42;
    arhdr.magic_num[1] = 0x60;
    arhdr.magic_num[2] = 0x80;
    arhdr.magic_num[3] = 0x02;
    arhdr.rank = recvfrom_rank;
    arhdr.sequence_id = curr_sequence_id;
    arhdr.op = OP_FINISH;

    ssize_t sent_bytes = send(finish_socket_fd, &arhdr, sizeof(arhdr), 0);
    if (sent_bytes == -1)
    {
        fprintf(stderr, "BPF AllReduce Error: failed to send finish msg\n");
        exit(EXIT_FAILURE);
    }
}


int allreduce_ebpf(int rank, int nranks, int segcount, int block_count, MPI_Aint *cnts, MPI_Aint *displs, void *recvbuf, size_t extent, MPIR_Comm *comm, MPIR_Errflag_t *errflag)
{
    struct timespec start_time, end_time; //, resend_start_time, resend_test_time;
    long long execution_time;
    int mpi_errno = MPI_SUCCESS, mpi_errno_ret = MPI_SUCCESS;
    void *tmpbuf;
    int tag;
    char *tmpsend = NULL;
    int src = (nranks + rank - 1) % nranks;
    int dst = (rank + 1) % nranks;
    unsigned urank = rank;

    if (!has_initialed) {
        if (init(rank, dst, src))
        {
            fprintf(stderr, "eBPF Error: init failed.\n");
            exit(EXIT_FAILURE);
        }
        has_initialed = true;
    }

    // if (init(rank, dst, src))
    // {
    //     fprintf(stderr, "eBPF Error: init failed.\n");
    //     exit(EXIT_FAILURE);
    // }


    init_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (init_sockfd < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    listen_sockfd = alter_create_listen_socket(ALTER_BEGIN_PORT + rank);

    finish_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (finish_socket_fd == -1)
    {
        fprintf(stderr, "BPF AllReduce Error: failed to create tcp socket when sending finish msg\n");
        exit(EXIT_FAILURE);
    }
    recvAddr.sin_port = htons(FINISH_MSG_PORT);
    if (connect(finish_socket_fd, (struct sockaddr *)&recvAddr, sizeof(recvAddr)) == -1)
    {
        fprintf(stderr, "BPF AllReduce Error: failed to connect to recvfrom rank when sending finish msg\n");
        exit(EXIT_FAILURE);
    }
    recvAddr.sin_port = htons(ALTER_BEGIN_PORT + recvfrom);


    // clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
    // =================================================
    // 初始化meta信息
    struct mpi_rank_info info = {0};
    unsigned int key = rank_sequence_id_hash(rank, curr_sequence_id);
    info.sendto = dst;
    info.recvfrom = src;
    info.size = nranks;
    info.count = segcount;
    info.valided = 1;
    info.finished = 0;
    info.submitted = 0;
    info.bitmap_rs = 0;
    info.bitmap_ag = 0;
    info.bitmap_cnt = 0;

    // 记录初始化时间
    // {
    //     clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
    //     execution_time = (end_time.tv_sec - start_time.tv_sec) * 1000000LL +
    //                     (end_time.tv_nsec - start_time.tv_nsec) / 1000LL;
    //     if (rank == 0)
    //         printf("BPF execution time 0.1: %lld microseconds\n", execution_time);
    //     clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
    // }

    // 更新数据

    memset(&blocks_buff, 0, sizeof(blocks_buff));
    if (!is_float)
    {
        for (int i = 0; i < nranks; ++i)
        {
            block_count = cnts[i];
            tmpsend = ((char *)recvbuf) + displs[i] * extent;
            memcpy(blocks_buff.buff[i], tmpsend, block_count * sizeof(int));
        }
    }
    else
    {
        float *buff_ptr;
        for (int i = 0; i < nranks; ++i)
        {
            block_count = cnts[i];
            tmpsend = ((char *)recvbuf) + displs[i] * extent;
            buff_ptr = (float *)tmpsend;
            for (int j = 0; j < block_count; ++j)
            {
                blocks_buff.buff[i][j] = *buff_ptr * FLOAT_BASE;
                buff_ptr += 1;
            }
            // memcpy(blocks_buff.buff[i], tmpsend, block_count * sizeof(int));
        }
    }

    bpf_map_update_elem(blocks_buff_fd, &key, &blocks_buff, BPF_ANY);
    bpf_map_update_elem(ar_rank_infos_fd, &key, &info, BPF_ANY);

    // {
    //     clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
    //     execution_time = (end_time.tv_sec - start_time.tv_sec) * 1000000LL +
    //                     (end_time.tv_nsec - start_time.tv_nsec) / 1000LL;
    //     if (rank == 0)
    //         printf("BPF execution time 0.1: %lld microseconds\n", execution_time);
    //     clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
    // }
    signal(SIGINT, int_exit);

    if (rank != 0)
    {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 10000 * rank;
        nanosleep(&ts, NULL);
    }

    // 发送第一个数据包
    if (send_payload_packet(init_sockfd, info.sendto, curr_sequence_id, &sendAddr, OP_REDUCESCATTER, 0, segcount * sizeof(int), blocks_buff.buff[rank]))
    {
        fprintf(stderr, "Error in BPF AR: send init packet failed!\n");
        exit(EXIT_FAILURE);
    }

    // {
    //     clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
    //     execution_time = (end_time.tv_sec - start_time.tv_sec) * 1000000LL +
    //                     (end_time.tv_nsec - start_time.tv_nsec) / 1000LL;
    //     if (rank == 0)
    //         printf("BPF execution time 0.4: %lld microseconds\n", execution_time);
    //     clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
    // }

    if (process_early_packet(rank, &info, &blocks_buff, init_sockfd))
    {
        fprintf(stderr, "Error in BPF AR: send early packet failed.\n");
        exit(EXIT_FAILURE);
    }

    // {
    //     clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
    //     execution_time = (end_time.tv_sec - start_time.tv_sec) * 1000000LL +
    //                     (end_time.tv_nsec - start_time.tv_nsec) / 1000LL;
    //     if (rank == 0)
    //         printf("BPF execution time 0.5: %lld microseconds\n", execution_time);
    //     clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
    // }

    if (poll_rb(OP_FINIAL, rank, 0, init_sockfd, &recvAddr, -1))
    {
        fprintf(stderr, "Error in bpf Allreduce, rank %d: Poll ring buff submit_rb failed\n", rank);
        exit(EXIT_FAILURE);
    }

    if (poll_kernel_result(nranks, cnts, displs, recvbuf, extent))
    {
        fprintf(stderr, "Error in bpf Allreduce, rank %d: Poll kernel result failed\n", rank);
        exit(EXIT_FAILURE);
    }

    // if (bpf_map_lookup_elem(ar_rank_infos_fd, &key, &info))
    // {
    //     fprintf(stderr, "Error in get map elem in  mpi_rank_info\n");
    //     exit(EXIT_FAILURE);
    // }
    // info.submitted = 1;
    // bpf_map_update_elem(ar_rank_infos_fd, &key, &info, BPF_ANY); // 先更新再读，防止读写冲突
    // if (bpf_map_lookup_elem(ar_rank_infos_fd, &key, &info))
    // {
    //     printf("Map elem has been deleted\n");
    // }
    // else
    // {
    //     if (info.finished == 1 && info.submitted == 1)
    //     {
    //         bpf_map_delete_elem(ar_rank_infos_fd, &key);
    //         bpf_map_delete_elem(blocks_buff_fd, &key);
    //         printf("Info: Delete rinfo map elem: rank is %d, seq_id is %d\n", rank, curr_sequence_id);
    //     }
    // }
    send_finish_msg(info.recvfrom);

    if (curr_sequence_id > 0) {
        unsigned int prev_key = rank_sequence_id_hash(rank, curr_sequence_id);
        bpf_map_delete_elem(blocks_buff_fd, &prev_key);
        bpf_map_delete_elem(ar_rank_infos_fd, &prev_key);
    } else {
        unsigned int prev_key = rank;
        bpf_map_delete_elem(blocks_buff_fd, &prev_key);
        bpf_map_delete_elem(ar_rank_infos_fd, &prev_key);
    }

    curr_sequence_id = (curr_sequence_id + 1) % 1024;
    
    // close(ar_rank_infos_fd);
    // close(blocks_buff_fd);
    // close(mpi_rank_tmp_buff_fd);
    // close(submit_rb_fd);
    close(init_sockfd);
    close(finish_socket_fd);
    close(listen_sockfd);

    // {
    //     clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
    //     execution_time = (end_time.tv_sec - start_time.tv_sec) * 1000000LL +
    //                     (end_time.tv_nsec - start_time.tv_nsec) / 1000LL;
    //     if (rank == 0)
    //         printf("BPF execution time 1: %lld microseconds\n", execution_time);
    // }
    return 0;
    //     printf("BPF execution time 1: %lld microseconds\n", execution_time);
}

#endif