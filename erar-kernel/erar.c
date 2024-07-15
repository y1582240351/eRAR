#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <stdlib.h>
#include <string.h>
// #include <arpa/inet.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <getopt.h>
#include <pthread.h>

#include "erar.h"
// #include "afxdp.h"

#define LEN_MAX 512
#define TOTAL_ETH_DEV 5
#define BPF_SYSFS_ROOT "/sys/fs/bpf"

#define FINISH_MSG_PORT 12890

struct bpf_object *obj;
const char *filename = "mpi-reduce.bpf.o";
const char *config_filename = "erar.conf";
char filepath[LEN_MAX];
char command[LEN_MAX];
struct bpf_progs_desc
{
    char name[256];
    char title[256];
    enum bpf_prog_type type;
    unsigned char pin;
    int map_prog_idx;
    struct bpf_program *prog;
};
int prog_count, err;
int server_socket;
int main_xdp_prog = 2;
static struct bpf_progs_desc progs[] = {
    // {"arstart_tc_main", "ARStart", BPF_PROG_TYPE_SCHED_CLS, 1, -1, NULL},
    {"resendGen_main", "ResendGen", BPF_PROG_TYPE_SCHED_CLS, 1, -1, NULL},
    {"early_packet_main", "EarlyPacket", BPF_PROG_TYPE_SCHED_CLS, 1, -1, NULL},

    {"reduce_scatter_main", "ReduceScatter", BPF_PROG_TYPE_XDP, 0, -1, NULL},
    {"allgather_main", "AllGather", BPF_PROG_TYPE_XDP, 0, XDP_ALLGATHER, NULL},
    {"summit_main", "Summit", BPF_PROG_TYPE_XDP, 0, XDP_SUMMIT, NULL},
    {"resend_filter_main", "ResendFilter", BPF_PROG_TYPE_XDP, 0, XDP_RESEND_FILTER, NULL},
    {"resend_init_main", "ResendInit", BPF_PROG_TYPE_XDP, 0, XDP_RESEND_INIT, NULL},
    {"resend_rs_main", "ResendRS", BPF_PROG_TYPE_XDP, 0, XDP_RESEND_RS, NULL},
    {"resend_ag_main", "ResendAG", BPF_PROG_TYPE_XDP, 0, XDP_RESEND_AG, NULL},
    // {"finish_main", "Finish", BPF_PROG_TYPE_XDP, 0, XDP_FINISH, NULL},
    // {"finish_query_main", "FinishQuery", BPF_PROG_TYPE_XDP, 0, XDP_FINISH_QUERY, NULL},
    // {"clean_main", "Clean", BPF_PROG_TYPE_XDP, 0, XDP_CLEAN, NULL},
    // {"clean_query_main", "CleanQuery", BPF_PROG_TYPE_XDP, 0, XDP_CLEAN_QUERY, NULL},
    // {"tc_send_main", "TcSend", BPF_PROG_TYPE_SCHED_CLS, 0, ARMPI_PROG_TC_SEND, NULL},
};

int interface_count = 0;
int interfaces_idx[TOTAL_ETH_DEV] = {2, 1};
char interfaces[TOTAL_ETH_DEV][16] = {"ens3", "lo"};
int xdp_main_prog_fd;
int mpi_rank_infos_fd, mpi_rank_tmp_buff_fd, submit_rb_fd, net_infos_fd;

unsigned int mechine_rank = ~0;

bool hook_created = false;
struct bpf_tc_hook *tc_hooks[TOTAL_ETH_DEV];
struct bpf_tc_opts *tc_optses[TOTAL_ETH_DEV];
int tc_hook_count = 0;
uint32_t xdp_flag = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;

struct recv_finish_args {
    int client_socket;
    int ar_rank_infos_fd;
    int data_blocks_fd;
};

void print_usage(const char *program_name)
{
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -r, --rank <rank>      Set the rank (integer)\n");
    printf("  -h, --help             Show this help message\n");
}

void set_opt(int argc, char *argv[])
{
    int opt;

    static struct option long_options[] = {
        {"rank", required_argument, NULL, 'r'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "r:h", long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'r':
            mechine_rank = atoi(optarg);
            break;
        case 'h':
        case '?':
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
        default:
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (mechine_rank == ~0)
    {
        fprintf(stderr, "Error: rank not set\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
}

// #define MAX_BUF_SIZE 128
// #define MAX_RANK_SIZE 16
// struct mpi_rank_info {
// 	int sendto; // send rank
// 	int recvfrom; // recv rank
// 	int size; // #comm_rank
// 	long count;
// 	// int elem_size;
// 	unsigned char buf[MAX_RANK_SIZE][MAX_BUF_SIZE];
// };
int check_map_fd_info(const struct bpf_map_info *info,
                      const struct bpf_map_info *exp)
{
    if (exp->key_size && exp->key_size != info->key_size)
    {
        fprintf(stderr, "ERR: %s() "
                        "Map key size(%d) mismatch expected size(%d)\n",
                __func__, info->key_size, exp->key_size);
        return 1;
    }
    if (exp->value_size && exp->value_size != info->value_size)
    {
        fprintf(stderr, "ERR: %s() "
                        "Map value size(%d) mismatch expected size(%d)\n",
                __func__, info->value_size, exp->value_size);
        return 1;
    }
    if (exp->max_entries && exp->max_entries != info->max_entries)
    {
        fprintf(stderr, "ERR: %s() "
                        "Map max_entries(%d) mismatch expected size(%d)\n",
                __func__, info->max_entries, exp->max_entries);
        return 1;
    }
    if (exp->type && exp->type != info->type)
    {
        fprintf(stderr, "ERR: %s() "
                        "Map type(%d) mismatch expected type(%d)\n",
                __func__, info->type, exp->type);
        return 1;
    }

    return 0;
}

// void init_rank_ip() {

// }

void init_bpf()
{
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
    {
        perror("Failed to set RLIMIT_MEMLOCK");
        exit(1);
    }

    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "Error loading BPF object from file: %s\n", filename);
        exit(1);
    }

    prog_count = sizeof(progs) / sizeof(progs[0]);
    for (int i = 0; i < prog_count; ++i)
    {
        progs[i].prog = bpf_object__find_program_by_name(obj, progs[i].name);
        if (!progs[i].prog)
        {
            fprintf(stderr, "Error: bpf_object__find_program_by_name failed: %s\n", progs[i].name);
            exit(1);
        }
        else
        {
            printf("progname: %s\n", progs[i].name);
        }
        bpf_program__set_type(progs[i].prog, progs[i].type);
    }

    err = bpf_object__load(obj);
    if (err)
    {
        fprintf(stderr, "Error: bpf_object__load failed\n");
        exit(1);
    }

    // int mpi_rank_infos_fd, mpi_rank_tmp_buff_fd, submit_rb_fd;
    // mpi_rank_infos_fd = bpf_object__find_map_fd_by_name(obj, "mpi_rank_infos");
    // if (mpi_rank_infos_fd < 0) {
    // 	fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed: mpi_rank_infos_fd\n");
    // 	exit(1); //return 1;
    // }
    // mpi_rank_tmp_buff_fd = bpf_object__find_map_fd_by_name(obj, "rank_tmp_buff");
    // if (mpi_rank_tmp_buff_fd < 0) {
    // 	fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed: mpi_rank_tmp_buff_fd\n");
    // 	exit(1); //return 1;
    // }
    // submit_rb_fd = bpf_object__find_map_fd_by_name(obj, "submit_rb");
    // if (submit_rb_fd < 0) {
    // 	fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed: submit_rb_fd\n");
    // 	exit(1); //return 1;
    // }

    int xdp_map_progs_fd = bpf_object__find_map_fd_by_name(obj, "xdp_progs");
    if (xdp_map_progs_fd < 0)
    {
        fprintf(stderr, "Error: bpf_object__find_program_by_name failed: map_progs\n");
        exit(1);
    }

    net_infos_fd = bpf_object__find_map_fd_by_name(obj, "net_infos");
    if (xdp_map_progs_fd < 0)
    {
        fprintf(stderr, "Error: bpf_object__find_program_by_name failed: net_infos\n");
        exit(1);
    }

    for (int i = 0; i < prog_count; ++i)
    {
        int prog_fd = bpf_program__fd(progs[i].prog);

        if (prog_fd < 0)
        {
            fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", progs[i].name);
            exit(1);
        }

        if (progs[i].map_prog_idx != -1)
        {
            unsigned int map_prog_idx = progs[i].map_prog_idx;
            if (map_prog_idx < 0)
            {
                fprintf(stderr, "Error: Can't get prog fd for bpf program %s\n", progs[i].name);
                exit(1);
            }

            err = bpf_map_update_elem(xdp_map_progs_fd, &map_prog_idx, &prog_fd, 0);
            if (err)
            {
                fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
                exit(1);
            }
        }

        if (progs[i].pin)
        {
            int len = snprintf(filepath, LEN_MAX, "%s/%s", BPF_SYSFS_ROOT, progs[i].title);
            if (len < 0)
            {
                fprintf(stderr, "Error: Program name '%s' is invaild\n", progs[i].title);
                exit(-1);
            }
            else if (len >= LEN_MAX)
            {
                fprintf(stderr, "Error: Program name '%s' is too long\n", progs[i].title);
                exit(-1);
            }
        retry:
            if (bpf_program__pin(progs[i].prog, filepath))
            {
                fprintf(stderr, "Error: Failed to pin program '%s' to path: %s\n", progs[i].title, filepath);
                if (errno == EEXIST)
                {
                    fprintf(stdout, "BPF program '%s' already pinned, unpinning it to reload it\n", progs[i].title);
                    if (bpf_program__unpin(progs[i].prog, filepath))
                    {
                        fprintf(stderr, "Error: Failed to unpin program '%s' at %s\n", progs[i].title, progs[i].title);
                        exit(-1);
                    }
                    goto retry;
                }
                exit(-1);
            }
            else
            {
                printf("Success pin arreduce\n");
            }
        }
    }

    xdp_main_prog_fd = bpf_program__fd(progs[main_xdp_prog].prog);
    if (xdp_main_prog_fd < 0)
    {
        fprintf(stderr, "Error: bpf_program__fd failed: xdp\n");
        exit(-1);
    }
}

static inline unsigned int rank_sequence_id_hash(unsigned int rank, unsigned int sequence_id)
{
    return sequence_id * MAX_RANK_SIZE + rank;
}

void *handle_finish(void *arg)
{
    struct recv_finish_args * args = (struct recv_finish_args *)arg;
    int client_socket = args->client_socket;
    int ar_rank_infos_fd = args->ar_rank_infos_fd;
    int data_blocks_fd = args->data_blocks_fd;
    free(arg);

    if (client_socket == -1)
    {
        fprintf(stderr, "BPF AllReduce Error: failed to accept when recving finish msg");
        exit(EXIT_FAILURE);
    }

    char recv_buff[152];
    struct arhdr *hdr;
    unsigned int key;
    struct mpi_rank_info rinfo;


    int received_bytes = recv(client_socket, recv_buff, 152, 0);
    if (received_bytes == -1)
    {
        close(client_socket);
        fprintf(stderr, "Failed to receive finsih msg\n");
        exit(EXIT_FAILURE);
    }

    hdr = recv_buff;
    if (hdr->magic_num[0] != 0x42 || hdr->magic_num[1] != 0x60 || hdr->magic_num[2] != 0x80 || hdr->magic_num[3] != 0x02)
    {
        fprintf(stderr, "Error: recv unrespected packet\n");
        close(client_socket);
        return NULL;
    }

    key = rank_sequence_id_hash(hdr->rank, hdr->sequence_id);
    if (bpf_map_lookup_elem(ar_rank_infos_fd, &key, &rinfo))
    {
        fprintf(stderr, "Error in get map elem in  mpi_rank_info, rank: %d, seq_id: %d\n", hdr->rank, hdr->sequence_id);
        close(client_socket);
        return NULL;
    }
    printf("Info: Finish. rank is %d, seq_id is %d\n", hdr->rank, hdr->sequence_id);
    rinfo.finished = 1;
    bpf_map_update_elem(ar_rank_infos_fd, &key, &rinfo, BPF_ANY); // 先更新再读，防止读写冲突
    if (bpf_map_lookup_elem(ar_rank_infos_fd, &key, &rinfo))
    {
        printf("Map elem has been deleted\n");
        close(client_socket);
        return NULL;
    }
    if (rinfo.finished == 1 && rinfo.submitted == 1)
    {
        bpf_map_delete_elem(ar_rank_infos_fd, &key);
        // bpf_map_delete_elem(data_blocks_fd, &key);
        printf("Info: Delete rinfo map elem: rank is %d, seq_id is %d\n", hdr->rank, hdr->sequence_id);
    }
    close(client_socket);
    return NULL;
}

void recv_finish_msg()
{
    int client_socket;
    ssize_t received_bytes;
    
    struct sockaddr_in server_addr, client_addr;
    int client_addr_len = sizeof(client_addr);
    
    int ar_rank_infos_fd = bpf_obj_get("/sys/fs/bpf/mpi_rank_infos");
    if (ar_rank_infos_fd <= 0)
    {
        fprintf(stderr, "Error in bpf allreduce: error in obj get: /sys/fs/bpf/mpi_rank_infos\n");
        return;
    }
    int data_blocks_fd = bpf_obj_get("/sys/fs/bpf/data_blocks");
    if (data_blocks_fd <= 0)
    {
        fprintf(stderr, "Error in bpf allreduce: error in obj get: /sys/fs/bpf/data_blocks\n");
        return;
    }
    int rank_tmp_buff_fd = bpf_obj_get("/sys/fs/bpf/rank_tmp_buff");
    if (rank_tmp_buff_fd <= 0)
    {
        fprintf(stderr, "Error in bpf allreduce: error in obj get: /sys/fs/bpf/rank_tmp_buff\n");
        return;
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        fprintf(stderr, "BPF AllReduce Error: failed to create socket when recving finish msg\n");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(FINISH_MSG_PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        fprintf(stderr, "BPF AllReduce Error: bind failed when recving finish msg");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 1) == -1)
    {
        fprintf(stderr, "BPF AllReduce Error: listen failed when recving finish msg");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        struct recv_finish_args *args = malloc(sizeof(struct recv_finish_args));
        args->client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (args->client_socket < 0) {
            perror("Error accepting connection");
            close(server_socket);
            exit(EXIT_FAILURE);
        }

        args->ar_rank_infos_fd = ar_rank_infos_fd;
        args->data_blocks_fd = data_blocks_fd;
        pthread_t thread;
        pthread_create(&thread, NULL, handle_finish, args);
        pthread_detach(thread);
    }
    close(server_socket);
}

void clean_bpf()
{
    for (int i = 0; i < interface_count; ++i)
    {
        if (bpf_xdp_detach(interfaces_idx[i], xdp_flag, NULL) < 0)
        {
            fprintf(stderr, "Error: bpf_xdp_detach failed for interface %d\n", interfaces_idx[i]);
        }
        else
        {
            printf("BPF Program detached to XDP on interface %d\n", interfaces_idx[i]);
        }
    }

    // detach tc ebpf prog
    for (int i = 0; i < tc_hook_count; ++i)
    {
        struct bpf_tc_opts *tc_opts = tc_optses[i];
        struct bpf_tc_hook *tc_hook = tc_hooks[i];
        tc_opts->flags = tc_opts->prog_fd = tc_opts->prog_id = 0;
        err = bpf_tc_detach(tc_hook, tc_opts);
        if (err)
        {
            fprintf(stderr, "Failed to detach TC in %s: %d\n", interfaces[i], err);
        }
        else
        {
            printf("BPF Program detached to TC on interface %d\n", tc_hook->ifindex);
        }
    }

    // 为什么需要用这条命令呢?因为下面的bpf_tc_hook_destroy 并不能将前面声明的 qdisc 删除.
    // char command[LEN_MAX];
    for (int i = 0; i < interface_count; ++i)
    {
        snprintf(command, LEN_MAX, "tc filter del dev %s egress", interfaces[i]);
        assert(system(command) == 0);
        snprintf(command, LEN_MAX, "tc filter del dev %s ingress", interfaces[i]);
        assert(system(command) == 0);
        snprintf(command, LEN_MAX, "tc qdisc del dev %s clsact", interfaces[i]);
        assert(system(command) == 0);
    }

    // assert(remove("/sys/fs/bpf/ARStart") == 0);
    assert(remove("/sys/fs/bpf/mpi_rank_infos") == 0);
    // assert(remove("/sys/fs/bpf/xsks_map") == 0);
    assert(remove("/sys/fs/bpf/submit_rb") == 0);
    assert(remove("/sys/fs/bpf/rank_tmp_buff") == 0);
    assert(remove("/sys/fs/bpf/data_blocks") == 0);
    assert(remove("/sys/fs/bpf/EarlyPacket") == 0);
    assert(remove("/sys/fs/bpf/ResendGen") == 0);
    assert(remove("/sys/fs/bpf/net_infos") == 0);
}

// static bool is_exit = false;
static void int_exit(int sig)
{
    // is_exit = true;
    close(server_socket);
    clean_bpf();
    exit(EXIT_SUCCESS);
}

int get_interface_id(const char *interface)
{
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("Error creating socket");
        return -1;
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
    {
        fprintf(stderr, "Error getting interface index: %s\n", interface);
        close(sockfd);
        return -1;
    }
    close(sockfd);

    return ifr.ifr_ifindex;
}

#define MAX_CONFIG_LINE_LENGTH 512
int set_net_info(const char *line)
{
    char *token;
    char buffer[MAX_CONFIG_LINE_LENGTH];
    struct rank_net_info net_info = {0};
    strcpy(buffer, line);

    // Parse ID
    token = strtok(buffer, ", ");
    unsigned int id = atoi(token);

    // Parse IP
    token = strtok(NULL, ", ");
    net_info.ip_addr.addr = inet_addr(token);

    // Parse MAC
    token = strtok(NULL, ", ");
    sscanf(token, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &net_info.mac_addr[0], &net_info.mac_addr[1], &net_info.mac_addr[2],
           &net_info.mac_addr[3], &net_info.mac_addr[4], &net_info.mac_addr[5]);

    if (bpf_map_update_elem(net_infos_fd, &id, &net_info, BPF_ANY))
    {
        fprintf(stderr, "Error: bpf_map_update_elem failed for net_infos, rank is %d\n", id);
        return EXIT_FAILURE;
    }

    if (id == mechine_rank)
    {
        // Parse number of interfaces
        token = strtok(NULL, ", ");
        interface_count = atoi(token);

        // Parse interfaces
        int if_id;
        for (int i = 0; i < interface_count; i++)
        {
            token = strtok(NULL, ", ");
            if (token)
            {
                strcpy(interfaces[i], token);
                if_id = get_interface_id(interfaces[i]);
                if (if_id == -1)
                {
                    return EXIT_FAILURE;
                }
                interfaces_idx[i] = if_id;
            }
            else
            {
                fprintf(stderr, "Error: Not enough interfaces provided in the input line.\n");
                return EXIT_FAILURE;
            }
        }
    }
    return 0;
}

int load_config()
{
    FILE *file = fopen(config_filename, "r");
    if (!file)
    {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    char line[MAX_CONFIG_LINE_LENGTH];
    while (fgets(line, sizeof(line), file))
    {
        line[strcspn(line, "\n")] = '\0';
        if (set_net_info(line))
        {
            fclose(file);
            return EXIT_FAILURE;
        }
    }
    fclose(file);
    return 0;
}

int main(int argc, char *argv[])
{
    set_opt(argc, argv);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    // init_rank_ip();
    init_bpf();
    if (load_config())
    {
        fprintf(stderr, "Error in load config\n");
        goto cleanup;
    }

    // 挂载到lo的时候需要使用 XDP_FLAGS_SKB_MODE；其他则用 XDP_FLAGS_DRV_MODE
    for (int i = 0; i < interface_count; ++i)
    {
        if (bpf_xdp_attach(interfaces_idx[i], xdp_main_prog_fd, xdp_flag, NULL) < 0)
        {
            bpf_xdp_detach(interfaces_idx[i], xdp_flag, NULL);
            fprintf(stderr, "Error: bpf_xdp_attach failed for interface %d\n", interfaces_idx[i]);
            goto cleanup;
        }
        else
        {
            printf("XDP BPF program attached to XDP on interface %d\n", interfaces_idx[i]);
        }
    }

    // attach tc ebpf prog

    // ingress
    // for (int i = 0; i < interface_count; ++i) {
    //     DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
    // 	.ifindex = interfaces_idx[i], .attach_point = BPF_TC_INGRESS);
    //     DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
    //         .handle = 1, .priority = 1);
    //     err = bpf_tc_hook_create(&tc_hook);
    //     if (!err) {
    //         tc_hooks[tc_hook_count] = &tc_hook;
    //         tc_optses[tc_hook_count] = &tc_opts;
    //         tc_hook_count += 1;
    //     } else if (err && err != -EEXIST) {
    //         fprintf(stderr, "Failed to create TC hook in %s: %d\n", interfaces[i], err);
    //         goto cleanup;
    //     } else {
    //         fprintf(stderr, "Failed to create TC hook in %s: hook existed\n", interfaces[i]);
    //         continue;
    //     }
    //     tc_opts.prog_fd = bpf_program__fd(progs[0].prog);
    //     err = bpf_tc_attach(&tc_hook, &tc_opts);
    //     if (err) {
    //         fprintf(stderr, "Failed to attach TC in %s: %d\n", interfaces[i], err);
    //         goto cleanup;
    //     }
    // }

    for (int i = 0; i < interface_count; ++i)
    {
        snprintf(command, LEN_MAX, "tc qdisc add dev %s clsact", interfaces[i]);
        assert(system(command) == 0);
        snprintf(command, LEN_MAX, "tc filter add dev %s egress bpf object-pinned /sys/fs/bpf/EarlyPacket", interfaces[i]);
        assert(system(command) == 0);
        snprintf(command, LEN_MAX, "tc filter add dev %s ingress bpf object-pinned /sys/fs/bpf/ResendGen", interfaces[i]);
        assert(system(command) == 0);
        printf("Main BPF program attached to TC on interface %s\n", interfaces[i]);
    }

    assert(system("bpftool map pin name mpi_rank_infos /sys/fs/bpf/mpi_rank_infos") == 0);
    assert(system("bpftool map pin name rank_tmp_buff /sys/fs/bpf/rank_tmp_buff") == 0);
    assert(system("bpftool map pin name submit_rb /sys/fs/bpf/submit_rb") == 0);
    assert(system("bpftool map pin name data_blocks /sys/fs/bpf/data_blocks") == 0);
    assert(system("bpftool map pin name net_infos /sys/fs/bpf/net_infos") == 0);

    signal(SIGINT, int_exit);
    recv_finish_msg();

cleanup:
    clean_bpf();
    return 0;
    // unsigned char buffer[1000];
    // int len = xsk_init(buffer, 0);
    // #define MAGIC_LEN 4
    // #define PAYLOAD_HEADER_LEN MAGIC_LEN + sizeof(unsigned int) + sizeof(int) + sizeof(unsigned int)
    // unsigned char* result = (unsigned char*)(buffer + 16 + 42);
    // len = (len > 1000 ? 999 : len);
    // printf("recv len is %d\n", len);
    // int record = 0;
    // for (int i = 0; i < len - 16 - 42; ++i) {
    //     int value = *((unsigned int*)(result + i * sizeof(int)));
    //     printf("%d ", value);
    //     // if (i % 4 == 0) {
    //     //     printf("\n");
    //     // }
    //     // printf("%02x ", result[i]);
    // }
    // printf("\n===============================\n");
    // for (int i = 0; i < len - 16 - 42; ++i) {
    //     // int value = *((unsigned int*)(result + i * sizeof(int)));
    //     // printf("%x ", value);
    //     if (i % 4 == 0) {
    //         printf("\t");
    //     }
    //     printf("%02x ", result[i]);
    // }
    // for (int i = 0; i < tc_hook_count; ++i)
    //     bpf_tc_hook_destroy(tc_hooks[i]);
}