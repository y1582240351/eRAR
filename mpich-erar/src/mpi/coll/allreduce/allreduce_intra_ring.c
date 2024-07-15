/* -*- Mode: C; c-basic-offset:4 ; indent-tabs-mode:nil ; -*- */
/*
 *  Copyright (C) by Argonne National Laboratory.
 *     See COPYRIGHT in top-level directory.
 *
 */
/* Routine to schedule a ring exchange based allreduce. The algorithm is
 * based on Baidu's ring based allreduce. http://andrew.gibiansky.com/ */

#include "mpiimpl.h"
// #include "afxdp.h"
#include "ebpf_helper.h"

int MPIR_Allreduce_intra_ring(const void *sendbuf, void *recvbuf, MPI_Aint count,
                              MPI_Datatype datatype, MPI_Op op,
                              MPIR_Comm *comm, MPIR_Errflag_t *errflag)
{
    // int tmp_fd = bpf_obj_get("/sys/fs/bpf/mpi_rank_infos");
    // if (tmp_fd < 0)
    // {
    //     printf("Error!\n");
    // }
    // else
    // {
    //     printf("Right\n");
    // }

    int mpi_errno = MPI_SUCCESS, mpi_errno_ret = MPI_SUCCESS;
    int i, src, dst;
    int nranks, is_inplace, rank;
    size_t extent;
    MPI_Aint lb, true_extent;
    MPI_Aint *cnts, *displs; /* Created for the allgatherv call */
    int send_rank, recv_rank, total_count, segcount;
    void *tmpbuf;
    char *tmpsend = NULL;
    int tag;
    int block_count;
    MPIR_Request *reqs[2]; /* one send and one recv per transfer */

    // printf("In Ring AllReduce\n");

    is_inplace = (sendbuf == MPI_IN_PLACE);
    nranks = MPIR_Comm_size(comm);
    rank = MPIR_Comm_rank(comm);

    // 这个extent和openmpi中的extent是一样的，表示数组中元素type的大小
    MPIR_Datatype_get_extent_macro(datatype, extent);
    MPIR_Type_get_true_extent_impl(datatype, &lb, &true_extent);
    extent = MPL_MAX(extent, true_extent);

    cnts = (MPI_Aint *)MPL_malloc(nranks * sizeof(MPI_Aint), MPL_MEM_COLL);
    MPIR_ERR_CHKANDJUMP(!cnts, mpi_errno, MPI_ERR_OTHER, "**nomem");
    displs = (MPI_Aint *)MPL_malloc(nranks * sizeof(MPI_Aint), MPL_MEM_COLL);
    MPIR_ERR_CHKANDJUMP(!displs, mpi_errno, MPI_ERR_OTHER, "**nomem");

    for (i = 0; i < nranks; i++)
        cnts[i] = 0;

    total_count = 0;
    // cnts 记录了每个rank需要负责多少个元素的allreduce（需要allreduce的数量不一定等于rank的数量，有可能大于）
    // 这个cnts计算的方法是：对count取最小被nranks整除的上界，前面cnts[i]就是这个上界整除nranks之后的值，
    // 最后一个cnts[i]会比前面的cnts[i]小一点
    for (i = 0; i < nranks; i++)
    {
        cnts[i] = (count + nranks - 1) / nranks;
        if (total_count + cnts[i] > count)
        {
            cnts[i] = count - total_count;
            break;
        }
        else
            total_count += cnts[i];
    }
    segcount = (count + nranks - 1) / nranks;

    displs[0] = 0;
    // 每个rank负责元素的起始位置
    for (i = 1; i < nranks; i++)
        displs[i] = displs[i - 1] + cnts[i - 1];

    /* Phase 1: copy to tmp buf */
    if (!is_inplace)
    {
        mpi_errno = MPIR_Localcopy(sendbuf, count, datatype, recvbuf, count, datatype);
        if (mpi_errno)
        {
            MPIR_ERR_POP(mpi_errno);
        }
    }

    char *is_set = getenv("MPI_EBPF_ALLREDUCE");
    is_float = false;
    if (nranks < MAX_RANK_SIZE && segcount < MAX_BUF_SIZE && (datatype == MPI_INT || datatype == MPI_FLOAT) && is_set != NULL && op == MPI_SUM)
    {
        if (datatype == MPI_FLOAT) {
            is_float = true;
        }
        // printf("eBPF Allreduce\n");
        int ret = allreduce_ebpf(rank, nranks, segcount, block_count, cnts, displs, recvbuf, extent, comm, errflag);
        if (ret != 0)
        {
            printf("eBPF Allreduce error!\n");
        }
    }
    else
    {
        /* Phase 2: Ring based send recv reduce scatter */
        /* Need only 2 spaces for current and previous reduce_id(s) */
        tmpbuf = MPL_malloc(count * extent, MPL_MEM_COLL);
        MPIR_ERR_CHKANDJUMP(!tmpbuf, mpi_errno, MPI_ERR_OTHER, "**nomem");

        src = (nranks + rank - 1) % nranks;
        dst = (rank + 1) % nranks;
        struct timespec start_time, end_time, resend_start_time, resend_test_time;
        long long execution_time;

        clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
        // ==================================================

        for (i = 0; i < nranks - 1; i++)
        {
            recv_rank = (nranks + rank - 2 - i) % nranks;
            send_rank = (nranks + rank - 1 - i) % nranks;

            /* get a new tag to prevent out of order messages */
            mpi_errno = MPIR_Sched_next_tag(comm, &tag);
            if (mpi_errno)
                MPIR_ERR_POP(mpi_errno);

            mpi_errno = MPIC_Irecv(tmpbuf, cnts[recv_rank], datatype, src, tag, comm, &reqs[0]);
            if (mpi_errno)
            {
                /* for communication errors, just record the error but continue */
                *errflag = MPIR_ERR_OTHER;
                MPIR_ERR_SET(mpi_errno, *errflag, "**fail");
                MPIR_ERR_ADD(mpi_errno_ret, mpi_errno);
            }

            mpi_errno = MPIC_Isend((char *)recvbuf + displs[send_rank] * extent, cnts[send_rank],
                                   datatype, dst, tag, comm, &reqs[1], errflag);
            if (mpi_errno)
            {
                /* for communication errors, just record the error but continue */
                *errflag = MPIR_ERR_OTHER;
                MPIR_ERR_SET(mpi_errno, *errflag, "**fail");
                MPIR_ERR_ADD(mpi_errno_ret, mpi_errno);
            }

            mpi_errno = MPIC_Waitall(2, reqs, MPI_STATUSES_IGNORE, errflag);
            if (mpi_errno)
            {
                /* for communication errors, just record the error but continue */
                *errflag = MPIR_ERR_OTHER;
                MPIR_ERR_SET(mpi_errno, *errflag, "**fail");
                MPIR_ERR_ADD(mpi_errno_ret, mpi_errno);
            }

            mpi_errno =
                MPIR_Reduce_local(tmpbuf, (char *)recvbuf + displs[recv_rank] * extent,
                                  cnts[recv_rank], datatype, op);
            if (mpi_errno)
            {
                /* for communication errors, just record the error but continue */
                *errflag = MPIR_ERR_OTHER;
                MPIR_ERR_SET(mpi_errno, *errflag, "**fail");
                MPIR_ERR_ADD(mpi_errno_ret, mpi_errno);
            }
        }

        /* Phase 3: Allgatherv ring, so everyone has the reduced data */
        mpi_errno = MPIR_Allgatherv_intra_ring(MPI_IN_PLACE, -1, MPI_DATATYPE_NULL, recvbuf, cnts,
                                               displs, datatype, comm, errflag);
        if (mpi_errno)
        {
            /* for communication errors, just record the error but continue */
            *errflag = MPIR_ERR_OTHER;
            MPIR_ERR_SET(mpi_errno, *errflag, "**fail");
            MPIR_ERR_ADD(mpi_errno_ret, mpi_errno);
        }

        // clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
        // execution_time = (end_time.tv_sec - start_time.tv_sec) * 1000000LL +
        //                  (end_time.tv_nsec - start_time.tv_nsec) / 1000LL;
        // if (rank == 0) {
        //     printf("rank: %d, MPI execution time: %lld microseconds, sequence_id: %d\n", rank, execution_time, curr_sequence_id);
        //     curr_sequence_id += 1;
        
        //     if (nranks < MAX_RANK_SIZE && segcount < MAX_BUF_SIZE && datatype == MPI_INT) {
        //         for (int i = 0; i < count; ++i) {
        //             int* tmp = recvbuf;
        //             printf("%d ", *tmp);
        //             tmp += sizeof(int);
        //         }
        //         printf("\n");
        //     }
        // }

        MPL_free(tmpbuf);
    }

    MPL_free(cnts);
    MPL_free(displs);

fn_exit:
    if (mpi_errno_ret)
        mpi_errno = mpi_errno_ret;
    else if (*errflag != MPIR_ERR_NONE)
        MPIR_ERR_SET(mpi_errno, *errflag, "**coll_fail");

    return mpi_errno;

fn_fail:
    goto fn_exit;
}
