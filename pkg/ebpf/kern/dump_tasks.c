#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

SEC("iter/task")
int dump_tasks(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    if (seq == NULL){
        return 0;
    }
    if (!task){
        return 0;
    }

    pid_t pid = BPF_CORE_READ(task, pid);
    pid_t ppid = BPF_CORE_READ(task, tgid);
    if (pid != ppid) {
        return 0;
    }
    char comm[TASK_COMM_LEN]={0};
    BPF_CORE_READ_STR_INTO(&comm, task, comm);

    BPF_SEQ_PRINTF(seq, "pid=%d ppid=%d comm=%s\n", pid, ppid, comm);
    //BPF_SEQ_PRINTF(seq, fmt, sizeof(fmt), &tsk, sizeof(tsk));
    return 0;
}

char _license[] SEC("license") = "GPL";
