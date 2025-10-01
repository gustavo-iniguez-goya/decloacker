#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

// https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_iter_ksym.c

unsigned long last_sym_value = 0;

SEC("iter/ksym")
int dump_kmods(struct bpf_iter__ksym *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct kallsym_iter *iter = ctx->ksym;
	__u32 seq_num = ctx->meta->seq_num;
	unsigned long value;
	char type;

	if (!iter)
		return 0;

	if (seq_num == 0) {
		BPF_SEQ_PRINTF(seq, "ADDR TYPE NAME MODULE_NAME KIND MAX_SIZE\n");
		return 0;
	}
	if (last_sym_value)
		BPF_SEQ_PRINTF(seq, "0x%x\n", iter->value - last_sym_value);
	else
		BPF_SEQ_PRINTF(seq, "\n");

	value = iter->show_value ? iter->value : 0;

	last_sym_value = value;

	type = iter->type;

	if (iter->module_name[0]) {
		BPF_SEQ_PRINTF(seq, "addr=0x%llx atype=%c func=%s name=%s ",
			       value, type, iter->name, iter->module_name);
	} else {
		BPF_SEQ_PRINTF(seq, "addr=0x%llx atype=%c func=%s name=<none> ", value, type, iter->name);
	}
	if (!iter->pos_mod_end || iter->pos_mod_end > iter->pos)
		BPF_SEQ_PRINTF(seq, "type=MOD ");
	else if (!iter->pos_ftrace_mod_end || iter->pos_ftrace_mod_end > iter->pos)
		BPF_SEQ_PRINTF(seq, "type=FTRACE_MOD ");
	else if (!iter->pos_bpf_end || iter->pos_bpf_end > iter->pos)
		BPF_SEQ_PRINTF(seq, "type=BPF ");
	else
		BPF_SEQ_PRINTF(seq, "type=KPROBE ");
	return 0;
}

char _license[] SEC("license") = "GPL";
