/*
   VG_(printf)(" M %08lx,%lu\n", addr, size);
 * FIXME Might not work with multithreaded programs, cause different threads could try to access the socket simultaneously. But if there is some internal lock on the socket then there should be no problem
 */

#include <linux/time.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#define MAX_PAYLOAD 256
#define NETLINK_USER 31
#define pr_fmt(fmt) "%s: " fmt, __func__

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jamie K");
MODULE_DESCRIPTION("Simple module");
MODULE_VERSION("0.1");

static int stalkpid = -1;
static int pid = -1;
static struct sock *socket = NULL;

// kpmmap_post
static char sym_mmap[KSYM_NAME_LEN] = "do_mmap";
// kpswap_pre 
static char sym_swap[KSYM_NAME_LEN] = "do_swap_page";
// kphmf_pre
static char sym_hmf[KSYM_NAME_LEN] = "handle_mm_fault"; // hmf = handle_mm_fault
module_param_string(sym_mmap, sym_mmap, KSYM_NAME_LEN, 0664);
module_param_string(sym_swap, sym_swap, KSYM_NAME_LEN, 0664);
module_param_string(sym_hmf, sym_hmf, KSYM_NAME_LEN, 0664);

static struct kprobe kp_mmap = {
	.symbol_name = sym_mmap,
};

static struct kprobe kp_swap = {
	.symbol_name = sym_swap,
};

static struct kprobe kp_hmf = {
	.symbol_name = sym_hmf,
};

static int send_msg(char* msg, int stalk){
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	char res, msg_size;
	if(stalk && stalkpid != current->pid)
		return 0;

	if(pid < 0) // check that there is a user to send info to
		return -1;
	pr_info("sending: %s", msg);
	msg_size = strlen(msg);
	skb_out = nlmsg_new(msg_size, 0);
	if(!skb_out){
		printk(KERN_ERR "Failed to allocate new skb\n");
		return -1;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	strncpy(nlmsg_data(nlh), msg, msg_size);
	res = nlmsg_unicast(socket, skb_out, pid);
	if(res < 0){
		printk(KERN_INFO "Error while sending back to user\n");
		return -1;
	}
	return 0;
}

static int __kprobes kpmmap_pre(struct kprobe *p, struct pt_regs *regs){
	ktime_t kt = ktime_get_boottime();
	//uint64_t* sp = (uint64_t*)regs->sp;
	//uint64_t* file_file = (uint64_t*)regs->di;
	uint64_t ul_addr = regs->si;
	uint64_t ul_len = regs->dx;
	//uint64_t* ul_prot = (uint64_t*)regs->cx;
	//uint64_t* ul_flags = (uint64_t*)regs->r8;
	//uint64_t* ul_pgoff = (uint64_t*)regs->r9;
	//uint64_t* ul_populate = (uint64_t*)(sp+1);
	//uint64_t* listhead_uf = (uint64_t*)(sp);
	char msg[MAX_PAYLOAD];
	snprintf(msg, MAX_PAYLOAD, "pre_mmap,%lli,0x%p,0x%p,0,0,0,%llu",kt, ul_addr, virt_to_phys(ul_addr), ul_len);
	if(send_msg(msg, 1) < 0)
		return -1;
	return 0;
}

static void __kprobes kpmmap_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags){
	char msg[MAX_PAYLOAD];
	unsigned long mapped_addr = regs->ax;
	ktime_t kt = ktime_get_boottime();

	snprintf(msg, MAX_PAYLOAD, "post_mmap,%lli,0x%p,0x%p,0,0,0,0", kt, mapped_addr, virt_to_phys(mapped_addr));
	if(send_msg(msg, 1) < 0)
		printk(KERN_INFO "Error sending message to userspace");
}

static int __kprobes kpswap_pre(struct kprobe *p, struct pt_regs *regs){
	ktime_t kt = ktime_get_boottime();
	struct vm_fault* vmf = (struct vm_fault*)regs->di;
	char msg[MAX_PAYLOAD];
	snprintf(msg, MAX_PAYLOAD, "pre_swap,%lli,0,0,0x%p,0x%p,0,0",kt,vmf->address,virt_to_phys(vmf->address));
	if(send_msg(msg, 0) < 0)
		printk(KERN_INFO "Some error in sending message to userspace");

	//pr_info("pid: %d swap: 0x%p, at time %li\n", current->pid, vmf->address, kt);
	//pr_info("pid %d swap: pte at time of fault 0x%p, pte 0x%p\n", current->pid, vmf->orig_pte, vmf->pte);
	//pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx, pid = %d\n",
	//		p->symbol_name, p->addr, regs->ip, regs->flags, current->pid);
	return 0;
}

static void __kprobes kpswap_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags){
	ktime_t kt = ktime_get_boottime();
	char msg[MAX_PAYLOAD];
	uint64_t vmf_reason = regs->ax;
	snprintf(msg, MAX_PAYLOAD, "post_swap,%lli,0,0,0,0,%llu,0",kt,vmf_reason);
	if(send_msg(msg, 0) < 0)
		printk(KERN_INFO "Error in sending message to userspace");
}

static int __kprobes kphmf_pre(struct kprobe *p, struct pt_regs *regs){
	//uint64_t vma_pointer = (uint64_t)regs->di;
	uint64_t ul_address = (uint64_t)regs->si;
	//uint64_t ui_flags = (uint64_t)regs->dx;
	//uint64_t ptregs_regs = (uint64_t)regs->cx;
	//pr_info("hmf: faulting address 0x%p, flags 0x%p\n", ul_address, ui_flags);
	//pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx, pid = %d\n",
	//		p->symbol_name, p->addr, regs->ip, regs->flags, current->pid);
	ktime_t kt = ktime_get_boottime();
	char msg[MAX_PAYLOAD];
	snprintf(msg, MAX_PAYLOAD, "pre_hmf,%lli,0x%p,0x%p,0,0,0,0", kt, ul_address, virt_to_phys(ul_address));
	if(send_msg(msg, 1) < 0)
		printk(KERN_INFO "Error while sending back to user\n");

	return 0;
}

static void __kprobes kphmf_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags){
	ktime_t kt = ktime_get_boottime();
	char msg[MAX_PAYLOAD];
	uint64_t vmf_reason = regs->ax;
	snprintf(msg, MAX_PAYLOAD, "post_hmf,%lli,0,0,0,0,%llu,0", kt, vmf_reason);
	if(send_msg(msg, 1) < 0)
		printk(KERN_INFO "Error while sending back to user\n");
}


static void register_process(struct sk_buff *skb){
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	char *msg = "ack";
	int res, msg_size;

	msg_size = strlen(msg);

	nlh = (struct nlmsghdr*)skb->data;

	if(kstrtoint((char*)nlmsg_data(nlh), 10, &stalkpid) < 0)
		printk(KERN_INFO "Error turning string to int");
	pid = nlh->nlmsg_pid;

	printk(KERN_INFO "Registration socket received msg payload: %d\n", stalkpid);

	skb_out = nlmsg_new(msg_size, 0);
	if(!skb_out){
		printk(KERN_ERR "Failed to allocate new skb\n");
		return;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	strncpy(nlmsg_data(nlh), msg, msg_size);

	res = nlmsg_unicast(socket, skb_out, pid);
	if(res < 0)
		printk(KERN_INFO "Error while sending back to user\n");
}

static int __init kprobe_init(void){
	struct netlink_kernel_cfg cfg = {
		.input = register_process,
	};
	int ret;

	socket = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	if(!socket){
		printk(KERN_ALERT "Error creating socket.\n");
		return -10;
	}

	kp_mmap.pre_handler = kpmmap_pre;
	kp_mmap.post_handler = kpmmap_post;
	kp_swap.pre_handler = kpswap_pre;
	kp_swap.post_handler = kpswap_post;
	kp_hmf.pre_handler = kphmf_pre;
	kp_hmf.post_handler = kphmf_post;
	if( (ret = register_kprobe(&kp_mmap)) < 0){
		pr_err("register kp_mmap failed, returned %d\n", ret);
		return ret;
	}
	if( (ret = register_kprobe(&kp_swap)) < 0){
		pr_err("register kp_wrpage failed, returned %d\n", ret);
		return ret;
	}
	if( (ret = register_kprobe(&kp_hmf)) < 0){
		pr_err("register kp_hmf failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted kprobe mmap at %p\n", kp_mmap.addr);
	pr_info("Planted kprobe swap at %p\n", kp_swap.addr);
	pr_info("Planted kprobe handle_mm_swap at %p\n", kp_hmf.addr);
	return 0;
}

static void __exit kprobe_exit(void){
	unregister_kprobe(&kp_mmap);
	unregister_kprobe(&kp_swap);
	unregister_kprobe(&kp_hmf);
	pr_info("kprobe mmap  %p unregistered\n", kp_mmap.addr);
	pr_info("kprobe wrpage %p unregistered\n", kp_swap.addr);
	pr_info("kprobe handle_mm_swap %p unregistered\n", kp_hmf.addr);

	netlink_kernel_release(socket);
}

module_init(kprobe_init);
module_exit(kprobe_exit);
