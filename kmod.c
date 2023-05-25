/*
 * FIXME Might not work with multithreaded programs, cause different threads could try to access the socket simultaneously. But if there is some internal lock on the socket then there should be no problem
 */

#include <linux/module.h>
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

static char sym_mmap[KSYM_NAME_LEN] = "do_mmap";
static char sym_swap[KSYM_NAME_LEN] = "do_swap_page";
module_param_string(sym_mmap, sym_mmap, KSYM_NAME_LEN, 0664);
module_param_string(sym_swap, sym_swap, KSYM_NAME_LEN, 0664);

static struct kprobe kp_mmap = {
	.symbol_name = sym_mmap,
};

static struct kprobe kp_swap = {
	.symbol_name = sym_swap,
};


static int __kprobes kpmmap_pre(struct kprobe *p, struct pt_regs *regs){
	//pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx, pid = %d\n",
	//		p->symbol_name, p->addr, regs->ip, regs->flags, current->pid);
	return 0;
}

static void __kprobes kpmmap_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags){
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	char msg[MAX_PAYLOAD];
	int res, msg_size;

	pr_info("symbol: %s, pid: %d\n", p->symbol_name, current->pid);
	if(current->pid != stalkpid)
		return;

	if(pid < 0)
		return;

	snprintf(msg, MAX_PAYLOAD, "<%s>, p->addr = ox%p, flags = 0x%lx, pid = %d\n", p->symbol_name, p->addr, regs->flags, current->pid);
	msg_size = strlen(msg);

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

static int __kprobes kpswap_pre(struct kprobe *p, struct pt_regs *regs){
//	pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx, pid = %d\n",
//			p->symbol_name, p->addr, regs->ip, regs->flags, current->pid);
	return 0;
}

static void __kprobes kpswap_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags){
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	char msg[MAX_PAYLOAD];
	int res, msg_size;

	pr_info("symbol: %s, pid: %d\n", p->symbol_name, current->pid);
	if(current->pid != stalkpid)
		return;

	if(pid < 0)
		return;

	snprintf(msg, MAX_PAYLOAD, "<%s>, p->addr = ox%p, flags = 0x%lx, pid = %d\n", p->symbol_name, p->addr, regs->flags, current->pid);
	msg_size = strlen(msg);

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

static void register_process(struct sk_buff *skb){
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	char *msg = "ack";
	int res, msg_size;

	msg_size = strlen(msg);

	nlh = (struct nlmsghdr*)skb->data;

	kstrtoint((char*)nlmsg_data(nlh), 10, &stalkpid);
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
	if( (ret = register_kprobe(&kp_mmap)) < 0){
		pr_err("register kp_mmap failed, returned %d\n", ret);
		return ret;
	}
	if( (ret = register_kprobe(&kp_swap)) < 0){
		pr_err("register kp_wrpage failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted kprobe mmap at %p\n", kp_mmap.addr);
	pr_info("Planted kprobe wrpage at %p\n", kp_swap.addr);
	return 0;
}

static void __exit kprobe_exit(void){
	unregister_kprobe(&kp_mmap);
	unregister_kprobe(&kp_swap);
	pr_info("kprobe mmap  %p unregistered\n", kp_mmap.addr);
	pr_info("kprobe wrpage %p unregistered\n", kp_swap.addr);

	netlink_kernel_release(socket);
}

module_init(kprobe_init);
module_exit(kprobe_exit);
