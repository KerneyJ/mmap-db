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

static struct sock *socket = NULL;

// kpmmap_post
static char sym_mmap[KSYM_NAME_LEN] = "do_mmap";
module_param_string(sym_mmap, sym_mmap, KSYM_NAME_LEN, 0664);
static struct kprobe kp_mmap = {
	.symbol_name = sym_mmap,
};

int clientpid = -1;

static int send_msg(char* msg, int probe){
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	char res, msg_size;
	if(probe)
		return 0;

	if(clientpid < 0) // check that there is a user to send info to
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
	res = nlmsg_unicast(socket, skb_out, clientpid);
	if(res < 0){
		printk(KERN_INFO "Error while sending back to user\n");
		return -1;
	}
	return 0;
}

static int __kprobes kpmmap_pre(struct kprobe *p, struct pt_regs *regs){
	//ktime_t kt = ktime_get_boottime();
	//uint64_t ul_addr = regs->si;
	//uint64_t ul_len = regs->dx;
	char msg[MAX_PAYLOAD];
	snprintf(msg, MAX_PAYLOAD, "pre_mmap"); // ,%lli,0x%p,0x%p,0,0,0,%llu",kt, ul_addr, virt_to_phys(ul_addr), ul_len);
	if(send_msg(msg, 1) < 0)
		return -1;
	return 0;
}

static void __kprobes kpmmap_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags){
	//ktime_t kt = ktime_get_boottime();
	//unsigned long mapped_addr = regs->ax;
	char msg[MAX_PAYLOAD];
	snprintf(msg, MAX_PAYLOAD, "post_mmap"); // ,%lli,0x%p,0x%p,0,0,0,0", kt, mapped_addr, virt_to_phys(mapped_addr));
	if(send_msg(msg, 1) < 0)
		printk(KERN_INFO "Error sending message to userspace");
}

static void register_process(struct sk_buff *skb){
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	char *msg = "ack";
	int res, msg_size;

	msg_size = strlen(msg);

	nlh = (struct nlmsghdr*)skb->data;

	//if(kstrtoint((char*)nlmsg_data(nlh), 10, &stalkpid) < 0)
	//	printk(KERN_INFO "Error turning string to int");
	clientpid = nlh->nlmsg_pid;

	printk(KERN_INFO "Registration socket received init msg: %s\n", (char*)nlmsg_data(nlh));

	skb_out = nlmsg_new(msg_size, 0);
	if(!skb_out){
		printk(KERN_ERR "Failed to allocate new skb\n");
		return;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	strncpy(nlmsg_data(nlh), msg, msg_size);

	res = nlmsg_unicast(socket, skb_out, clientpid);
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
		return -1;
	}

	kp_mmap.pre_handler = kpmmap_pre;
	kp_mmap.post_handler = kpmmap_post;
	if( (ret = register_kprobe(&kp_mmap)) < 0){
		pr_err("register kp_mmap failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted kprobe mmap at %p\n", kp_mmap.addr);
	return 0;
}

static void __exit kprobe_exit(void){
	unregister_kprobe(&kp_mmap);
	pr_info("kprobe mmap  %p unregistered\n", kp_mmap.addr);

	netlink_kernel_release(socket);
}

module_init(kprobe_init);
module_exit(kprobe_exit);
