#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#define pr_fmt(fmt) "%s: " fmt, __func__

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jamie K");
MODULE_DESCRIPTION("Simple module");
MODULE_VERSION("0.1");

static char symbol[KSYM_NAME_LEN] = "kernel_clone";
module_param_string(symbol, symbol, KSYM_NAME_LEN, 0664);

static struct kprobe kp = {
	.symbol_name = symbol,
};

static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs){
	pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx\n",
			p->symbol_name, p->addr, regs->ip, regs->flags);
	return 0;
}

static void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags){
	pr_info("<%s> p->addr = 0x%p, flags = 0x%lx\n",
			p->symbol_name, p->addr, regs->flags);
}

static int __init kprobe_init(void){
	int ret;
	kp.pre_handler = handler_pre;
	kp.post_handler = handler_post;
	ret = register_kprobe(&kp);
	if(ret < 0){
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted kprobe at %p\n", kp.addr);
	//printk(KERN_INFO "Loading hello module...\n");
	//printk(KERN_INFO "Hello world\n");
	return 0;
}

static void __exit kprobe_exit(void){
	// printk(KERN_INFO "Goodbye Mr.\n");
	unregister_kprobe(&kp);
	pr_info("kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init);
module_exit(kprobe_exit);
