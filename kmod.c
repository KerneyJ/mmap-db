#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#define pr_fmt(fmt) "%s: " fmt, __func__

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jamie K");
MODULE_DESCRIPTION("Simple module");
MODULE_VERSION("0.1");

static char sym_mmap[KSYM_NAME_LEN] = "do_mmap";
static char sym_wrpage[KSYM_NAME_LEN] = "swap_writepage";
static char sym_rdpage[KSYM_NAME_LEN] = "swap_readpage";
module_param_string(sym_mmap, sym_mmap, KSYM_NAME_LEN, 0664);
module_param_string(sym_rdpage, sym_rdpage, KSYM_NAME_LEN, 0664);
module_param_string(sym_wrpage, sym_wrpage, KSYM_NAME_LEN, 0664);

static struct kprobe kp_mmap = {
	.symbol_name = sym_mmap,
};

static struct kprobe kp_wrpage = {
	.symbol_name = sym_wrpage,
};

static struct kprobe kp_rdpage = {
	.symbol_name = sym_rdpage,
};

static int __kprobes kpmmap_pre(struct kprobe *p, struct pt_regs *regs){
	pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx, pid = %d\n",
			p->symbol_name, p->addr, regs->ip, regs->flags, current->pid);
	return 0;
}

static void __kprobes kpmmap_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags){
	pr_info("<%s> p->addr = 0x%p, flags = 0x%lx\n",
			p->symbol_name, p->addr, regs->flags);
}

static int __kprobes kpwrpage_pre(struct kprobe *p, struct pt_regs *regs){
	pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx, pid = %d\n",
			p->symbol_name, p->addr, regs->ip, regs->flags, current->pid);
	return 0;
}

static void __kprobes kpwrpage_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags){
	pr_info("<%s> p->addr = 0x%p, flags = 0x%lx\n",
			p->symbol_name, p->addr, regs->flags);
}

static int __kprobes kprdpage_pre(struct kprobe *p, struct pt_regs *regs){
	pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx, pid = %d\n",
			p->symbol_name, p->addr, regs->ip, regs->flags, current->pid);
	return 0;
}

static void __kprobes kprdpage_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags){
	pr_info("<%s> p->addr = 0x%p, flags = 0x%lx\n",
			p->symbol_name, p->addr, regs->flags);
}

static int __init kprobe_init(void){
	int ret;
	kp_mmap.pre_handler = kpmmap_pre;
	kp_mmap.post_handler = kpmmap_post;
	kp_wrpage.pre_handler = kpwrpage_pre;
	kp_wrpage.post_handler = kpwrpage_post;
	kp_rdpage.pre_handler = kprdpage_pre;
	kp_rdpage.post_handler = kprdpage_post;
	if( (ret = register_kprobe(&kp_mmap)) < 0){
		pr_err("register kp_mmap failed, returned %d\n", ret);
		return ret;
	}
	if( (ret = register_kprobe(&kp_wrpage)) < 0){
		pr_err("register kp_wrpage failed, returned %d\n", ret);
		return ret;
	}
	if((ret = register_kprobe(&kp_rdpage)) < 0){
		pr_err("register kp_rdpage failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted kprobe mmap at %p\n", kp_mmap.addr);
	pr_info("Planted kprobe wrpage at %p\n", kp_wrpage.addr);
	pr_info("Planted kprobe rdpage at %p\n", kp_rdpage.addr);
	return 0;
}

static void __exit kprobe_exit(void){
	unregister_kprobe(&kp_mmap);
	unregister_kprobe(&kp_wrpage);
	unregister_kprobe(&kp_rdpage);
	pr_info("kprobe mmap  %p unregistered\n", kp_mmap.addr);
	pr_info("kprobe wrpage %p unregistered\n", kp_wrpage.addr);
	pr_info("kprobe rdpage %p unregistered\n", kp_rdpage.addr);
}

module_init(kprobe_init);
module_exit(kprobe_exit);
