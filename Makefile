obj-m = kmod.o netkmod.o
all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

usrprog:
	gcc user_prog.c -o user_prog
