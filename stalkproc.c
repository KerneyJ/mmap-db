#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NETLINK_USER 31

#define MAX_PAYLOAD 1024

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

int main(int argc, char** argv){
	if(argc < 2){
		printf("not enough arguments\n");
		printf("format: ./stalkproc [PID]\n");
		return -1;
	}
	
	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
	if(sock_fd < 0)
		return -1;

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();

	bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	strcpy(NLMSG_DATA(nlh), argv[1]); // send the pid of the process to stalk

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	printf("Sending message to kernel\n");
	sendmsg(sock_fd, &msg, 0);
	printf("Waiting for message from kernel\n");

	recvmsg(sock_fd, &msg, 0);
	printf("Received message payload: %s\n", (char *)NLMSG_DATA(nlh));
	while(1){
		recvmsg(sock_fd, &msg, 0);
		printf("Received message pauload: %s\n", (char *)NLMSG_DATA(nlh));
	}
}

