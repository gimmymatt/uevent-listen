#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <sys/un.h>
#include <linux/types.h>
#include <linux/netlink.h>

#define HOTPLUG_BUFFER_SIZE     1024
#define HOTPLUG_NUM_ENVP        32
#define OBJECT_SIZE         512

struct uevent {
    void *next;
    char buffer[HOTPLUG_BUFFER_SIZE + OBJECT_SIZE];
    char *devpath;
    char *action;
    char *envp[HOTPLUG_NUM_ENVP];
};

static struct uevent * alloc_uevent (void)
{
    return (struct uevent *)malloc(sizeof(struct uevent));
}

int main(int argc, char *argv[])
{
    int sock;
    struct sockaddr_nl snl;
    struct sockaddr_un sun;
    socklen_t addrlen;
    int retval;
    int rcvbufsz = 128*1024;
    int rcvsz = 0;
    int rcvszsz = sizeof(rcvsz);
    unsigned int *prcvszsz = (unsigned int *)&rcvszsz;
    pthread_attr_t attr;
    const int feature_on = 1;

    memset(&snl, 0x00, sizeof(struct sockaddr_nl));
    snl.nl_family = AF_NETLINK;
    snl.nl_pid = getpid();
    snl.nl_groups = 1;

    sock = socket(PF_NETLINK, SOCK_DGRAM  , NETLINK_KOBJECT_UEVENT);
    if (sock == -1) {
        printf("error getting socket, exit\n");
        return 1;
    }

    printf("reading events from kernel.\n");

    retval = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbufsz, sizeof(rcvbufsz));
    if (retval < 0) {
        printf("error setting receive buffer size for socket, exit\n");
        exit(1);
    }

    retval = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvsz, prcvszsz);
    if (retval < 0) {
        printf("error setting receive buffer size for socket, exit\n");
        exit(1);
    }
    printf("receive buffer size for socket is %u.\n", rcvsz);

    /*  enable receiving of the sender credentials */
    setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &feature_on, sizeof(feature_on));

    retval = bind(sock, (struct sockaddr *) &snl, sizeof(struct sockaddr_nl));
    if (retval < 0) {
        printf("bind failed, exit\n");
        goto exit;
    }

    while(1) {
	static char buf[4096];
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct ucred *cred;
    	struct iovec iov[1];
        char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
	size_t bufpos=0;
	int i;
  
        memset(&msg, 0x0, sizeof(struct msghdr));
	iov[0].iov_base = buf;
        iov[0].iov_len = 100;
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
	msg.msg_control = cred_msg;
        msg.msg_controllen = sizeof(cred_msg);

        //int len = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
	if ( (retval =recvmsg(sock, &msg, 0)) <=0) {
	    printf("recvmsg error\n");
	    return -1;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
            printf("no sender credentials received, message ignored\n");
            continue;
        }
	cred = (struct ucred *)CMSG_DATA(cmsg);
        if (cred->uid != 0) {
            printf("sender uid=%d, message ignored\n", cred->uid);
            continue;
        }
	printf("==%s\n",buf);
	bufpos = strlen(buf) + 1;
	//buf[retval]='\0';
	for (i = 0; (bufpos < (size_t)retval) && (i < 32 - 1); i++) {
            int keylen;
            char *key;

            key = &buf[bufpos];
            keylen = strlen(key);
	    printf("%s\n",key);
            bufpos += keylen + 1;
        }
    }

    return 0;

exit:
    close(sock);
    return 1;
}
