#include "seccomp-bpf.h"
#include <fcntl.h>

#include <stdbool.h>
#include <sys/types.h>

#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <linux/audit.h>

static bool have_cap_net_admin() {
	cap_t caps = cap_get_proc();
	if (!caps)
		return false;

	cap_flag_value_t value = CAP_CLEAR;
	int rc = cap_get_flag(caps, CAP_NET_ADMIN, CAP_EFFECTIVE, &value);
	cap_free(caps);

	if (rc)
		return false;

	return value == CAP_SET;
}

static bool drop_cap_net_admin() {
	cap_t caps = cap_get_proc();
	if (!caps)
		return false;

	if (cap_clear(caps)) {
		cap_free(caps);
		return false;
	}

	int rc = cap_set_proc(caps);
	cap_free(caps);

	return rc == 0;
}

static bool install_seccomp() {
	struct sock_filter filter[] = {
		VALIDATE_ARCHITECTURE,
		EXAMINE_SYSCALL,
		ALLOW_SYSCALL(write),
		ALLOW_SYSCALL(close),
		ALLOW_SYSCALL(poll),
		ALLOW_SYSCALL(recvmsg),
		ALLOW_SYSCALL(exit_group),
		KILL_PROCESS,
	};

	struct sock_fprog fprog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl");
		return false;
	}

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog)) {
		perror("prctl2");
		return false;
	}

	return true;
}

struct child_state {
	pid_t pid;
};

static bool handle_proc_event(struct child_state *state, struct proc_event *ev) {
	switch (ev->what) {
	case PROC_EVENT_NONE:
		return true;
	case PROC_EVENT_FORK: {
		struct fork_proc_event *fork_ev = &ev->event_data.fork;
		fprintf(stderr, "fork pid=%d/tgid=%d -> pid=%d/tgid=%d\n",
			fork_ev->parent_pid,
			fork_ev->parent_tgid,
			fork_ev->child_pid,
			fork_ev->child_tgid
		);
		return true;
	}
	case PROC_EVENT_EXEC: {
		struct exec_proc_event *exec_ev = &ev->event_data.exec;
		fprintf(stderr, "exec pid=%d/tgid=%d\n",
			exec_ev->process_pid,
			exec_ev->process_tgid
		);
		return true;
	}
	case PROC_EVENT_EXIT: {
		struct exit_proc_event *exit_ev = &ev->event_data.exit;
		fprintf(stderr, "exit pid=%d/tgid=%d\n",
			exit_ev->process_pid,
			exit_ev->process_tgid
		);
		return exit_ev->process_pid != state->pid;
	}
	case PROC_EVENT_UID: {
		struct id_proc_event *proc_ev = &ev->event_data.id;
		fprintf(stderr, "uid pid=%d/tgid=%d -> ruid=%d/euid=%d\n",
			proc_ev->process_pid,
			proc_ev->process_tgid,
			proc_ev->r.ruid,
			proc_ev->e.euid
		);
		return true;
	}
	case PROC_EVENT_GID: {
		struct id_proc_event *proc_ev = &ev->event_data.id;
		fprintf(stderr, "gid pid=%d/tgid=%d -> rgid=%d/egid=%d\n",
			proc_ev->process_pid,
			proc_ev->process_tgid,
			proc_ev->r.rgid,
			proc_ev->e.egid
		);
		return true;
	}
	case PROC_EVENT_SID: {
		struct sid_proc_event *session_ev = &ev->event_data.sid;
		fprintf(stderr, "session pid=%d/tgid=%d\n",
			session_ev->process_pid,
			session_ev->process_tgid
		);
		return true;
	}
	case PROC_EVENT_COMM: {
		struct comm_proc_event *comm_ev = &ev->event_data.comm;
		fprintf(stderr, "comm pid=%d/tgid=%d: '%s'\n",
			comm_ev->process_pid,
			comm_ev->process_tgid,
			&comm_ev->comm[0]
		);
		return true;
	}
	default:
		fprintf(stderr, "unhandled event: 0x%8x\n", ev->what);
		return false;
	}
}

static bool recv_proc_event(int sock, struct child_state *state) {
	char buf[256];
	struct iovec iov[1];
	iov[0].iov_base = &buf[0];
	iov[0].iov_len = sizeof(buf);

	struct msghdr msghdr;
	struct sockaddr_nl addr;
	memset(&msghdr, '\0', sizeof(msghdr));

	msghdr.msg_name = &addr;
	msghdr.msg_namelen = sizeof(addr);
	msghdr.msg_iov = iov;
	msghdr.msg_iovlen = 1;

	ssize_t len = recvmsg(sock, &msghdr, 0);
	if (len < 0) {
		perror("recvmsg");
		return false;
	}
	if (addr.nl_pid != 0)
		return true;

	for (struct nlmsghdr *nlmsghdr = (struct nlmsghdr *)buf;
	     NLMSG_OK(nlmsghdr, len);
	     nlmsghdr = NLMSG_NEXT(nlmsghdr, len)) {
		struct cn_msg *cn_msg = NLMSG_DATA(nlmsghdr);
		if (cn_msg->id.idx == CN_IDX_PROC && cn_msg->id.val == CN_VAL_PROC) {
			struct proc_event *ev = (void *)&cn_msg->data;
			if (!handle_proc_event(state, ev))
				return false;
		}
	}

	return true;
}

const char SYNC_VALUE = 'S';
static void spawn_child(int sync_sock, char **argv) {
	char sync_byte = 0;
	int rc = read(sync_sock, &sync_byte, sizeof(sync_byte));
	close(sync_sock);

	if (rc == 1 && sync_byte == SYNC_VALUE)
		execv(argv[0], argv);
	exit(1);
}

int main(int argc, char **argv) {
	int sock;
	int rc;

	if (argc < 2)
		return 1;

	if (!have_cap_net_admin())
		return 1;

	sock = socket(
		PF_NETLINK,
		SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
		NETLINK_CONNECTOR
	);

	if (sock < 0) {
		perror("socket");
		return 1;
	}

	struct sockaddr_nl addr;
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();
	addr.nl_groups = CN_IDX_PROC;

	rc = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		perror("bind");
		close(sock);
		return 1;
	}

	if (!drop_cap_net_admin())
		return 1;

	if (have_cap_net_admin())
		/* This should never succeed */
		return 1;

	int sync[2];
	rc = pipe2(sync, O_CLOEXEC);
	if (rc) {
		perror("pipe2");
		return 1;
	}

	pid_t child_pid = fork();
	if (child_pid == 0)
		spawn_child(sync[0], &argv[1]);

	struct child_state state = { .pid = child_pid };

	struct pollfd pollfds[1];
	pollfds[0].fd = sock;
	pollfds[0].events = POLLIN;

	if (!install_seccomp()) {
		char q = 'X';
		write(sync[1], &q, sizeof(q));
		close(sync[1]);
		return 1;
	}

	char q = SYNC_VALUE;
	write(sync[1], &q, sizeof(q));
	close(sync[1]);

	while (true) {
		int rc = poll(pollfds, 1, -1);
		if (rc < 0) {
			perror("poll");
			return 1;
		}

		if (pollfds[0].revents & POLLIN)
			if (!recv_proc_event(sock, &state))
				break;
	}

	_exit(0);
}
