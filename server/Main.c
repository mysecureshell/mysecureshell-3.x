#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PATH_CMDLINE	"cmdline"
#define PATH_CMDLINEl       strlen(PATH_CMDLINE)
#define PATH_FD_SUFF	"fd"
#define PATH_FD_SUFFl       strlen(PATH_FD_SUFF)
#define PATH_PROC	   "/proc"
#define PATH_PROC_X_FD      PATH_PROC "/%s/" PATH_FD_SUFF
#define PRG_SOCKET_PFX    "socket:["
#define PRG_SOCKET_PFXl (strlen(PRG_SOCKET_PFX))
#define PRG_SOCKET_PFX2   "[0000]:"
#define PRG_SOCKET_PFX2l  (strlen(PRG_SOCKET_PFX2))
#define PROGNAME_WIDTH 20
//#define LINE_MAX 4096
#define PORT 2020

static void extract_type_1_socket_inode(const char lname[], long * inode_p)
{

	/* If lname is of the form "socket:[12345]", extract the "12345"
	 as *inode_p.  Otherwise, return -1 as *inode_p.
	 */

	if (strlen(lname) < PRG_SOCKET_PFXl + 3)
		*inode_p = -1;
	else if (memcmp(lname, PRG_SOCKET_PFX, PRG_SOCKET_PFXl))
		*inode_p = -1;
	else if (lname[strlen(lname) - 1] != ']')
		*inode_p = -1;
	else
	{
		char inode_str[strlen(lname + 1)]; /* e.g. "12345" */
		const int inode_str_len = strlen(lname) - PRG_SOCKET_PFXl - 1;
		char *serr;

		strncpy(inode_str, lname + PRG_SOCKET_PFXl, inode_str_len);
		inode_str[inode_str_len] = '\0';
		*inode_p = strtol(inode_str, &serr, 0);
		if (!serr || *serr || *inode_p < 0 || *inode_p >= INT_MAX)
			*inode_p = -1;
	}
}

static void extract_type_2_socket_inode(const char lname[], long * inode_p)
{
	/* If lname is of the form "[0000]:12345", extract the "12345"
	 as *inode_p.  Otherwise, return -1 as *inode_p.
	 */

	if (strlen(lname) < PRG_SOCKET_PFX2l + 1)
		*inode_p = -1;
	else if (memcmp(lname, PRG_SOCKET_PFX2, PRG_SOCKET_PFX2l))
		*inode_p = -1;
	else
	{
		char *serr;

		*inode_p = strtol(lname + PRG_SOCKET_PFX2l, &serr, 0);
		if (!serr || *serr || *inode_p < 0 || *inode_p >= INT_MAX)
			*inode_p = -1;
	}
}

static void finish_this_one(int searchUid, unsigned long searchInode)
{
	char line[LINE_MAX];
	int procfdlen, lnamelen;
	char lname[30], cmdlbuf[512];
	long inode;
	const char *cs;
	DIR *dirproc = NULL, *dirfd = NULL;
	struct dirent *direproc, *direfd;

	cmdlbuf[sizeof(cmdlbuf) - 1] = '\0';
	if (!(dirproc = opendir(PATH_PROC)))
		return;
	while (errno = 0, direproc = readdir(dirproc))
	{
#ifdef DIRENT_HAVE_D_TYPE_WORKS
		if (direproc->d_type!=DT_DIR) continue;
#endif
		for (cs = direproc->d_name; *cs; cs++)
			if (!isdigit(*cs))
				break;
		if (*cs)
			continue;
		procfdlen = snprintf(line, sizeof(line), PATH_PROC_X_FD, direproc->d_name);
		if (procfdlen <= 0 || procfdlen >= sizeof(line) - 5)
			continue;
		dirfd = opendir(line);
		if (!dirfd)
			continue;
		line[procfdlen] = '/';
		while ((direfd = readdir(dirfd)))
		{
#ifdef DIRENT_HAVE_D_TYPE_WORKS
			if (direfd->d_type != DT_LNK)
				continue;
#endif
			if (procfdlen + 1 + strlen(direfd->d_name) + 1 > sizeof(line))
				continue;
			memcpy(line + procfdlen - PATH_FD_SUFFl, PATH_FD_SUFF "/", PATH_FD_SUFFl + 1);
			strcpy(line + procfdlen + 1, direfd->d_name);
			lnamelen = readlink(line, lname, sizeof(lname) - 1);
			lname[lnamelen] = '\0';
			extract_type_1_socket_inode(lname, &inode);
			if (inode < 0)
				extract_type_2_socket_inode(lname, &inode);
			if (inode < 0)
				continue;
			if (inode == searchInode)
			{
				snprintf(cmdlbuf, sizeof(cmdlbuf), "/proc/%s/exe", direproc->d_name);
				printf("Try to readfile: %s\n", cmdlbuf);
				if (readlink(cmdlbuf, line, sizeof(line)) > 0)
					printf("APP: %s\n", line);
			}
		}
		closedir(dirfd);
		dirfd = NULL;
	}
	if (dirproc)
		closedir(dirproc);
	if (dirfd)
		closedir(dirfd);
}

static void tcp_do_one(int lnr, const char *line, int localClientPort)
{
	unsigned long rxq, txq, time_len, retr, inode;
	int num, local_port, rem_port, d, state, uid, timer_run, timeout;
	char rem_addr[128], local_addr[128], more[512];

	if (lnr == 0)
		return;

	num = sscanf(line,
					"%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %ld %512s\n",
					&d, local_addr, &local_port, rem_addr, &rem_port, &state,
					&txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout,
					&inode, more);

	if (num < 11)
	{
		fprintf(stderr, "warning, got bogus tcp line.\n");
		return;
	}
	//printf("%d == %d ??? %s\n", local_port, localClientPort, line);
	if (local_port == localClientPort)
	{
		printf("-> %s\n", line);
		finish_this_one(uid, inode);
	}
}

static int tcp_do(int localClientPort)
{
	FILE *fh;

	if ((fh = fopen("/proc/net/tcp", "r")) == NULL)
		perror("Unable to open proc/tcp");
	else
	{
		char line[1024];
		int nbLines = 0;

		while (fgets(line, sizeof(line), fh) != NULL)
		{
			tcp_do_one(nbLines, line, localClientPort);
			nbLines++;
		}
	}
	return 0;
}

int main(int argc, char *argv[])
{
	fd_set master;
	fd_set read_fds;
	struct sockaddr_in serveraddr;
	struct sockaddr_in clientaddr;
	int fdmax;
	int listener;
	int newfd;
	int yes = 1;
	socklen_t addrlen;
	int i, j;

	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("Server-socket() error lol!");
		exit(1);
	}
	printf("Server-socket() is OK...\n");
	if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
	{
		perror("Server-setsockopt() error lol!");
		exit(1);
	}
	printf("Server-setsockopt() is OK...\n");

	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = INADDR_ANY;
	serveraddr.sin_port = htons(PORT);
	memset(&(serveraddr.sin_zero), '\0', 8);
	if (bind(listener, (struct sockaddr *) &serveraddr, sizeof(serveraddr))
			== -1)
	{
		perror("Server-bind() error lol!");
		exit(1);
	}
	printf("Server-bind() is OK...\n");
	if (listen(listener, 10) == -1)
	{
		perror("Server-listen() error lol!");
		exit(1);
	}
	printf("Server-listen() is OK...\n");
	FD_SET(listener, &master);
	fdmax = listener;
	for (;;)
	{
		read_fds = master;
		if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1)
		{
			perror("Server-select() error lol!");
			exit(1);
		}
		printf("Server-select() is OK...\n");
		for (i = 0; i <= fdmax; i++)
		{
			if (FD_ISSET(i, &read_fds))
			{
				if (i == listener)
				{
					/* handle new connections */
					addrlen = sizeof(clientaddr);
					if ((newfd = accept(listener,
							(struct sockaddr *) &clientaddr, &addrlen)) == -1)
						perror("Server-accept() error lol!");
					else
					{
						printf("Server-accept() is OK...\n");
						FD_SET(newfd, &master);
						if (newfd > fdmax)
							fdmax = newfd;
						printf("%s: New connection from %s:%d on socket %d\n",
								argv[0], inet_ntoa(clientaddr.sin_addr),
								ntohs(clientaddr.sin_port), newfd);
						tcp_do(ntohs(clientaddr.sin_port));
					}
				}
				else
				{
					char buf[1024];
					int nbytes;

					if ((nbytes = recv(i, buf, sizeof(buf), 0)) <= 0)
					{
						if (nbytes == 0)
							printf("%s: socket %d hung up\n", argv[0], i);
						else
							perror("recv() error lol!");
						close(i);
						FD_CLR(i, &master);
					}
					else
					{
						for (j = 0; j <= fdmax; j++)
							if (FD_ISSET(j, &master))
								if (j != listener && j != i)
									if (send(j, buf, nbytes, 0) == -1)
										perror("send() error lol!");
					}
				}
			}
		}
	}
	return 0;
}
