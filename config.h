//#define PATH_CMDLINE	"cmdline"
//#define PATH_CMDLINEl       strlen(PATH_CMDLINE)
#define MSS_EXE "/home/teka/Documents/Developpement/MySecureShell/mysecureshell-3.x/MSS_client"

#define PATH_EXE_SUFF	"exe"
#define PATH_FD_SUFF	"fd"
//#define PATH_FD_SUFFl       strlen(PATH_FD_SUFF)
#define PATH_PROC	   "/proc"
#define PATH_PROC_X_FD      PATH_PROC "/%s/" PATH_FD_SUFF
#define PATH_PROC_X_EXE      PATH_PROC "/%s/" PATH_EXE_SUFF
//#define PRG_SOCKET_PFX    "socket:["
//#define PRG_SOCKET_PFXl (strlen(PRG_SOCKET_PFX))
//#define PRG_SOCKET_PFX2   "[0000]:"
//#define PRG_SOCKET_PFX2l  (strlen(PRG_SOCKET_PFX2))
#define PROGNAME_WIDTH 20
#define LINE_MAX 4096
#define PORT 2020

#define DODEBUG 1
#define MSS_HAVE_ADMIN 1
#define SHUTDOWN_FILE "/tmp/sftp.shut"
#define CONFIG_FILE "/etc/ssh/sftp_config"
#define MSS_LOG "/tmp/sftp.log"
#define MSS_SFTPWHO "/bin/ls"
#define MSS_SFTPUSER "/bin/ls"

#define MSSEXT_DISKUSAGE 1
#define MSSEXT_DISKUSAGE_SSH 1
#define HAVE_SYSLOG_H 1
#define HAVE_STATFS 1
#define HAVE_SYS_MOUNT_H 1
#define HAVE_SYS_PARAM_H 1
#define HAVE_SYS_STATVFS_H 1
