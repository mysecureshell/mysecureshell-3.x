//#define PATH_CMDLINE	"cmdline"
//#define PATH_CMDLINEl       strlen(PATH_CMDLINE)
#define MSS_EXE "/bin/nc.openbsd"

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
