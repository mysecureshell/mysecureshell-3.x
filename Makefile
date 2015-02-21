
NAME_SRV = MSS_server
SRC_SRV = server/Main.c server/TcpCheck.c server/Sftp.c server/Admin.c server/Buffer.c server/Encode.c \
		  server/Encoding.c server/FileSystem.c server/FileSystemAcl.c server/Log.c server/Handle.c \
		  server/SftpWho.c server/Send.c server/Stats.c server/SftpExt.c server/SftpServer.c \
		  server/Util.c server/GetUsersInfos.c server/Access.c server/CFixes.c \
		  Core/FileSpec.c Core/string.c
OBJ_SRV = $(SRC_SRV:.c=.o)

NAME_CLT = MSS_client
SRC_CLT = client/Main.c
OBJ_CLT = $(SRC_CLT:.c=.o)


CFLAGS	= -Wall -Wunused -Wpointer-arith -Wno-uninitialized -O2 -ISftpServer  -DDODEBUG -g3
LDFLAGS	=  -lgnutls -lacl  
CC	= gcc
EXT	= 
RM	= rm -f
CHMOD	= chmod
TAR	= tar
CP	= cp -pf
STRIP	= strip
FIND	= find
LN	= ln
LS	= ls

all	: $(NAME_SRV) $(NAME_CLT)

$(NAME_SRV): $(OBJ_SRV)
	@echo "Compile binary	[$(NAME_SRV)]"
	@$(CC) -o $(NAME_SRV) $(OBJ_SRV) $(LDFLAGS)
	@$(CHMOD) 755 $(NAME_SRV)
	
$(NAME_CLT): $(OBJ_CLT)
	@echo "Compile binary	[$(NAME_CLT)]"
	@$(CC) -o $(NAME_CLT) $(OBJ_CLT) $(LDFLAGS)
	@$(CHMOD) 755 $(NAME_CLT)

clean:
	@echo "Delete all objects"
	@$(RM) $(OBJ_SRV)

distclean: clean
	@echo "Delete all unecessary files"
	@$(RM) $(NAME_SRV)
	@$(RM) -i `$(FIND) . | grep -F '~'` *.tgz || true

.c.o:
	@echo "Compile		[$<]"
	@$(CC) $(CFLAGS) -c -o $@ $<
