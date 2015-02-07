
NAME_SRV = MSS_server
SRC_SRV = server/Main.c server/TcpCheck.c
OBJ_SRV = $(SRC_SRV:.c=.o)


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

all	: $(NAME_SRV)

$(NAME_SRV): $(OBJ_SRV)
	@echo "Compile binary	[$(NAME_SRV)]"
	@$(CC) -o $(NAME_SRV) $(OBJ_SRV) $(LDFLAGS)
	@$(CHMOD) 755 $(NAME_SRV)

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
