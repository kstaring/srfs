CFLAGS	=-g -O2 -Wall
LDFLAGS	=-lssl -lcrypto

FCLIENT	=srfs
SERVER	=srfsd
AUTH	=srfs_auth

FCSRCS	=srfs_fuse.c srfs_client.c srfs_sock.c
SSRCS	=srfsd.c srfs_server.c srfs_exports.c srfs_sock.c
ASRCS	=srfs_auth.c

all: fuse-client server authenticator

fuse-client:
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(FCLIENT) `pkg-config fuse --cflags --libs` $(FCSRCS)

server:
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(SERVER) $(SSRCS)

authenticator:
	$(CC) $(CFLAGS) -o $(AUTH) $(ASRCS)

clean:
	rm -f $(FCLIENT) $(SERVER) $(AUTH) *.o *.core
