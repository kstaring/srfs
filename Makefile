CFLAGS	=-Wall
LDFLAGS	=-lssl -lcrypto

FCLIENT	=srfs
SERVER	=srfsd
AUTH	=srfs_auth

FCSRCS	=client_fuse.c srfs_client.c
SSRCS	=server.c
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
