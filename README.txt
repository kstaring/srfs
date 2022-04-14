Introduction
------------
The (Simple|Safe) Remote File System, for short SRFS, is meant to be
a secure-by-default NFS replacement. In true open source fashion, apparently
one must be able to pronounce this acronym in a different and supposedly
clever way, so it is decided thusly to be pronounced `SERVES'.

SRFS features include the following:

- All network communication is encrypted by default, all communication is
  handled by one TCP connection on one port: a SRFS client mount can always be
  associated by one TCP connection.
- Users must authenticate with the SRFS server before being able to access
  files on its exported filesystems.
  - srfs can leverage SSH infrastructure to transparently authenticate with
    authorized_keys.
  - srfs_auth to authenticate with a username and password, which might
    be integrated in PAM or similar system.
- User- and group IDs are transparently rewritten; users and groups not
  present on the client are presented as 'nobody' and 'nogroup'. In other
  words: there is no need for uids and gids to be equal on the client and
  server, however usernames must match and be authenticated.

Background
----------
NFS has definitely stood the test of time. It is ubiquitous among unix systems
and can even be used on some non-unix systems. However, NFS has some serious
downsides, which include:
- When not using Kerberos, authentication is basically IP address based.
- Network data is not encrypted, except when one uses NFSv4 krb5p, which
  obviously only works in combination with a complete Kerberos infrastructure.
- User- and group IDs must be the same on client and server, except again
  when one uses Kerberized NFSv4.
- NFSv4 is quite a bit less ubiquitous than previous versions, e.g.
  several of the BSDs did not implement this version, and at least OpenBSD
  did not implement version 4 on purpose.

When Kerberization of one's infrastucture is overkill or not wanted, there
are few options left. SSHFS has a tendency of locking up. And if Kerberization
is overkill, then e.g. Andrew Filesystem or CEPH probably are as well.

Setup
-----

- SRFS depends on the Fusefs library, so that needs to be installed first.
  pkg install fusefs-libs	# BSD
  apt install libfuse-dev	# e.g. Ubuntu
  dnf install fuse-libs		# e.g. RedHat

- Then, you need to compile the source.
  make

- Create /etc/srfs and populate it on the server side. This example uses
  a self-signed certificate, but please do use real public key infrastructure.
  The files should be named /etc/srfs/server.key and /etc/srfs/server.crt .
  mkdir /etc/srfs
  mkdir /etc/srfs/srfs_client_keys.d
  cp etc/{srfsd.conf,exports} /etc/srfs
  openssl req -x509 -newkey rsa:4096 -keyout /etc/srfs/server.key -out /etc/srfs/server.crt -sha256 -days 365

- Edit the /etc/srfs/exports file to your tastes and start the SRFS daemon.
  Note that using the default configuration, no client can simply mount the
  share and view files. You need to explicitly allow clients by placing
  the client pubkeys in /etc/srfs/srfs_client_keys.d .
  vi /etc/srfs/exports
  srfsd

- Create /etc/srfs on the client side. Create an RSA keypair and place it
  in /etc/srfs/client.key and /etc/srfs/client.pub . Then, copy the public
  key to the *server* in /etc/srfs/srfs_client_keys.d . The filename on the
  server doesn't matter, as long as it's placed in this directory. If you
  configured the server with a self-signed certificate, you need to change
  allow_selfsigned_server from 'false' to 'true' in /etc/srfs/srfs.conf .
  mkdir /etc/srfs
  cp etc/srfs.conf /etc/srfs
  openssl genrsa -out /etc/srfs/client.key 4096
  openssl rsa -in /etc/srfs/client.key -outform PEM -pubout -out /etc/srfs/client.pub

- Mount your share on the client.
  mount_srfs server:/share /mnt

- If the shared directory on the server is readable by nobody and the client
  pubkey is placed in the srfs_client_keys.d directory on the server, you
  should be able to see files in /mnt . If you have ssh configured with a
  passwordless id_rsa and authorized_keys on the client and server, you
  should also already be able to write to your own files and read your own
  directories.

- Alternatively, create ~/.srfs on the client and server in your homedirectory
  and populate it with ssh-keygen id_rsa(.pub) and fill authorized_keys on
  the server as you would with ssh to make it work `natively'.

- srfsd logs to the LOG_AUTH syslog facility at LOG_NOTICE and LOG_INFO levels.
  So if something doesn't work as expected, the auth log might be helpful.
