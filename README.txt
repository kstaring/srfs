Introduction
------------
The (Simple|Safe) Remote File System, for short SRFS, is meant to be
a secure-by-default NFS replacement. In true open source fashion, apparently
one must be able to pronounce this acronym in a different and supposedly
clever way, so it is decided thusly to be pronounced `SERVES'.

SRFS features include the following:

- All network communication is encrypted by default, all communication is
  handled by one TCP connection on one port: a SRFS client can always be
  associated by one TCP connection.
- Users must authenticate with the SRFS server before being able to access
  their files on its exported filesystems.
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
