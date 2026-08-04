ssh2proxy
========= 
The sshproxy allows to select different ssh backend hosts based
on the ssh username. This allows users of multiple sshservers to
access the ssh service through a single endpoint.

The proxy implements the client-side and server-side connections
using the api of the libssh.a provided by the openssh project.
This allows the proxy code to stay in sync with openssh updates
and bugfixes.

The current version is built on top of openssh-10.4p1.

The proxy supports ssh2 password & pubkey authentication.

To allow transparent operation for a client, the ssh2proxy has to
use the same hostkeys as the backend ssh servers. With different
hostkeys a client with existing known_hosts entries would notice
the proxy as a man-in-the-middle.

The backend host for each user can be configured in the sshproxy
config file. For more complex setups it is possible to add a
special switch module to the implementation.

For public key authentication the ssh2proxy has to use a different
authentication scheme for the backend connection. The current
implementation allows to switch to hostbased authentication for
the backend. More info below.

Configuration
-------------
The example configuration file sshproxy.conf.example shows the basic
configuration of the sshproxy.

- the sshproxy server listens on the configured `bindaddr` and proxies
  to the given `default_server` if nothing else is configured.

- the `hostkey` entry is used to configure private hostkeys for the
  connection to the client, and public hostkeys for the proxy-connections
  to the backend servers.

- with `switch_target = <user> <host>` entries, it is possible to
  direct ssh-users to hosts different from the default_server. 

- the private key required for hostbased authentication can be configured
  via a `hostkey_auth = <key>` entry.

- the sshproxy can be tested via: `sshproxy -c sshproxy.conf.example &`

sshproxy protocol handling
--------------------------
1) In the first step the ssh protocol negotiation and the ssh key-exchange
   take place only between sshclient and sshproxy.

   The hostkey configured for the sshproxy is used for the key-exchange,
   to generate the session-id (priv) and is also transmitted in the
   proposal (pub).

2) After the key-exchange the sshproxy waits for a USERAUTH-requests with
   the 'username' for 'password' or 'pubkey' authentication.

3) Depending on the 'username' the sshproxy switch-module decides to which
   backend sshserver the proxy will connect.
  
4) The sshproxy connects to the backend sshserver und performs another
   key-exchange.

5) Now the USERAUTH-request is forwarded to the backend using the hostkey
   of the backend sshserver.

Password:

6) If the backend sshserver response to the USERAUTH-request is SUCCESS,
   then the proxy-authentication is complete. All subsequent ssh-packets
   can be passed transparently between sshclient and sshserver.
 
   For 'password'-requests the session-id is used only for the protocol
   handling of the ssh_packet_write() & ssh_packet_read() calls.

   So for 'password'-authentication it is possible to use different
   hostkeys for the proxy- and backend-connections.

Public Key Authentication:

7) When the sshclient uses 'pubkey'-authentication with a sshkey which
   is secured by a passphrase, then the sshproxy is first asked with
   the unsigned sshkey if the key is available on the server side.

   - this USERAUTH-request is forwarded to the sshserver as in point (5),
     and the response tells if the sshkey is allowed.

   - the sshproxy does not need access to the webspace of the user. The
     public sshkey has just to be configured in the .ssh/authorized_keys
     file of the user-account on the backend sshserver.

8) Now the sshclient authenticates again with a signed sshkey. This
   request is answered directly by the sshproxy after it validated
   the sshkey.

   - it is not possible to pass this USERAUTH-request on to the
     sshserver, since this request uses the hash from the key-exchange.
     And the hash is different for the proxy- and backend-connections.
     (see for example kexgex/kexdh->dh_gen_key()).

   For this reason it is necessary to use a different authentication
   like 'hostbased' for the Backend-Connection at this place.
   (see the example for hostbased configuration below)

9) For sshkeys without passphrase the protocol is slightly different.
   In this case already the first USERAUTH-request from the sshclient
   includes a signed sshkey. The sshproxy will pass this sshkey without
   signature on to the sshserver and then continues at point (8).

ssh2 states for public key authentication
-----------------------------------------
For sshkey with passphrase and 'hostbased' authentication for the backend:
```
  0) exchange of SSH2_MSG_USERAUTH_REQUEST 'none'
  1)           proxy <- client SSH2_MSG_USERAUTH_REQUEST 'pubkey' no-sig
  2) server <- proxy           SSH2_MSG_USERAUTH_REQUEST 'pubkey' no-sig
  3) server -> proxy           SSH2_MSG_USERAUTH_PK_OK (server knows key)
  4)           proxy -> client SSH2_MSG_USERAUTH_PK_OK
  5)           proxy <- client SSH2_MSG_USERAUTH_REQUEST 'pubkey' sig
                               (check signature -> FAIL if not match)
  6) server <- proxy           SSH2_MSG_USERAUTH_REQUEST 'hostbased'
  7) server -> proxy           SSH2_MSG_REQUEST_SUCCESS (for: hostbased)
  8)           proxy -> client SSH2_MSG_REQUEST_SUCCESS (for: pubkey (5))
```
For sshkey without passphrase:
```
  0) exchange of SSH2_MSG_USERAUTH_REQUEST 'none'
  1)           proxy <- client SSH2_MSG_USERAUTH_REQUEST 'pubkey' sig
                               (check signature -> FAIL if not match)
  2) server <- proxy           SSH2_MSG_USERAUTH_REQUEST 'pubkey' no-sig
  3) server -> proxy           SSH2_MSG_USERAUTH_PK_OK (server knows key)
  4) server <- proxy           SSH2_MSG_USERAUTH_REQUEST 'hostbased'
  5) server -> proxy           SSH2_MSG_REQUEST_SUCCESS (for: hostbased)
  6)           proxy -> client SSH2_MSG_REQUEST_SUCCESS (for: pubkey (1))
```

Hostbased authentication configuration
--------------------------------------
For a hostbased backend connection the sshproxy uses the key configured
via the 'hostkey_auth' config setting. To get this working, the backend
sshserver needs to allow hostbased authentication and the key must be
configured in the SSHDIR/etc/ssh_known_hosts file.

### sshserver configuration for hostbased sshproxy access:

- sshserver SSHDIR/etc/sshd_config:
  ```
  HostbasedAuthentication yes
  IgnoreUserKnownHosts yes
  IgnoreRhosts yes
  ```
- sshserver SSHDIR/etc/shosts.equiv:
  Add hostline: `<clienthost>`

- sshserver SSHDIR/etc/ssh_known_hosts:

  Get proxy public hostkey:
  ```
  # cat <hostkey_proxy> | ssh-keygen -y -f /dev/stdin
    ssh-rsa <hostkey_proxy_pub>
  ```
  Add hostline:
  `<host>[,<ip>] ssh-rsa <hostkey_proxy_pub>`

### sshserver configuration for hostbased connection test with normal ssh client:

- sshserver SSHDIR/etc/ssh_known_hosts:
  Add client public hostkey (for test):
  ```
  # ssh-keyscan -t rsa <clienthost>
  ```
- sshserver SSHDIR/etc/shosts.equiv:
  Add hostline: `<clienthost> <clientuser>`

- sshclient SSHDIR/etc/ssh_config:
  (uses libexec/ssh-keysign tool for authentication) 
  ```
  EnableSSHKeysign yes
  ```
- sshclient connection test:
  (will try all hostkeys without HostbasedAcceptedAlgorithms option)
  ```
  clientuser@clienthost # ssh -v -o PubkeyAuthentication=no -o PasswordAuthentication=no \
    -o HostbasedAuthentication=yes -o HostbasedAcceptedAlgorithms=rsa-sha2-* <user>@<sshserver>
  ```

Support for high performance ssh-hpn receive-window scaling
-----------------------------------------------------------
HPN enabled ssh endpoints scale the SSH channel receive window with the kernel's
TCP receive buffer instead of leaving it at OpenSSH's fixed 2 MB. It raises
throughput once the Bandwidth-Delay Product (BDP = rate × RTT) of a connection
exceeds that window, because a sender that has filled the receiver's window has
to stop until the window is extended again.

The proxy just relays packets and owns none of the ssh channels, so the
`SSH_MSG_CHANNEL_WINDOW_ADJUST` passes through untouched and client and backend
negotiate their windows end-to-end. The proxy terminates the transport on both
legs and sends its own banner, so neither endpoint sees the other's `_hpn`
marker and can not depend on it for the ssh windows growth. Enabling HPN is a
matter for the two endpoints, and only the receiving side of a transfer matters:

| transfer                   | receiver | HPN has to be on   |
|----------------------------|----------|--------------------|
| download (from the server) | client   | ssh                |
| upload (to the server)     | server   | sshd               |

For a speed-up the OS receive buffer has to be sized to the BDP. The
`net.ipv4.tcp_rmem` (and `tcp_wmem`) max values should be set to ~2×BDP.
For too small values the ssh window cannot grow.

The `make perf` performance test measures a HPN setup inside an unprivileged
build container, and compares a raw-TCP link ceiling vs a bulk ssh upload and
download through the proxy, with HPN on both endpoints either enabled/disabled.

For the ssh implementation the FreeBSD ports HPN `ssh-hpn.patch` is used.
A small patch on top allows it to advertise up to 3/4 of the socket buffer
to any peer even without '_hpn' signalling from the remote side.

The proxy relays with blocking writes: while it writes to one peer, the socket
buffer of the other has to hold the data still in flight. The tcp windows are
adjusted by Linux kernel autotuning.

For the performance test proxy and backend both sit in the server namespace
and talk over local virtual ethernet interfaces using netem/qdisc to shape
the traffic on the client-to-proxy hop to simulate WAN-facing traffic. The
best test results are reached when a tcp_bbr congestion-control module is
available to avoid the burstiness of the default Linux CUBIC congestion-control
module for local loopback tests:
```
[client ns] ssh  veth-c <==netem==> veth-s  sshproxy -> sshd  [server ns]
```
The throughput comparison for a 512 MiB file over a 200ms / 1000mbit link
(~25 MB BDP) shows approx. a 7x improvement for a HPN enabled connection:
```
# ceiling : up  71.2  down  76.9 MiB/s  (60%/65% of 1000mbit cap)
# download: hpn  56.3 | off   8.7 MiB/s   hpn/off  6.50x   inflt 36 / 2 MB
# upload  : hpn  38.1 | off   4.8 MiB/s   hpn/off  7.93x   inflt 13 / 2 MB
```
Without HPN both directions are limited at the stock ssh 2 MB window.
The upload measurement varies because the receiver sits on the non-shaped
proxy-to-backend connection, which sizes the window.

