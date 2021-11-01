ssh2proxy
========= 
The sshproxy allows to select different ssh backend hosts based on
the ssh username. This allows users of multiple sshservers to
access the ssh service through a single endpoint.

Currently the ssh2proxy supports password & pubkey authentication
for the ssh2 protocol.

The switch mechanism allows the sshproxy to act as a man-in-the-middle.
But to allow completely transparent operation for a client, the sshproxy
has to use the same hostkeys as the backend ssh servers. So it poses
no risk to a client, because the use of a different hostkey on the
same endpoint would be noticed.

The ssh2proxy implementation is based on the openssh project.

The backend host for each user can be configured in the sshproxy config
file, as well as a default host. For more complex setups it is possible
to add a special switch module to the implementation.

To support public key authentication the sshproxy has to use a different
authentication scheme for the backend connection. The current implementation
allows to use hostbased authentication for the backend. More info below.

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
   (like Diffie-Hellman) take only place between sshclient and sshproxy.

   The hostkey of the sshproxy is used for the key-exchange, to generate
   the session-id (priv) and is also transmitted in the proposal (pub).

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
   (see the example for hostbased configuration in a later section)

9) For sshkeys without passphrase the protocol is slightly different.
   In this case already the first USERAUTH-request from the sshclient
   includes a signed sshkey. The sshproxy will pass this sshkey without
   signature on the sshserver and then coninues as in point (8).

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
  (will try all hostkeys without HostbasedKeyTypes option)
  ```
  clientuser@clienthost # ssh -v -o PubkeyAuthentication=no -o PasswordAuthentication=no \
          -o HostbasedAuthentication=yes -o HostbasedKeyTypes=ssh-rsa <user>@<sshserver>
  ```

