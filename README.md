# qcat

This is just a basic version of netcat that runs over QUIC. The TLS authentication happens via certificate pinning. When
the server starts, it randomly generates a password from a wordlist included in the binary. This password is sent through
Argon2id and used as an ED25519 key, which is used as the private key for the X509 certificate. The password is output to
the terminal for the user to read. To connect with the client, run the client and input the generated server password in order
to derive the expected keypair and certificate.

Once the connection is established stdin from the client is simply written over the QUIC connection and output to stdout by
the server.

This non-standard TLS authentication is simply because rustls doesn't support PSK or TLS-PWD, and I just wanted to mess around
implementing something weird.

