curl --socks5 localhost:1080 http://example.com  # Allowed
curl --socks5 localhost:1080 telnet://10.0.0.2:23  # Blocked (port)