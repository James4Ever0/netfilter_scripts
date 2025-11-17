# install dependencies with: pip install proxy.py
# run with: python socks_proxy.py
import ipaddress
import socket
from proxy.http.proxy import BaseTcpProxyHandler
from proxy.plugin.socks_proxy import Socks5ProxyHandler


class FilteredSocksProxy(Socks5ProxyHandler):
    ALLOWED_RULES = [
        # Format: (IP/CIDR, port) - None for port means any port
        ("127.0.0.0/8", None),  # Localhost
        ("10.0.0.0/8", 80),  # HTTP only on private network
        ("192.168.1.0/24", 443),  # HTTPS only on specific subnet
        ("172.16.0.0/12", None),  # All ports on another private network
    ]

    def resolve_host(self, host):
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None

    # blacklist approach
    # def is_allowed(self, dest_host, dest_port):
    #     blocked = [
    #         ('192.168.1.100', None),    # Block all ports
    #         ('10.0.0.5', 22),           # Block SSH
    #     ]
    #     # Check blocklist first
    #     for rule in blocked:
    #         ...
    #     return True

    def is_allowed(self, dest_host, dest_port):
        """Check if destination is allowed"""
        # Resolve host if needed
        try:
            ipaddress.ip_address(dest_host)
        except ValueError:
            dest_host = self.resolve_host(dest_host)
            if not dest_host:
                return False

        # Check against rules
        for rule in self.ALLOWED_RULES:
            rule_ip, rule_port = rule

            # Port check
            if rule_port is not None and rule_port != dest_port:
                continue

            # IP check
            try:
                network = ipaddress.ip_network(rule_ip, strict=False)
                if ipaddress.ip_address(dest_host) in network:
                    return True
            except ValueError:
                continue

        return False

    def proxy(self):
        """Override proxy connection with filtering"""
        if not self.is_allowed(self.dest_host, self.dest_port):
            self.log(f"Blocked {self.dest_host}:{self.dest_port}")
            self.close()
            return

        super().proxy()


if __name__ == "__main__":
    import ipaddress
    import proxy
    
    if True:
        proxy.main(hostname=ipaddress.IPv6Address("::1"), port=8899)

    if False:
        import shlex
        from proxy import Proxy

        with Proxy(
            input_args=shlex.split(""), hostname=ipaddress.IPv6Address("::1"), port=8899
        ) as p:
            proxy.sleep_loop(p)
