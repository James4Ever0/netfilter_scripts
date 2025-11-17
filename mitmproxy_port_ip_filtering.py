from mitmproxy import http
import datetime

# TODO: do not provide self-signed certificate and decrypt https traffic

# mitmproxy will pop up a tui for flow inspection. 
# mitmweb will open up a web ui for flow inspection.
# mitmdump will not.

# mitmdump -s mitmproxy_port_ip_filtering.py --allow-hosts 127.0.0.1 --listen-host 127.0.0.1 --listen-port 8887 --show-ignored-hosts

# all non-localhost https requests are ignored. these https requests will not be processed by the "request" function.
# need reference on how to write mitmproxy scripts. specifically, the naming of those functions.

# how does "allow-hosts" works under the hood? can we achieve this via script?

# different modes:
# mitmdump --mode dns
# mitmdump --mode socks5
# mitmdump --mode transparent
import mitmproxy.ctx

def request(flow: http.HTTPFlow):
    # this is never logged.
    # redirect to different host
    scheme = flow.request.scheme
    host = flow.request.host
    timestamp = datetime.datetime.now().isoformat()
    mitmproxy.ctx.log.info("[Time: %s] Scheme: %s, Host: %s" % (timestamp, scheme, host))
    if flow.request.pretty_host == "example.com":
        flow.request.host = "mitmproxy.org"
    # answer from proxy
    elif flow.request.path.endswith("/brew"):
        flow.response = http.Response.make(
            418,
            b"I'm a teapot",
        )
