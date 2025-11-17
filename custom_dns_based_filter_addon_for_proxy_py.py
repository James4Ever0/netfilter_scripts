# -*- coding: utf-8 -*-
"""
proxy.py
~~~~~~~~
⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
Network monitoring, controls & Application development, testing, debugging.

:copyright: (c) 2013-present by Abhinav Singh and contributors.
:license: BSD, see LICENSE for more details.
"""
from typing import Optional

from proxy.http import httpStatusCodes
from proxy.http.proxy import HttpProxyBasePlugin
from proxy.http.parser import HttpParser
from proxy.common.utils import text_
from proxy.http.exception import HttpRequestRejected

# we may dynamically change this, read it from a file or redis, which makes a difference in case of tinyproxy.
upstream_hosts_whitelist = [
    "baidu.com",
    "bing.com",
]


# we can implement a whitelist instead of blacklist
class FilterByUpstreamWhitelistHostPlugin(HttpProxyBasePlugin):
    """Drop traffic by inspecting upstream host."""

    def before_upstream_connection(
        self,
        request: HttpParser,
    ) -> Optional[HttpParser]:
        request_host = text_(request.host)
        # print("Request:", request)
        # proxy.http.parser.parser.HttpParser
        # print(dir(request))
        # ['add_header', 'add_headers', 'body', 'body_expected', 'buffer', 'build', 'build_response', 'chunk', 'code', 'content_expected', 'del_header', 'del_headers', 'has_header', 'header', 'headers', 'host', 'http_handler_protocol', 'is_chunked_encoded', 'is_complete', 'is_connection_upgrade', 'is_http_1_1_keep_alive', 'is_https_tunnel', 'is_websocket_upgrade', 'method', 'parse', 'path', 'port', 'protocol', 'reason', 'request', 'response', 'set_url', 'state', 'total_size', 'type', 'update_body', 'version']
        print("Request host:", request_host)
        is_in_whitelist = request_host in upstream_hosts_whitelist
        # suffix based filtering might not be the best way. maybe we should figure out the exact domains after collected enough request hosts.
        is_endswith_whitelist_elem = any(
            request_host.endswith("." + elem) for elem in upstream_hosts_whitelist
        )
        check_passed = is_in_whitelist or is_endswith_whitelist_elem
        if not check_passed:
            raise HttpRequestRejected(
                status_code=httpStatusCodes.I_AM_A_TEAPOT,
                reason=b"I'm a tea pot",
            )
        return request
