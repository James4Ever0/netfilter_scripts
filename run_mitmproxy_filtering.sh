# https://serverfault.com/questions/1108971/mitmproxy-as-a-chain-proxy-without-ssl-decryption
mitmproxy -p 1080 --mode socks5 --scripts filter_socks5.py --allow-hosts ''