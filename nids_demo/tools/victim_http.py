# -*- coding: utf-8 -*-
"""Web server 'nạn nhân' tối giản cho lab DoS HTTP.

Trả về 200 OK cho mọi yêu cầu, đa luồng + hàng đợi lớn để chịu được flood (vd ApacheBench -c 50).
Mặc định chỉ lắng nghe trên card Host-only để Kali tấn công, KHÔNG mở ra Wi-Fi.

    python tools/victim_http.py [host] [port]       # mặc định 192.168.136.1 80
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b'<html><body><h1>Lab victim</h1></body></html>'


class VictimServer(ThreadingHTTPServer):
    request_queue_size = 512        # hàng đợi lớn để chịu nhiều kết nối đồng thời không bị reset
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'          # cho phép keep-alive -> nhiều yêu cầu/luồng, giống HTTP DoS thật

    def _serve(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(BODY)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(BODY)

    do_GET = do_POST = do_HEAD = _serve

    def log_message(self, *a):
        pass                                # tắt log cho đỡ nghẽn khi bị flood


if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '192.168.136.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    srv = VictimServer((host, port), Handler)
    print(f'Victim HTTP server tren http://{host}:{port}/ (Ctrl+C de dung)', flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
