#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 17/4/8 上午00:00
# @Author  : Komi
# @File    : run.py
# @Ver:    : 0.1

helpinfo = '''\
##########################################################
#    _____       ______    ___    _____   __ __          #
#   / ___  \    /  ____/  |   |  |_ _ |  |_____|         #
#  / /    \ \  / /         | |   | |_      | |           #
#  | \___ / /  | \ ____    | |   |  _|     | |           #
#   \ __ __/    \ ____ /  |___|  |_|      |___|   v1.0   #
##########################################################
# 一个半自动化命令注入漏洞Fuzz工具
Named From: OCIFT(OS Command Injection Fuzzy Tool)
Referer:
https://github.com/commixproject/commix
https://www.owasp.org/index.php/Command_Injection
Instructions:
    1、python osift.py 8081 (开启8081作为代理端口)
    2、浏览器设置通过代理地址: http://127.0.0.1:8081进行访问
    3、测试结果会记录在日志文件里,默认: rce_success_results.txt
'''
print helpinfo

import logging
import socket
import string
import random
from urlparse import urlparse
import os,sys
from Queue import Queue
import threading
import tornado.httpserver
import tornado.ioloop
import tornado.iostream
import tornado.web
from tornado.web import RequestHandler
import tornado.httpclient
from fuzz import CIF_Fuzz
from make_payload import PayloadGenerate
import ConfigParser

# logging.basicConfig(level=logging.ERROR)

class ProxyManage:
    def run_proxy(self, address, port, handler):
        ''''
        Start proxy server
        '''
        app = tornado.web.Application([
            (r'.*', handler),
        ])
        app.listen(port, address)
        logging.info("Starting HTTP proxy on {0}".format(address + ':' + str(port)))
        ioloop = tornado.ioloop.IOLoop.instance()
        ioloop.start()

    def close_proxy(self):
        ioloop = tornado.ioloop.IOLoop.instance()
        logging.info('stop proxy server')
        ioloop.stop()

def get_proxy(url):
    url_parsed = urlparse(url, scheme='http')
    proxy_key = '%s_proxy' % url_parsed.scheme
    return os.environ.get(proxy_key)

def parse_proxy(proxy):
    proxy_parsed = urlparse(proxy, scheme='http')
    return proxy_parsed.hostname, proxy_parsed.port

def fetch_request(url, callback, **kwargs):
    proxy = get_proxy(url)
    if proxy:
        tornado.httpclient.AsyncHTTPClient.configure(
            'tornado.curl_httpclient.CurlAsyncHTTPClient')
        host, port = parse_proxy(proxy)
        kwargs['proxy_host'] = host
        kwargs['proxy_port'] = port

    req = tornado.httpclient.HTTPRequest(url, **kwargs)
    client = tornado.httpclient.AsyncHTTPClient()
    client.fetch(req, callback, raise_error="error")

class LoadConfig:
    def __init__(self):
        self.version = "V1.0"

    def read_config(self):
        self.conf = ConfigParser.SafeConfigParser()
        self.conf.read('fuzz.conf')
        self.initconfig = self.conf.items('initconfig')

    def get_configprperity(self, key=""):

        for tmp in self.initconfig:
            if key == tmp[0] and key != "":
                return tmp[1]

class ProxyHandler(RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'CONNECT', "OPTIONS"]
    queue = Queue()
    print "[+] Load configuration file..."

    londconf = LoadConfig()
    londconf.read_config()
    londconf.get_configprperity()

    my_cloudeye = londconf.get_configprperity('my_cloudeye')
    white_site = londconf.get_configprperity('white_site')
    black_site = londconf.get_configprperity('black_hosts')
    checkkeys = londconf.get_configprperity('checkkeys')
    checkkey_list = checkkeys.split(",")
    fuzz_count = londconf.get_configprperity('fuzz_count')
    custom_domain = londconf.get_configprperity('custom_domain')
    dnslog_sessionid = londconf.get_configprperity('dnslog_sessionid')
    commix_payload_type = londconf.get_configprperity('commix_payload_type')
    url_ext_black = londconf.get_configprperity('url_ext_black')
    black_parameters = londconf.get_configprperity('black_parameters')

    Logfile = londconf.get_configprperity('Logfile')

    base_command = londconf.get_configprperity("base_command")

    base_command_list = []
    for base_command in base_command.split(","):
        base_command_list.append(base_command.format(my_cloudeye=my_cloudeye))

    timeout = londconf.get_configprperity("timeout")
    print "[+] Initialize Payloads..."
    PayloadME = PayloadGenerate(base_command_list)
    if commix_payload_type == "False":
        PayloadME.fuzz_mypayloads()
    else:
        TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))
        PayloadME.make_commix_payloads(TAG=TAG)
        checkkey_list.append(TAG)

    fuzzing_payloads_list = list(set(PayloadME.fuzzing_payloads_list))
    print "[+] we have %s payloads " % len(fuzzing_payloads_list)

    print "[+] Start Fuzzing Threads..."
    for i in range(0, int(fuzz_count)):
        cifz = CIF_Fuzz(queue=queue)
        cifz.fuzzing_payloads_list = PayloadME.fuzzing_payloads_list
        cifz.CheckKey_list = checkkey_list
        cifz.my_cloudeye = my_cloudeye
        cifz.url_ext_blacklist = url_ext_black.split(",")
        cifz.dnslog_sessionid = dnslog_sessionid
        cifz.Logfile = Logfile
        cifz.custom_domain = custom_domain
        cifz.white_site = white_site.split(",")
        cifz.black_site = black_site.split(",")
        cifz.black_parameters = black_parameters.split(",")
        cifz.timeout = int(timeout)
        cifz.start()
    print "[+] Everything is ready."
    @tornado.web.asynchronous
    def get(self):
        def handle_response(response):
            if (response.error and not
            isinstance(response.error, tornado.httpclient.HTTPError)):
                self.set_status(500)
                self.write('Internal server error:\n' + str(response.error))
            else:
                self.set_status(response.code, response.reason)
                self._headers = tornado.httputil.HTTPHeaders()  # clear tornado default header

                for header, v in response.headers.get_all():
                    if header not in ('Content-Length', 'Transfer-Encoding', 'Content-Encoding', 'Connection'):
                        self.add_header(header, v)  # some header appear multiple times, eg 'Set-Cookie'

                if response.body:
                    self.set_header('Content-Length', len(response.body))
                    self.write(response.body)
            self.finish()

        body = self.request.body
        if not body:
            body = None

        try:

            if 'Proxy-Connection' in self.request.headers:
                del self.request.headers['Proxy-Connection']

            fetch_request(
                self.request.uri, handle_response,
                method=self.request.method, body=body,
                headers=self.request.headers, follow_redirects=False,
                allow_nonstandard_methods=True)

            request_dict = {}
            request_dict['uri'] = self.request.uri
            request_dict['method'] = self.request.method
            request_dict['headers'] = self.request.headers
            request_dict['body'] = body
            self.queue.put(request_dict)

        except tornado.httpclient.HTTPError as e:
            if hasattr(e, 'response') and e.response:
                handle_response(e.response)
            else:
                self.set_status(500)
                self.write('Internal server error:\n' + str(e))
                self.finish()

    @tornado.web.asynchronous
    def post(self):
        return self.get()

    @tornado.web.asynchronous
    def options(self):
        return self.get()

    @tornado.web.asynchronous
    def connect(self):
        host, port = self.request.uri.split(':')
        client = self.request.connection.stream

        def read_from_client(data):
            upstream.write(data)

        def read_from_upstream(data):
            client.write(data)

        def client_close(data=None):
            if upstream.closed():
                return
            if data:
                upstream.write(data)
            upstream.close()

        def upstream_close(data=None):
            if client.closed():
                return
            if data:
                client.write(data)
            client.close()

        def start_tunnel():
            client.read_until_close(client_close, read_from_client)
            upstream.read_until_close(upstream_close, read_from_upstream)
            client.write(b'HTTP/1.0 200 Connection established\r\n\r\n')

        def on_proxy_response(data=None):
            if data:
                first_line = data.splitlines()[0]
                http_v, status, text = first_line.split(None, 2)
                if int(status) == 200:
                    start_tunnel()
                    return

            self.set_status(500)
            self.finish()

        def start_proxy_tunnel():
            upstream.write('CONNECT %s HTTP/1.1\r\n' % self.request.uri)
            upstream.write('Host: %s\r\n' % self.request.uri)
            upstream.write('Proxy-Connection: Keep-Alive\r\n\r\n')
            upstream.read_until('\r\n\r\n', on_proxy_response)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        upstream = tornado.iostream.IOStream(s)

        proxy = get_proxy(self.request.uri)
        if proxy:
            proxy_host, proxy_port = parse_proxy(proxy)
            upstream.connect((proxy_host, proxy_port), start_proxy_tunnel)
        else:
            upstream.connect((host, int(port)), start_tunnel)


class RunProxyThread(threading.Thread):
    def __init__(self, handler, host, port):
        self.host = host
        self.port = port
        self.handler = handler
        threading.Thread.__init__(self)

    def run(self):
        ProxyManage().run_proxy(self.host, self.port, self.handler)

if __name__ == "__main__":
    port = 8888
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    print "[*] Starting HTTP proxy at: http://127.0.0.1:%d" % port

    os.system('pkill -f "python run.py"')

    RunProxyThread(ProxyHandler, '127.0.0.1', int(port)).run()

