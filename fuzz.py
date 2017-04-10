#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 17/3/28 上午11:15
# @Author  : Komi
# @File    : fuzz.py
# @Ver:    : 0.1

import re
import random
import string
import requests
import threading
import hashlib
from urlparse import urlparse
from dnslog import DNSLog

class CIF_Fuzz(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue
        self.timeout = 5
        self.dnslog_sessionid = ''
        self.custom_domain = 'ano1qu2j'
        self.white_site = ['']
        self.url_ext_blacklist = ['']
        self.black_site = ['.gov']
        self.black_parameters = ['']
        self.Logfile = ''
        self.my_cloudeye = ""
        self.CheckKey_list = ['']
        self.fuzzing_payloads_list = []
        self.fuzzing_finished_hash = []

    # 计算一下请求的HASH，为了不重复测试.
    def HASH_Calc(self, requests_dict):
        md5 = hashlib.md5()
        md5.update(str(requests_dict))
        return md5.hexdigest()

    # 发出请求
    def HttpHelper(self, requests_dict, TAG):

        isOver = False
        fuzzing_url = requests_dict['uri']
        headers = requests_dict['headers']

        try:
            if "GET" == requests_dict['method']:
                resp = requests.get(fuzzing_url, headers=headers, timeout=self.timeout)
                result = resp.content
                for key in self.CheckKey_list:
                    if key in result:
                        isOver = True
                        break
            elif "POST" == requests_dict['method']:
                resp = requests.post(fuzzing_url, data=requests_dict['body'], headers=headers, timeout=self.timeout)
                result = resp.content

                for key in self.CheckKey_list:
                    if key in result:
                        isOver = True
                        break

            if self.my_cloudeye in str(requests_dict):
                dnslog = DNSLog()
                dnslog.sessionid = self.dnslog_sessionid
                dnslog.custom = self.custom_domain
                count = 3

                for i in range(count):
                    try:
                        flag = dnslog.verifyDNS(TAG)
                        if flag:
                            isOver = True
                            break
                    except Exception,e:
                        pass

        except Exception,e:
            isOver = False

        return isOver

    # Fuzzing_GET请求
    def Fuzzing_GET(self, request):
        fuzzing_payloads = self.fuzzing_payloads_list
        base_url = request['uri']
        TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))

        for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", base_url):
            in_black_param = self.check_in_keys(match.group("parameter"), self.black_parameters)
            if in_black_param:
                continue

            print "[GET] Fuzzing "+match.group("parameter")
            for payload_item in fuzzing_payloads:
                if self.my_cloudeye in payload_item:
                    payload_item = payload_item.replace(self.my_cloudeye, TAG+"."+self.my_cloudeye)
                    payload_item = match.group("value")+payload_item
                # ip=1.1.1.1;whoami
                fuzzing_uri_append = base_url.replace('%s=%s' % (match.group("parameter"), match.group("value")),'%s=%s' % (match.group("parameter"), match.group("value")+payload_item))
                request['uri'] = fuzzing_uri_append
                isVuln_a = self.HttpHelper(request, TAG)

                # ip=;whoami
                fuzzing_uri_replace = base_url.replace('%s=%s' % (match.group("parameter"), match.group("value")), '%s=%s' % (match.group("parameter"), payload_item))
                request['uri'] = fuzzing_uri_replace
                isVuln_r = self.HttpHelper(request, TAG)

                # 任意一个测试成功都结束Fuzz
                if isVuln_a or isVuln_r:
                    self.FileHelper("GET", base_url, match.group("parameter"), payload_item, TAG)
                    print "[+] Fuzzing Done!!"
                    return
            print "[+] Fuzzing Done!!"
        return

    # Fuzzing_POST请求
    def Fuzzing_POST(self, request):
        fuzzing_payloads = self.fuzzing_payloads_list
        base_url = request['uri']
        TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))

        post_body = request['body']
        for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", post_body):
            in_black_param = self.check_in_keys(match.group("parameter"), self.black_parameters)
            if in_black_param:
                continue

            try:
                print "[POST] Fuzzing "+match.group("parameter")
                for payload_item in fuzzing_payloads:
                    if self.my_cloudeye in payload_item:
                        payload_item = payload_item.replace(self.my_cloudeye, TAG+"."+self.my_cloudeye)
                        payload_item = match.group("value")+payload_item
                    fuzzing_post_body = post_body.replace('%s=%s' % (match.group("parameter"), match.group("value")),'%s=%s' % (match.group("parameter"), payload_item))
                    request['body'] = fuzzing_post_body
                    isOver = self.HttpHelper(request, TAG)
                    if isOver:
                        self.FileHelper("POST", base_url, match.group("parameter"), payload_item, TAG)
                        print "[success] Fuzzing Done!!"
                        return
                print "[failed] Fuzzing Done!!"
            except :
                pass
        return

    # header暂时不支持Fuzzing
    def Fuzzing_HEADER(self, request):
        print "Fuzzing HEADER"
        # headers_map = request['headers'].get_all()
        # for (k,v) in headers_map:
        #     print "%s - %s" % (k,v)

    # 记录到文件
    def FileHelper(self, HTTP_Method, Rce_URL, parameter, payload, TAG):
        wfile = open(self.Logfile, mode='a+')
        found_rce_text = '''\n\
+==++==++==++==++==++==++==++==++==++==++==++==++==++==++==++==++==++==++==++==++==++==+
+=+TAG: {TAG}
+=+URL: {RCE_URL}
+=+method: {HTTP_Method}
+=+param: {parameter}
+=+payload: {payload}
+==++==++==++==++==++==++==++==++==++==++==++==++==++==++==++==++==++==++==++==++==++==+\n
        '''
        found_rce_text = found_rce_text.replace("{TAG}", TAG).replace("{RCE_URL}", Rce_URL).replace("{HTTP_Method}", HTTP_Method).replace("{parameter}", parameter).replace("{payload}", payload)

        print found_rce_text

        wfile.write(found_rce_text)
        wfile.write("\r\n")
        wfile.flush()
        wfile.close()

    def check_in_keys(self, uri, keys_list):
        uri = uri.lower()

        if len(keys_list) == 0:
            return False
        else:
            for k in keys_list:
                if k.lower() in uri:
                    return True
            return False

    def check_url_blackext(self, uri):
        not_staticFlag = True
        url_ext = urlparse(uri).path[-5:].lower()

        if ".js" in uri and ".jsp" not in url_ext:
            not_staticFlag = False
        else:
            for u in self.url_ext_blacklist:
                if u in url_ext:
                    not_staticFlag = False

        return not_staticFlag


    def run(self):
        while True:
            try:
                request = self.queue.get()
                uri = request['uri']
                hash_value = self.HASH_Calc(requests_dict=request)
                in_white_site = self.check_in_keys(uri, self.white_site)
                in_black_site = self.check_in_keys(uri, self.black_site)

                is_notstatic = self.check_url_blackext(uri)

                # 判断是否已经Fuzzing过了、URL是否在测试范围内、是否在黑名单里、是否是静态文件
                if hash_value not in self.fuzzing_finished_hash and in_white_site and not in_black_site and is_notstatic:
                    self.fuzzing_finished_hash.append(hash_value)
                    method = request['method']
                    if "POST" in method:
                        self.Fuzzing_POST(request)
                    elif "GET" in method:
                        self.Fuzzing_GET(request)
            except:
                pass
