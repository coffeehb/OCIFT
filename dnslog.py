#!/usr/bin/env python
# -*- coding: utf-8 -*-
# author = Komi

import random
import requests
from string import ascii_lowercase


class DNSLog:
    def __init__(self):
        self.unique = ''
        self.sessionid = ''
        self.random = ''.join([random.choice(ascii_lowercase) for _ in range(10)])
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.95 Safari/537.36",
            'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            'Referer': "http://dnslog.xfkxfk.com/dnslog/",
            'Accept-Encoding': "gzip, deflate, sdch",
            'Cookie': "sessionid={my_sessionid}".format(my_sessionid=self.sessionid),
        }

    def getRandomDomain(self, custom='poc'):
        """
        full domain = [random].[custom].[unique].xfkxfk.com
        e.g. fezarvgo.poc.helloworld.xfkxfk.com
        """
        
        self.custom = custom
        return '%s.%s.%s.xfkxfk.com' % (self.random, self.custom, self.unique)

    def getDnsRecord(self, timeout=3):
        api_base = 'http://dnslog.xfkxfk.com/dnslog/'
        return requests.get(api_base, headers=self.headers, timeout=timeout).content

    def getHttpRecord(self, timeout=3):
        api_base = 'http://dnslog.xfkxfk.com/httplog/'
        return requests.get(api_base, headers=self.headers, timeout=timeout).content

    def verifyDNS(self, domain, timeout=3):
        return domain in self.getDnsRecord(timeout)

    def verifyHTTP(self, domain, timeout=3):
        return domain in self.getHttpRecord(timeout)

if __name__ == "__main__":
    dnslog = DNSLog()
    print dnslog.verifyDNS("xfkxfk")
