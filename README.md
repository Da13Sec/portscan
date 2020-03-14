# portscan

## 前言

在信息搜集阶段，用于批量端口扫描



## 项目介绍

该脚本结合了masscan的快速扫描全端口的有点和nmap服务探测的功能。两者之间优势互补。

文件名: portscan.py

开发语言: python3.8

第三方库：subprocess
threading
nmap

## 用法

1. pip3 install requirments.txt

2. 将要测试的urls保存为portscan.py同级目录下的ip.txt。
3. 
```
python3 portscan.py
```
也可以直接放进编辑器中运行

## 结果说明

这里对ip.txt文件url进行了测试。结果保存在result目录下的result.txt。



测试时间：1分钟

## 不足之处

大量扫描可能会导致ip被封，最好才用分布式架构。

## 致谢

最后感谢硬糖师傅的指导！

相关代码的分析参加我博客



如果有师傅们还有更好的建议，非常欢迎一起交流！