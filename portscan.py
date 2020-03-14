import nmap
import argparse
import datetime
import threading
import requests
import re
import sys
import os
import time
import subprocess
requests.packages.urllib3.disable_warnings()
from queue import Queue

limitNumber = 50
lock = threading.Lock()
final_domains = []
final_port={}

f1 = open('./result/result.txt', 'w', encoding='utf-8')
class PortScan(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self._queue = queue

    def run(self):

        while not self._queue.empty():
            scan_ip = self._queue.get()
            try:
                lock.acquire()
                ports = portscan(scan_ip)
                lock.release()
                time.sleep(1)
                Scan(scan_ip, ports)
                lock.acquire()
                print_result(scan_ip)

                lock.release()

            except Exception as e:
                print(e)
                pass
def print_result(scan_ip):
    for i in final_port:
        if i ==scan_ip:
            f1.write(scan_ip + ':' + str(final_port[i])+'\n')
            print(scan_ip+':'+str(final_port[i]))
#调用masscan
def portscan(scan_ip):
    try:
        tmp_ports=[]
        ports = []
        command = f'echo "qpalzm123!"|sudo -S masscan '+scan_ip+' -p 1-65535 --rate 2000'


        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)

        while child.poll() is None:
            output = child.stdout.readline()
            line = str(output, encoding='utf-8').strip()
            if "found=" in line:

                print(line)
                if re.findall(r'port (\d{1,5})/tcp',line):
                    port = re.findall(r'port (\d{1,5})/tcp',line)[0]

                    tmp_ports.append(port)

                foundNumber = re.findall(r'found=(\d{1,5})', line)
                if int(foundNumber[-1]) > int(limitNumber):
                    os.kill(child.pid, 9)
                    print("有waf")
        if len(tmp_ports)>limitNumber:
            tmp_ports.clear()
        else:
            ports.extend(tmp_ports)

        return ports
    except Exception as e:
        print(e)

#调用nmap识别服务
def Scan(scan_ip,ports):
    service ={}
    nm = nmap.PortScanner()
    try:
        for port in ports:
            ret = nm.scan(scan_ip,port,arguments='-sV -Pn --open --version-all --host-timeout 20')

            try:
                if ret['scan'][scan_ip]['tcp'][int(port)]['name']:
                    service_name = ret['scan'][scan_ip]['tcp'][int(port)]['name']
                    if 'http' in service_name  or service_name == 'sun-answerbook':

                        service[port]=service_name
                    else:
                        service[port]=service_name
            except:
                service[port]='未找到服务'

    except Exception as e:
       print(e)
       pass
    finally:

        final_port[scan_ip] = service

#启用多线程扫描
def main(urls_file):
    queue = Queue()
    try:
        f = open(urls_file, 'r')
        for line in f.readlines():
            final_ip = line.strip('\n')
            queue.put(final_ip)
        f.close()
        threads = []
        thread_count = 100
        for i in range(thread_count):
            threads.append(PortScan(queue))

        for t in threads:
            t.start()

        for t in threads:
            t.join()


    except Exception as e:
        print(e)
        pass
#由于之前titlescna的存储原因，这里用存活的网站进行扫描。先获取所有的ip存进ip.txt




if __name__ =='__main__':
    start_time = datetime.datetime.now()

    parser = argparse.ArgumentParser(usage='python3 dirscan.py --target [source urls file]')
    parser.add_argument("--target", type=str, help="target urls file.")
    if len(sys.argv) == 1:
        sys.argv.append("-h")
    args = parser.parse_args()
    urls_file = args.target

    main(urls_file)
    f1.close()
    spend_time = (datetime.datetime.now() - start_time).seconds
    print('程序共运行了： ' + str(spend_time) + '秒')