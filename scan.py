# -*-coding: utf-8 -*-
# Author: mntn
# version: 1.0
import requests
from optparse import OptionParser
import threading

'''
    扫描脚本，每次学到新的漏洞时，尝试进行脚本自动化，每次更新进行版本记录。
    v1.0：spring-boot actuator xxe和rce漏洞，以及备份文件扫描
'''

def spring_boot(host, thread_name):
    # 将host处理为http://ip:port/形式
    if host[:4] == "http":
        if host[-1] == "/":
            url = host
        else:
            url = host + "/"
    elif host[-1] == "/":
        url = "http://" + host
    else:
        url = "http://" + host + "/"
    # 先扫描env，如果有，再扫描jolokia
    try:
        response_1 = requests.get(url+"env", timeout=5)
        if (response_1.status_code == 200) and ("profiles" in response_1.text):
            print("\033[32m[+] %s\t Nice! find env : %s\033[0m" % (thread_name, url+"env"))
            vuln_url.append(url+"env")
            response_2 = requests.get(url+"jolokia", timeout=5)
            if (response_2.status_code == 200) and ("request" in response_2.text):
                print("\033[32m[+] %s\t Nice! find jolokia, try XXE or RCE : %s\033[0m" % ( thread_name,url+"jolokia"))
                vuln_url.append(url+"jolokia")
        else:
            print("[-] %s\t404: %s" % (thread_name, url+"env"))
    except requests.exceptions.Timeout:
        print("[-] %s\tconnect timeout: %s" % (thread_name, url+"env"))
    except requests.exceptions.ConnectionError:
        print("[-] %s\tconnect failed: %s" % (thread_name, url+"env"))
    except Exception as e:
        print("[-] %s\tconnect with unknown error: %s" % (thread_name, url+"env"))


def backup(host, thread_name):
    # 将host处理为http://ip:port/形式
    if host[:4] == "http":
        if host[-1] == "/":
            url = host
        else:
            url = host+"/"
    elif host[-1] == "/":
        url = "http://"+host
    else:
        url = "http://"+host+"/"
    # 定义备份文件
    backup_file = ['.git/config', '.svn/entries', 'www.zip', 'www.rar', 'web.zip', 'web.rar',
                   'phpinfo.php', 'manager/html', 'jmx-console', 'web-console']
    for i in backup_file:
        try:
            full_url = url+i
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200 and response.text != "":
                print("\033[32m[+] %s\tNice! find backup : %s\033[0m" % (thread_name,full_url))
                vuln_url.append(full_url)
            elif response.status_code == 404:
                print("[-] %s\t404: %s" % (thread_name,full_url))
        except requests.exceptions.Timeout:
            print("[-] %s\tconnect timeout: %s" % (thread_name,full_url))
            continue
        except requests.exceptions.ConnectionError:
            print("[-] %s\tconnect failed: %s" % (thread_name,full_url))
            continue
        except:
            print("[-] %s\tconnect with unknown error: %s" % (thread_name,full_url))
            continue


# 定义全局变量
# vuln_url：存储存在漏洞的url
vuln_url = []
# thread_list：存放多线程
thread_list = []
# fun：保存可用的扫描函数
fun = [backup, spring_boot]
fun_name = ["backup", "spring_boot"]

# 启动多线程
def run_thread(thread, module_num, host, thread_name):
    for i in range(0, thread):
        t = threading.Thread(target=fun[module_num], args=(host,thread_name,))
        thread_list.append(t)
    for i in range(0, thread):
        thread_list[i].start()
    for i in range(0, thread):
        thread_list[i].join()

# 匹配出指定模块，通过中间变量开启多线程
def get_module(module):
    for i in range(0, len(fun_name)):
        if module == fun_name[i]:
            return i
    print("\033[31m[!] no such module! only: sprint_boot, backup\033[0m")
    exit()

# 读n行数据，起n个线程，等这n个线程结束，再起n个线程，直到数据被读完
def run_thread(uList, thread, module_num):
    f = open(uList, "r")
    host_list = f.readlines()
    count = 0
    while count<(len(host_list)/thread):
        for i in range(0, thread):
            if (thread*count+i)<len(host_list):
                t = threading.Thread(target=fun[module_num], args=(host_list[thread*count+i].strip(), "thread-"+str(i+1)))
                thread_list.append(t)
                thread_list[i].start()
                thread_list[i].join()
        del thread_list[:]
        count += 1

def main():
    usage ='''
    ************************************************
                       scan v1.0
     python3 scan.py [-u url] [-L list] [--module=]
     -u or --url: single url
     -L or --list: url list file
     --module: specify scan module
     -t: thread, default is 5
     -o: output file, default is scanFile.txt
     module: spring-boot, backup
    ************************************************'''
    # 定义输入参数
    parser = OptionParser(usage)  # 带参的话会把参数变量的内容作为帮助信息输出
    parser.add_option('-u', '--url', dest='target_Url', type='string', help='single url')
    parser.add_option('-L', '--list', dest='Url_List', type='string', help='url list file')
    parser.add_option('--module', dest='module', type='string', help='specify scan module')
    parser.add_option('-t', dest='thread', type='int', default=5, help='thread number')
    parser.add_option('-o', dest='outfile', type='string', default='scanFile.txt', help='output file')
    (options, args) = parser.parse_args()

    # 给输入参数赋值
    host = options.target_Url
    uList = options.Url_List
    module = options.module
    thread = options.thread
    output = options.outfile

    if host and module:
        module_num = get_module(module)
        print("\033[34m[~] Host: %s\033[0m\n\033[34m[~] module: %s\033[0m" % (host, module))
        fun[module_num](host, "thread-1")

    elif uList and module:
        module_num = get_module(module)
        print("\033[34m[~] File: %s\033[0m\n\033[34m[~] module: %s\033[0m\n\033[34m[~] threads: %d\033[0m" % (uList, module, thread))
        run_thread(uList, thread, module_num)
    else:
        print(usage)

    f = open(output, "w")
    for result in vuln_url:
        f.write(result+"\n")

if __name__ == '__main__':
    main()
