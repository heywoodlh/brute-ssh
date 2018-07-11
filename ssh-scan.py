#!/usr/bin/env python3
import socket
import argparse
import contextlib
import sys
import os
import re
import netaddr
import subprocess
import dns.resolver


##Function for parsing through ranges of ports
def parseNumList(string):
    m = re.match(r'(\d+)(?:-(\d+))?$', string)
    # ^ (or use .split('-'). anyway you like.)
    if not m:
        raise argparse.ArgumentTypeError("'" + string + "' is not a range of number. Expected forms like '0-5' or '2'.")
    start = m.group(1)
    end = m.group(2) or start
    return list(range(int(start,10), int(end,10)+1))


parser = argparse.ArgumentParser(description="Python program that snatches banners of accessible ports")

parser.add_argument('--host', help='host(s) to scan', nargs='+', metavar='HOST', required='true')
parser.add_argument('-p', '--port', help='port(s) to scan', nargs='+', metavar='PORT', type=parseNumList, required='true')
parser.add_argument('-o', '--outfile', help='output to file', metavar='FILE')
parser.add_argument('--debug', help='print error messages', action='store_true')
parser.add_argument('-q', '--quiet', help='suppress all output', action='store_true')

args = parser.parse_args()

    
def port_check(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(.2)
    global port_result
    port_result = s.connect_ex((host, port))
    s.close
    if args.debug:
        if port_result != 0:
            print('Unable to connect to ' + host + ':' + str(port))
    return port_result


def banner_grab(host, port):
    s = socket.socket()
    s.connect((host,port))  
    global banner_results
    try:
        global banner
        banner = s.recv(4096)
        try:
            banner = banner.decode("utf-8")
        except UnicodeDecodeError:
            banner = banner
        banner_results = 'True'
    except:
        if args.debug:
            if non_ip == 'True':
                print(domain_name + ': unable to retrieve banner.')
            else:
                print(host + ': unable to retrieve banner.')
        banner_results = 'False'
    s.close()


def port_timed_check(host, port, file_write):
    global output
    if port_check(host, port) == 0:
        banner_grab(host, int(port))
        if banner_results == 'True':
            if non_ip == 'True':
                output = domain_name + ': ' + str(banner)
            else:
                output = host + ': ' + str(banner)
        else:
            output = ''
    else:
        output = ''

    
def dig(host):
    try:
        for ip in dns.resolver.query(host, 'A'):
            return str(ip)
        dig_error = 'False'
    except dns.resolver.NXDOMAIN:
        if args.debug:
            print('Unable to resolve domain ' + host)
        dig_error = 'True'


def port_scan(host, port, file_write):
    try:
        subprocess.Popen(port_timed_check(host, port, file_write))
    except TypeError:
        pass


def check_ssh(banner_output, file_write):
    ssh_titles = ['SSH', 'ssh']
    title_check = 0
    for title in ssh_titles:
        if title_check == 0:
            if title in banner_output:
                if file_write == 'True':
                    f.write(banner_output)
                if not args.quiet:
                    print(banner_output)
                title_check += 1
            


def ip_or_domain(host, file_write, ports):
    global non_ip
    if re.match("(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?", host):
        non_ip = 'False'
        ip = netaddr.IPNetwork(host)
        for host in ip:
            host = str(host)
            for portlist in ports[:]:
                for port in portlist:
                    port_scan(host, port, file_write)
                    check_ssh(output, file_write)
    else:
        non_ip = 'True'
        global domain_name
        domain_name = host
        ip = dig(host)
        for portlist in ports[:]:
            for port in portlist:
                port_scan(ip, port, file_write)
                check_ssh(banner_output, file_write)
        else:
            if args.debug:
                print('Unable to connect to host ' + domain_name)


if __name__ == '__main__':
    if args.outfile:
        outfile = args.outfile
        global f
        f = open(outfile, "a+")
        file_write = 'True'
    else:
        file_write = 'False'
    for host in args.host:
            ip_or_domain(host, file_write, args.port)
