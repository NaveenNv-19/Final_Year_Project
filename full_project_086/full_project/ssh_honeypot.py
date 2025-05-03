
import logging
from logging.handlers import RotatingFileHandler
import paramiko
import threading
import socket
import time
from pathlib import Path

SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

base_dir = Path(__file__).parent.parent
server_key = base_dir / 'ssh_honeypy' / 'static' / 'server.key'
creds_audits_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'creds_audits.log.1'
cmd_audits_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'cmd_audits.log'

host_key = paramiko.RSAKey(filename=server_key)

logging_format = logging.Formatter('%(message)s')

funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = logging.FileHandler(cmd_audits_log_local_file_path, mode='a')  
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler(creds_audits_log_local_file_path, maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        funnel_logger.info(f'Client {self.client_ip} attempted connection with username: {username}, password: {password}')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True

def emulated_shell(channel, client_ip):
    channel.send(b"corporate-jumpbox2$ ")
    command = b""
    while True:
        try:
            char = channel.recv(1)
            if not char:
                print(f"[{client_ip}] No more data, breaking")
                break
            print(f"[{client_ip}] Received: {char}")
            channel.send(char)

            if char == b'\x7f' or char == b'\b':  
                if command:
                    command = command[:-1]
                    channel.send(b'\b \b')
                continue

            command += char

            if char == b"\r":  
                command_str = command.strip().decode().strip()
                if command_str:
                    print(f"[{client_ip}] Command detected: {command_str}")
                    funnel_logger.info(f'Command "{command_str}" executed by {client_ip}') 
                    response = b""
                    if command_str == "exit":
                        response = b"\nGoodbye!\r\n"
                        channel.send(response)
                        break
                    elif command_str == "pwd":
                        response = b"\n/home/corpuser\r\n"
                    elif command_str == "whoami":
                        response = b"\ncorpuser1\r\n"
                    elif command_str == "ls":
                        response = b"\njumpbox1.conf  system.log  .bashrc  .ssh  Documents  Downloads  Pictures\r\n"
                    elif command_str == "ls /etc":
                        response = b"\npasswd  shadow  ssh\r\n"
                    elif command_str == "cat /etc/passwd":
                        response = b"\nroot:x:0:0:root:/root:/bin/bash\ncorpuser1:x:1000:1000:User:/home/corpuser:/bin/bash\r\n"
                    elif command_str == "cat /etc/shadow":
                        response = b"\nroot:$6$salT$somehashhere:18723:0:99999:7:::\ncorpuser1:$6$salT$anotherhash:18723:0:99999:7:::\r\n"
                    elif command_str == "cat config.conf":
                        response = b"\n[database]\nuser=admin\npassword=SuperSecret123\n\r\n"
                    elif command_str == "cat ~/.bash_history":
                        response = b"\nsudo apt update\nsudo apt install net-tools\nping 8.8.8.8\nls -lah\r\n"
                    elif command_str == "uptime":
                        response = b"\n22:34:59 up 3 days, 12:58,  1 user,  load average: 0.04, 0.06, 0.05\r\n"
                    elif command_str == "df -h":
                        response = b"\nFilesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   15G   35G  30% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm\r\n"
                    elif command_str == "free -m":
                        response = b"\n              total        used        free      shared  buff/cache   available\nMem:           3948        1200        1500         100        1248        2500\nSwap:          2048           0        2048\r\n"
                    elif command_str == "ps aux":
                        response = b"\nUSER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  12345  1234 ?        Ss   Apr10   0:01 /sbin/init\ncorpuser1 1234  0.0  0.2  67890  5678 pts/0    Ss   22:34   0:00 bash\r\n"
                    elif command_str == "netstat -tuln":
                        response = b"\nActive Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\nudp        0      0 0.0.0.0:68              0.0.0.0:* \r\n"
                    elif command_str == "who":
                        response = b"\ncorpuser1 pts/0  2025-04-14 22:34 (192.168.1.100)\r\n"
                    elif command_str == "ifconfig":
                        response = b"\neth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255\n        ether 00:16:17:3a:4b:5c  txqueuelen 1000  (Ethernet)\r\n"
                    elif command_str == "cat /etc/hosts":
                        response = b"\n127.0.0.1   localhost\n192.168.1.10   corporate-\r\n"
                    elif command_str == "date":
                        response = b"\nMon Apr 14 22:34:59 UTC 2025\r\n"
                    else:
                        response = b"\ncommand not supported\r\n"
                    channel.send(response)
                    channel.send(b"corporate-jumpbox2$ ")
                command = b""
        except Exception as e:
            print(f"[{client_ip}] Shell receive error: {e}")
            break

def client_handle(client, addr, username, password, tarpit=False):
    client_ip = addr[0]
    print(f"{client_ip} connected to server.")
    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER

        server = Server(client_ip=client_ip, input_username=username, input_password=password)
        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(100)

        if channel is None:
            print("No channel was opened.")

        standard_banner = "Welcome to Ubuntu 22.04 LTS!\r\n\r\n"

        try:
            if tarpit:
                endless_banner = standard_banner * 100
                for char in endless_banner:
                    channel.send(char)
                    time.sleep(8)

            else:
                channel.send(standard_banner)

            emulated_shell(channel, client_ip=client_ip)

        except Exception as error:
            print(error)

    except Exception as error:
        print(error)
        print("!!! Exception !!!")

    finally:
        try:
            transport.close()
        except Exception:
            pass

        client.close()

def honeypot(address, port, username, password, tarpit=False):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    socks.listen(100)
    print(f"SSH server is listening on port {port}.")

    while True:
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password, tarpit))
            ssh_honeypot_thread.start()

        except Exception as error:
            print("!!! Exception - Could not open new client connection !!!")
            print(error)

if __name__ == '__main__':
    honeypot('0.0.0.0', 2280, tarpit=False)
