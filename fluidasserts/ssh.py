import paramiko
# pip3 install paramiko
# pip3 install cryptography


def login(host, username, password):
    ssh = paramiko.SSHClient()
    ssh.connect(host, username=username, password=password)
