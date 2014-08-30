# PySSH2
An SSH library for Python3 to execute commands in a remote shell.

## Overview

This library lets you open a remote shell through SSH. It was tested with Linux and Cisco IOS remotes and worked perfectly.

It doesn't support Python2.

## Installation

```
pip3 install git+https://github.com/ihrwein/PySsh2
```

## Usage

The following example works like the `ssh` command. It reads from your stdin and sends the commands to the remote computer. You can find this example as the `clissh.py` file.


```python
import pyssh2
import time

HOST_NAME = "localhost"
USER_NAME = "sshuser"
PASSWORD = ""
PORT = 10022

def main():
    ssh = pyssh2.connect(USER_NAME, PASSWORD, HOST_NAME, PORT)
    shell = ssh.shell()
    print(shell.read(), end="")
    while True:
        try:
            command = input()
            shell.write(command)
            print(shell.read(), end="")
        except EOFError as err:
            ssh.close()
            break

if __name__ == "__main__":
    main()
```
