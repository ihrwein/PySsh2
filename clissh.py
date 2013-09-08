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

