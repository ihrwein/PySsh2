import unittest
import pyssh2
import socket
import ctypes
import pdb
import time
from pyssh2 import Ssh2

SLEEP_TIME = 0.6

HOST_NAME = "localhost"
USER_NAME = "sshtest"
PASS""
PORT = 10022

class TestPySSH2(unittest.TestCase):

    def test_import(self):
        import pyssh2

    @unittest.skip
    def test_create_ssh_connection(self):
        ssh2 = Ssh2()
        session = ssh2.session_init()
        sock = socket.create_connection((HOST_NAME, PORT))
        sock.setblocking(False)
        session.handshake(sock)
        rc = session.userauth_password(bytes(USER_NAME, "utf-8"),
                                       bytes(PASSWORD, "utf-8"))
        channel = session.channel_open()
        print(channel)
        rc = channel.request_pty(b"vt100")
        print(rc)    
        rc = channel.shell()
        print(rc)
        buffer = ctypes.create_string_buffer(300) 
        #pdb.set_trace()
        size = channel.read(buffer)
        print(str(buffer.value[:size]))        
        size = channel.write("ls\n")
        buffer = ctypes.create_string_buffer(300)
        time.sleep(SLEEP_TIME)
        size = channel.read(buffer)
        print(str(buffer.value[:size]))
        session.disconnect(b"description")
        sock.close()
    
    def test_connect(self):
        ssh = pyssh2.connect(USER_NAME, PASSWORD, HOST_NAME, PORT)
        self.assertTrue(ssh != None)
        ssh.close()

class TestSSH2(unittest.TestCase):

    def setUp(self):
        self.ssh = pyssh2.SSH2(USER_NAME, PASSWORD, HOST_NAME, PORT)

    def tearDown(self):
        self.ssh.close()

    def test_init(self):
        self.assertTrue(self.ssh != None)
    
    def test_shell_read(self):
        shell = self.ssh.shell()
        motd = shell.read()
        # motd starts with "Welcome"
        #pdb.set_trace()
        self.assertGreaterEqual(motd.find("Welcome"), 0)

    def test_shell_write(self):
        #pdb.set_trace()
        shell = self.ssh.shell()
        motd = shell.read()
        shell.write("cd ..\n")
        # clear the buffer
        shell.read()
        shell.write("pwd\n")
        time.sleep(SLEEP_TIME)
        pwd = shell.read()
        #pdb.set_trace()
        self.assertGreaterEqual(pwd.find("/home"), 0)
        shell.write("cd /tmp", True)
        # clear the buffer
        shell.read()
        shell.write("pwd", True)
        pwd = shell.read()
        self.assertGreaterEqual(pwd.find("/tmp"), 0)
    

if __name__ == "__main__":
    unittest.main()
    
