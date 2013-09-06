import unittest
import pyssh2
import socket
import ctypes
from pyssh2 import Ssh2

class TestPySSH2(unittest.TestCase):

    def test_import(self):
        import pyssh2

    def test_create_ssh_connection(self):
        ssh2 = Ssh2()
        session = ssh2.session_init()
        sock = socket.create_connection(("ssh.to.me", "22"))
        sock.setblocking(False)
        session.handshake(sock)
        rc = session.userauth_password(b"btibi", b"securepass")
        channel = session.channel_open()
        print(channel)
        rc = channel.request_pty(b"vt100")
        print(rc)    
        rc = channel.shell()
        print(rc)
        buffer = ctypes.create_string_buffer(200) 
        channel.read(buffer)
        print(str(buffer.raw))        

        sock.close()

if __name__ == "__main__":
    unittest.main()
    
