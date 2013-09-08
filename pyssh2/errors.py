class PySSH2Exception(Exception): pass

# authentication errors
class AuthError(PySSH2Exception): pass
# unable to open a socket level connection
class ConnectionError(PySSH2Exception): pass
# unable to open a session
class SessionError(PySSH2Exception): pass
#
class ChannelError(PySSH2Exception): pass

class ReadError(ChannelError): pass

class WriteError(ChannelError): pass
