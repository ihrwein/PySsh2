import time
import libssh2
import socket


class LibSsh2:
    
    def __init__(self):
        self.libssh2 = libssh2.LibSsh2()
        self.sessions = []
    
    def __del__(self):
        del self.sessions
        self.libssh2.exit()
    
    def open_session(self, trace=[], blocking=True, banner="SSH-2.0-libssh2_1.3.0"):
        session = Session(self.libssh2, trace, blocking, banner)
        self.sessions.append(session)
        return session
    
    def close_session(self, session):
        self.sessions.remove(session)
        del session


class Session:
    
    def __init__(self, lib, trace, blocking, banner):
        self.libssh2 = lib
        self.session = self.libssh2.session_init()
        val = 0
        for t in trace:
            val |= libssh2.LIBSSH2_TRACE[t]
        self.libssh2.trace_set(self.session, val)
        self.set_blocking(blocking)
        self.banner_set(banner)
    
    def __del__(self):
        self.libssh2.session_disconnect(self.session, "")
        self.libssh2.session_free(self.session)
    
    def set_blocking(self, state):
        self.libssh2.session_set_blocking(self.session, int(state))
    
    def banner_set(self, banner):
        self.libssh2.session_banner_set(self.session, banner)
    
    def startup(self, sock):
        self.sock = sock.fileno()
        self.libssh2.session_startup(self.session, self.sock)
    
    def userauth_list(self, username):
        return self.libssh2.userauth_list(self.session, username, len(username)).split(',')
    
    def userauth_password(self, username, password):
        self.libssh2.userauth_password(self.session, username, password)
    
    def userauth_agent(self, username):
        userauth_list = self.userauth_list(username)
        if 'publickey' in userauth_list:
            agent = Agent(self.libssh2, self.session)
            agent.userauth_agent(username)
            del agent
    
    def open_session(self):
        return Channel(self.libssh2, self)


class Channel:
    
    def __init__(self, lib, parent):
        self.libssh2 = lib
        self.parent = parent
        self.session = parent.session
        self.channel = self.libssh2.channel_open_session(self.session)
    
    def __del__(self):
        self.libssh2.channel_free(self.channel)
    
    def execute(self, command):
        #Send command
        self.libssh2.channel_exec(self.channel, command)
        #Get stdout
        stdout = ""
        buf = " "*1024
        count = self.libssh2.channel_read(self.channel, buf)
        while count>0:
            stdout += buf[:count]
            buf = " "*1024
            count = self.libssh2.channel_read(self.channel, buf)
        #Get stderr
        stderr = ""
        buf = " "*1024
        count = self.libssh2.channel_read_stderr(self.channel, buf)
        while count>0:
            stderr += buf[:count]
            buf = " "*1024
            count = self.libssh2.channel_read_stderr(self.channel, buf)
        return (stdout, stderr)


class Agent:
    
    def __init__(self, lib, session):
        self.libssh2 = lib
        self.session = session
        self.agent = self.libssh2.agent_init(self.session)
        self.libssh2.agent_connect(self.agent)
        self.libssh2.agent_list_identities(self.agent)
    
    def __del__(self):
        self.libssh2.agent_free(self.agent)
    
    def userauth_agent(self, username):
        identity = libssh2.POINTER(libssh2.AgentPublicKey)()
        prev_identity = libssh2.POINTER(libssh2.AgentPublicKey)()
        authenticated = False
        while (self.libssh2.agent_get_identity(self.agent, libssh2.byref(identity), prev_identity) == 0) and (not authenticated):
            authenticated = (self.libssh2.agent_userauth(self.agent, username, identity) == 0)
            prev_identity = identity


