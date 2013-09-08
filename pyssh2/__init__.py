import time
import os
import socket
import ctypes
import ctypes.util
import pdb

from pyssh2.errors import ReadError, WriteError, AuthError, ConnectionError

# Disconnect Codes (defined by SSH protocol)
SSH_DISCONNECT = {'HOST_NOT_ALLOWED_TO_CONNECT'         : 1,
                  'SSH_DISCONNECT_PROTOCOL_ERROR'       : 2,
                  'KEY_EXCHANGE_FAILED'                 : 3,
                  'RESERVED'                            : 4,
                  'MAC_ERROR'                           : 5,
                  'COMPRESSION_ERROR'                   : 6,
                  'SERVICE_NOT_AVAILABLE'               : 7,
                  'PROTOCOL_VERSION_NOT_SUPPORTED'      : 8,
                  'HOST_KEY_NOT_VERIFIABLE'             : 9,
                  'CONNECTION_LOST'                     : 10,
                  'BY_APPLICATION'                      : 11,
                  'TOO_MANY_CONNECTIONS'                : 12,
                  'AUTH_CANCELLED_BY_USER'              : 13,
                  'NO_MORE_AUTH_METHODS_AVAILABLE'      : 14,
                  'ILLEGAL_USER_NAME'                   : 15}

LIBSSH2_TRACE = {'TRANS'     : (1<<1),
                 'KEX'       : (1<<2),
                 'AUTH'      : (1<<3),
                 'CONN'      : (1<<4),
                 'SCP'       : (1<<5),
                 'SFTP'      : (1<<6),
                 'ERROR'     : (1<<7),
                 'PUBLICKEY' : (1<<8),
                 'SOCKET'    : (1<<9),
                 'ALL'       : (1<<10)-1}

LIBSSH2_ERROR = {  0 : 'NONE',
                  -1 : 'SOCKET_NONE',
                  -2 : 'BANNER_RECV',
                  -3 : 'BANNER_SEND',
                  -4 : 'INVALID_MAC',
                  -5 : 'KEX_FAILURE',
                  -6 : 'ALLOC',
                  -7 : 'SOCKET_SEND',
                  -8 : 'KEY_EXCHANGE_FAILURE',
                  -9 : 'TIMEOUT',
                 -10 : 'HOSTKEY_INIT',
                 -11 : 'HOSTKEY_SIGN',
                 -12 : 'DECRYPT',
                 -13 : 'SOCKET_DISCONNECT',
                 -14 : 'PROTO',
                 -15 : 'PASSWORD_EXPIRED',
                 -16 : 'FILE',
                 -17 : 'METHOD_NONE',
                 -18 : 'AUTHENTICATION_FAILED/PUBLICKEY_UNRECOGNIZED',
                 -19 : 'PUBLICKEY_UNVERIFIED',
                 -20 : 'CHANNEL_OUTOFORDER',
                 -21 : 'CHANNEL_FAILURE',
                 -22 : 'CHANNEL_REQUEST_DENIED',
                 -23 : 'CHANNEL_UNKNOWN',
                 -24 : 'CHANNEL_WINDOW_EXCEEDED',
                 -25 : 'CHANNEL_PACKET_EXCEEDED',
                 -26 : 'CHANNEL_CLOSED',
                 -27 : 'CHANNEL_EOF_SENT',
                 -28 : 'SCP_PROTOCOL',
                 -29 : 'ZLIB',
                 -30 : 'SOCKET_TIMEOUT',
                 -31 : 'SFTP_PROTOCOL',
                 -32 : 'REQUEST_DENIED',
                 -33 : 'METHOD_NOT_SUPPORTED',
                 -34 : 'INVAL',
                 -35 : 'INVALID_POLL_TYPE',
                 -36 : 'PUBLICKEY_PROTOCOL',
                 -37 : 'EAGAIN',
                 -38 : 'BUFFER_TOO_SMALL',
                 -39 : 'BAD_USE',
                 -40 : 'COMPRESS',
                 -41 : 'OUT_OF_BOUNDARY',
                 -42 : 'AGENT_PROTOCOL',
                 -43 : 'SOCKET_RECV',
                 -44 : 'ENCRYPT',
                 -45 : 'BAD_SOCKET'}

LIBSSH2_KNOWNHOST = {'TYPE_MASK'     : 0xffff,
                     'TYPE_PLAIN'    : 1,
                     'TYPE_SHA1'     : 2, #always base64 encoded
                     'TYPE_CUSTOM'   : 3,
                     'KEYENC_MASK'   : (3<<16),
                     'KEYENC_RAW'    : (1<<16),
                     'KEYENC_BASE64' : (2<<16)}

LIBSSH2_HOSTKEY_TYPE = {0: 'UNKNOWN',
                        1: 'RSA',
                        2: 'DSS'}
 
class Ssh2:
    
    #int libssh2_init(int flags);
    def __init__(self):
        libpath = ctypes.util.find_library("ssh2")
        self.libssh2 = ctypes.CDLL(libpath)
        self.libssh2.libssh2_init.restype = ctypes.c_int
        rc = self.libssh2.libssh2_init(0)
    
    #LIBSSH2_SESSION * libssh2_session_init_ex(LIBSSH2_ALLOC_FUNC((*myalloc)), LIBSSH2_FREE_FUNC((*myfree)), LIBSSH2_REALLOC_FUNC((*myrealloc)), void *abstract);
    #LIBSSH2_SESSION * libssh2_session_init(void);
    def session_init(self, myalloc=None, myfree=None, myrealloc=None, abstract=None):
        self.libssh2.libssh2_session_init_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self.libssh2.libssh2_session_init_ex.restype = ctypes.POINTER(Session.SessionType)
        session = self.libssh2.libssh2_session_init_ex(myalloc, myfree, myrealloc, abstract)
        return Session(self, session)


class Session:
    
    class SessionType(ctypes.Structure):
        pass
    
    def __init__(self, parent, session):
        self.parent = parent
        self.libssh2 = parent.libssh2
        self.session = session
        self.socket = None
        self.username = None
    
    #int libssh2_channel_free(LIBSSH2_CHANNEL *channel);
    def __del__(self):
        self.libssh2.libssh2_session_free.restype = ctypes.c_int
        rc = self.libssh2.libssh2_session_free(self.session)
    
    #int libssh2_session_disconnect_ex(LIBSSH2_SESSION *session, int reason, const char *description, const char *lang);
    def disconnect(self, description, reason=SSH_DISCONNECT['BY_APPLICATION'], lang=b""):
        self.libssh2.libssh2_session_disconnect_ex.argtypes = [ctypes.POINTER(Session.SessionType), ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
        self.libssh2.libssh2_session_disconnect_ex.restype = ctypes.c_int
        rc = self.libssh2.libssh2_session_disconnect_ex(self.session, reason, description, lang)
        return rc
    
    #int libssh2_session_banner_set(LIBSSH2_SESSION *session, const char *banner);
    def banner_set(self, banner=b"SSH-2.0-libssh2_1.3.0"):
        self.libssh2.libssh2_banner_set.argtypes = [ctypes.POINTER(Session.SessionType), ctypes.c_char_p]
        self.libssh2.libssh2_banner_set.restype = ctypes.c_int
        rc = self.libssh2.libssh2_banner_set(self.session, banner)
        return rc
    
    #void libssh2_trace(LIBSSH2_SESSION *session, int bitmask);
    def trace(self, bitmask):
        self.libssh2.libssh2_trace.argtypes = [ctypes.POINTER(Session.SessionType), ctypes.c_int]
        self.libssh2.libssh2_trace.restype = None
        self.libssh2.libssh2_trace(self.session, bitmask)
    
    #int libssh2_session_handshake(LIBSSH2_SESSION *session, libssh2_socket_t socket);
    def handshake(self, socket):
        self.socket = socket
        self.libssh2.libssh2_session_handshake.argtypes = [ctypes.POINTER(Session.SessionType), ctypes.c_int]
        self.libssh2.libssh2_session_handshake.restype = ctypes.c_int
        rc = self.libssh2.libssh2_session_handshake(self.session, socket.fileno())
        return rc
    
    #void libssh2_session_set_blocking(LIBSSH2_SESSION *session, int blocking);
    def set_blocking(self, blocking):
        self.libssh2.libssh2_set_blocking.argtypes = [ctypes.POINTER(Session.SessionType), ctypes.c_int]
        self.libssh2.libssh2_set_blocking.restype = None
        self.libssh2.libssh2_set_blocking(self.session, blocking)
    
    #LIBSSH2_CHANNEL * libssh2_channel_open_ex(LIBSSH2_SESSION *session, const char *channel_type, unsigned int channel_type_len, unsigned int window_size, unsigned int packet_size, const char *message, unsigned int message_len);
    #LIBSSH2_CHANNEL * libssh2_channel_open_session(LIBSSH2_SESSION *session);
    def channel_open(self, channel_type=b"session", window_size=256*1024, packet_size=32768, message=b""):
        self.libssh2.libssh2_channel_open_ex.argtypes = [ctypes.POINTER(Session.SessionType), ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_char_p, ctypes.c_uint]
        self.libssh2.libssh2_channel_open_ex.restype = ctypes.POINTER(Channel.ChannelType)
        channel = self.libssh2.libssh2_channel_open_ex(self.session, channel_type, len(channel_type), window_size, packet_size, message, len(message))
        return Channel(self, channel)
    
    #LIBSSH2_CHANNEL * libssh2_channel_direct_tcpip_ex(LIBSSH2_SESSION *session, const char *host, int port, const char *shost, int sport);
    #LIBSSH2_CHANNEL * libssh2_channel_direct_tcpip(LIBSSH2_SESSION *session, const char *host, int port);
    def direct_tcpip(self, host, port, shost=b"127.0.0.1", sport=22):
        self.libssh2.libssh2_channel_criect_tcpip_ex.argtypes = [ctypes.POINTER(Session.SessionType), ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        self.libssh2.libssh2_channel.direct_tcpip_ex.restype = ctypes.POINTER(Channel.ChannelType)
        channel = self.libssh2.libssh2_channel.direct_tcpip_ex(host, port, shost, sport)
        return Channel(self, channel)
    
    #LIBSSH2_AGENT *libssh2_agent_init(LIBSSH2_SESSION *session);
    def agent_init(self):
        self.libssh2.libssh2_agent_init.argtypes = [ctypes.POINTER(Session.SessionType)]
        self.libssh2.libssh2_agent_init.restype = ctypes.POINTER(Agent.AgentType)
        agent = self.libssh2.libssh2_agent_init(self.session)
        return Agent(self, agent)
    
    #const char *libssh2_session_hostkey(LIBSSH2_SESSION *session,   size_t *len, int *type);
    def hostkey(self):
        self.libssh2.libssh2_session_hostkey.argtypes = [ctypes.POINTER(Session.SessionType), ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_int)]
        self.libssh2.libssh2_session_hostkey.restype = ctypes.POINTER(ctypes.c_char)
        keyLen = ctypes.c_size_t(0)
        keyType = ctypes.c_int(0)
        key = self.libssh2.libssh2_session_hostkey(self.session, ctypes.byref(keyLen), ctypes.byref(keyType))
        return (key, keyLen, LIBSSH2_HOSTKEY_TYPE[keyType.value])
    
    #LIBSSH2_KNOWNHOSTS *libssh2_knownhost_init(LIBSSH2_SESSION *session);
    def knownhost_init(self):
        self.libssh2.libssh2_knownhost_init.argtypes = [ctypes.POINTER(Session.SessionType)]
        self.libssh2.libssh2_knownhost_init.restype = ctypes.POINTER(KnownHosts.KnownHostsType)
        knownHosts = self.libssh2.libssh2_knownhost_init(self.session)
        return KnownHosts(self, knownHosts)
    
    def isKnownHost(self, hostname, port, known_hosts="~/.ssh/known_hosts"):
        home = (os.getenv('USERPROFILE') or os.getenv('HOME'))
        (key, keyLen, keyType) = self.hostkey()
        knownHosts = self.knownhost_init()
        knownHosts.readfile(known_hosts.replace("~", home))
        return (knownHosts.checkp(hostname, port, key, keyLen, LIBSSH2_KNOWNHOST['TYPE_PLAIN']|LIBSSH2_KNOWNHOST['KEYENC_RAW']) == 'MATCH')
    
    #char * libssh2_userauth_list(LIBSSH2_SESSION *session, const char *username, unsigned int username_len);
    def userauth_list(self, username):
        self.username = username
        self.libssh2.libssh2_userauth_list.argtypes = [ctypes.POINTER(Session.SessionType), ctypes.c_char_p, ctypes.c_uint]
        self.libssh2.libssh2_userauth_list.restype = ctypes.c_char_p
        result = self.libssh2.libssh2_userauth_list(self.session, username, len(username))
        return result
    
    #int libssh2_userauth_password_ex(LIBSSH2_SESSION *session,   const char *username,   unsigned int username_len,   const char *password,   unsigned int password_len,   LIBSSH2_PASSWD_CHANGEREQ_FUNC((*passwd_change_cb)));
    #int libssh2_userauth_password(LIBSSH2_SESSION *session,   const char *username,   const char *password);
    def userauth_password(self, username, password, passwd_change_cb=None):
        self.username = username
        self.libssh2.libssh2_userauth_password_ex.argtypes = [ctypes.POINTER(Session.SessionType), ctypes.c_char_p, ctypes.c_uint, ctypes.c_char_p, ctypes.c_uint, ctypes.c_void_p]
        self.libssh2.libssh2_userauth_password_ex.restype = ctypes.c_int
        rc = self.libssh2.libssh2_userauth_password_ex(self.session, username, len(username), password, len(password), passwd_change_cb)
        return rc
    
    def userauth_agent(self, username):
        self.username = username
        authenticated = False
        agent = self.agent_init()
        agent.connect()
        agent.list_identities()
        identity = ctypes.POINTER(Agent.AgentPublicKey)()
        prev = None
        while (not agent.get_identity(identity, prev)) and (not authenticated):
            authenticated = (not agent.userauth(username, identity))
            prev = identity
        return authenticated
    
    #LIBSSH2_CHANNEL * libssh2_scp_recv(LIBSSH2_SESSION *session, const char *path, struct stat *sb);
    def scp_recv(self, path):
        stat = " "*1024
        self.libssh2.libssh2_scp_recv.argtypes = [ctypes.POINTER(Session.SessionType), ctypes.c_char_p, ctypes.c_char_p]
        self.libssh2.libssh2_scp_recv.restype = ctypes.POINTER(Channel.ChannelType)
        channel = self.libssh2.libssh2_scp_recv(self.session, path, stat)
        return Channel(self, channel)
    
    def sftp_init(self):
        self.libssh2.libssh2_sftp_init.argtypes = [ctypes.POINTER(Session.SessionType)]
        self.libssh2.libssh2_sftp_init.restype = ctypes.POINTER(SFTP.SFTPType)
        sftp = self.libssh2.libssh2_sftp_init(self.session)
        return SFTP(self, sftp)


class KnownHosts:
    
    class KnownHostsType(ctypes.Structure):
        pass
    
    class KnownHost(ctypes.Structure):
        pass
    
    CHECK = {0 : 'MATCH',
             1 : 'MISMATCH',
             2 : 'NOTFOUND',
             3 : 'FAILURE'}
    
    def __init__(self, parent, knownHosts):
        self.parent = parent
        self.session = parent.session
        self.libssh2 = parent.libssh2
        self.knownHosts = knownHosts
    
    #void libssh2_knownhost_free(LIBSSH2_KNOWNHOSTS *hosts);
    def __del__(self):
        self.libssh2.libssh2_knownhost_free.argtypes = [ctypes.POINTER(KnownHosts.KnownHostsType)]
        self.libssh2.libssh2_knownhost_free.restype = None
        self.libssh2.libssh2_knownhost_free(self.knownHosts)
    
    #int libssh2_knownhost_readfile(LIBSSH2_KNOWNHOSTS *hosts,   const char *filename, int type);
    def readfile(self, filename, type=1):
        self.libssh2.libssh2_knownhost_readfile.argtypes = [ctypes.POINTER(KnownHosts.KnownHostsType), ctypes.c_char_p, ctypes.c_int]
        self.libssh2.libssh2_knownhost_readfile.restype = ctypes.c_int
        rc = self.libssh2.libssh2_knownhost_readfile(self.knownHosts, filename, type)
        if rc<0:
            print(LIBSSH2_ERROR[rc])
        return rc
    
    #int libssh2_knownhost_get(LIBSSH2_KNOWNHOSTS *hosts,   struct libssh2_knownhost **store,   struct libssh2_knownhost *prev):
    def get(self, store, prev):
        self.libssh2.libssh2_knownhost_get.argtypes = [ctypes.POINTER(KnownHosts.KnownHostsType), ctypes.POINTER(ctypes.POINTER(KnownHosts.KnownHost)), ctypes.POINTER(KnownHosts.KnownHost)]
        self.libssh2.libssh2_knownhost_get.restype = ctypes.c_int
        rc = self.libssh2.libssh2_knownhost_get(self.knownHosts, ctypes.byref(store), prev)
        return rc
    
    #int libssh2_knownhost_check(LIBSSH2_KNOWNHOSTS *hosts,   const char *host,   const char *key, size_t keylen,   int typemask,   struct libssh2_knownhost **knownhost);
    def check(self, host, key, keyLen, typemask):
        self.libssh2.libssh2_knownhost_check.argtypes = [ctypes.POINTER(KnownHosts.KnownHostsType), ctypes.c_char_p, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(KnownHosts.KnownHost))]
        self.libssh2.libssh2_knownhost_check.restype = ctypes.c_int
        knownhost = ctypes.POINTER(KnownHosts.KnownHost)()
        rc = self.libssh2.libssh2_knownhost_check(self.knownHosts, host, key, keyLen, typemask, ctypes.byref(knownhost))
        return KnownHosts.CHECK[rc]
    
    #int libssh2_knownhost_checkp(LIBSSH2_KNOWNHOSTS *hosts,   const char *host, int port,   const char *key, size_t keylen,   int typemask,   struct libssh2_knownhost **knownhost);
    def checkp(self, host, port, key, keyLen, typemask):
        self.libssh2.libssh2_knownhost_checkp.argtypes = [ctypes.POINTER(KnownHosts.KnownHostsType), ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(KnownHosts.KnownHost))]
        self.libssh2.libssh2_knownhost_checkp.restype = ctypes.c_int
        knownhost = ctypes.POINTER(KnownHosts.KnownHost)()
        rc = self.libssh2.libssh2_knownhost_checkp(self.knownHosts, host, port, key, keyLen, typemask, ctypes.byref(knownhost))
        return KnownHosts.CHECK[rc]


class Agent:
    
    class AgentType(ctypes.Structure):
        pass
    
    class AgentPublicKey(ctypes.Structure):
        pass
    
    def __init__(self, parent, agent):
        self.parent = parent
        self.session = parent.session
        self.libssh2 = parent.libssh2
        self.agent = agent
    
    #void libssh2_agent_free(LIBSSH2_AGENT *agent);
    def __del__(self):
        self.libssh2.libssh2_agent_free.argtypes = [ctypes.POINTER(Agent.AgentType)]
        self.libssh2.libssh2_agent_free.restype = None
        self.libssh2.libssh2_agent_free(self.agent)
    
    #int libssh2_agent_connect(LIBSSH2_AGENT *agent);
    def connect(self):
        self.libssh2.libssh2_agent_connect.argtypes = [ctypes.POINTER(Agent.AgentType)]
        self.libssh2.libssh2_agent_connect.restype = ctypes.c_int
        rc = self.libssh2.libssh2_agent_connect(self.agent)
        return rc
    
    #int libssh2_agent_list_identities(LIBSSH2_AGENT *agent);
    def list_identities(self):
        self.libssh2.libssh2_agent_list_identities.argtypes = [ctypes.POINTER(Agent.AgentType)]
        self.libssh2.libssh2_agent_list_identities.restype = ctypes.c_int
        rc = self.libssh2.libssh2_agent_list_identities(self.agent)
        return rc
    
    #int libssh2_agent_get_identity(LIBSSH2_AGENT *agent,   struct libssh2_agent_publickey **store,   struct libssh2_agent_publickey *prev);
    def get_identity(self, store, prev):
        self.libssh2.libssh2_agent_get_identity.argtypes = [ctypes.POINTER(Agent.AgentType), ctypes.POINTER(ctypes.POINTER(Agent.AgentPublicKey)), ctypes.POINTER(Agent.AgentPublicKey)]
        self.libssh2.libssh2_agent_get_identity.restype = ctypes.c_int
        rc = self.libssh2.libssh2_agent_get_identity(self.agent, ctypes.byref(store), prev)
        if rc<0:
            print(LIBSSH2_ERROR[rc])
        return rc
    
    #int libssh2_agent_userauth(LIBSSH2_AGENT *agent,   const char *username,   struct libssh2_agent_publickey *identity);
    def userauth(self, username, identity):
        self.libssh2.libssh2_agent_userauth.argtypes = [ctypes.POINTER(Agent.AgentType), ctypes.c_char_p, ctypes.POINTER(Agent.AgentPublicKey)]
        self.libssh2.libssh2_agent_userauth.restype = ctypes.c_int
        rc = self.libssh2.libssh2_agent_userauth(self.agent, username, identity)
        return rc
    
    #int libssh2_agent_disconnect(LIBSSH2_AGENT *agent);
    def disconnect(self):
        self.libssh2.libssh2_agent_disconnect.argtypes = [ctypes.POINTER(Agent.AgentType)]
        self.libssh2.libssh2_agent_disconnect.restype = ctypes.c_int
        rc = self.libssh2.libssh2_agent_disconnect(self.agent)
        return rc


class Channel:
    
    class ChannelType(ctypes.Structure):
        pass
    
    class Stat(ctypes.Structure):
        pass
    
    def __init__(self, parent, channel):
        self.parent = parent
        self.session = parent.session
        self.libssh2 = parent.libssh2
        self.libssh2.libssh2_channel_open_ex.restype = ctypes.POINTER(Channel.ChannelType)
        self.channel = channel
    
    #int libssh2_channel_free(LIBSSH2_CHANNEL *channel);
    def __del__(self):
        self.libssh2.libssh2_channel_free.argtypes = [ctypes.POINTER(Channel.ChannelType)]
        self.libssh2.libssh2_channel_free.restype = ctypes.c_int
        rc = self.libssh2.libssh2_channel_free(self.channel)
    
    #int libssh2_channel_close(LIBSSH2_CHANNEL *channel);
    def close(self):
        self.libssh2.libssh2_channel_close.argtypes = [ctypes.POINTER(Channel.ChannelType)]
        self.libssh2.libssh2_channel_close.restype = ctypes.c_int
        rc = self.libssh2.libssh2_channel_close(self.channel)
        return rc
    
    #int libssh2_channel_process_startup(LIBSSH2_CHANNEL *channel,   const char *request,   unsigned int request_len,   const char *message,   unsigned int message_len);
    def process_startup(self, request, request_len, message, message_len):
        self.libssh2.libssh2_channel_process_startup.argtypes = [ctypes.POINTER(Channel.ChannelType), ctypes.c_char_p, ctypes.c_uint, ctypes.c_char_p, ctypes.c_uint]
        self.libssh2.libssh2_channel_process_startup.restype = ctypes.c_int
        rc = self.libssh2.libssh2_channel_process_startup(self.channel, request, request_len, message, message_len)
        if rc<0:
            print(LIBSSH2_ERROR[rc])
        return rc
    
    #int libssh2_channel_exec(LIBSSH2_CHANNEL *channel, const char *command);
    def execute(self, command):
        return self.process_startup(b"exec", len(b"exec"), command, len(command))
    
    #int libssh2_channel_shell(LIBSSH2_CHANNEL *channel)
    def shell(self):
        return self.process_startup(b"shell", len(b"shell"), None, 0)
    
    #int libssh2_channel_request_pty_ex(LIBSSH2_CHANNEL *channel, const char *term, unsigned int term_len, const char *modes, unsigned int modes_len, int width, int height, int width_px, int height_px);
    def request_pty_ex(self, term, modes, width, height, width_px, height_px):
        self.libssh2.libssh2_channel_request_pty_ex.argtypes = [ctypes.POINTER(Channel.ChannelType), ctypes.c_char_p, ctypes.c_uint, ctypes.c_char_p, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int]
        self.libssh2.libssh2_channel_request_pty_ex.restype = ctypes.c_int
        rc = self.libssh2.libssh2_channel_request_pty_ex(self.channel, term, len(term), modes, len(modes), width, height, width_px, height_px)
        if rc<0:
            print(LIBSSH2_ERROR[rc])
        return rc

    #int libssh2_channel_request_pty(LIBSSH2_CHANNEL *channel, char *term);
    def request_pty(self, term):
        rc = self.request_pty_ex(term, b"", 80, 24, 0, 0)
        return rc
    
    #LIBSSH2_API int libssh2_channel_setenv_ex(LIBSSH2_CHANNEL *channel, const char *varname, unsigned int varname_len, const char *value, unsigned int value_len);
    def setenv_ex(self, varname, value):
        self.libssh2.libssh2_channel_setenv_ex.argtypes = [ctypes.POINTER(Channel.ChannelType), ctypes.c_char_p, ctypes.c_uint, ctypes.c_char_p, ctypes.c_uint]
        self.libssh2.libssh2_channel_setenv_ex.restype = ctypes.c_int
        rc = self.libssh2.libssh2_channel_setenv_ex(self.channel, varname, len(varname), value, len(value))
        if rc<0:
            print(LIBSSH2_ERROR[rc])
        return rc
    
    #define libssh2_channel_setenv(channel, varname, value) libssh2_channel_setenv_ex((channel), (varname), strlen(varname), (value), strlen(value))
    def setenv(self, varname, value):
        rc = self.setenv_ex(varname, value)
        return rc

    #ssize_t libssh2_channel_read_ex(LIBSSH2_CHANNEL *channel, int stream_id, char *buf, size_t buflen);
    def read_ex(self, buf, stream_id):
        self.libssh2.libssh2_channel_read_ex.argtypes = [ctypes.POINTER(Channel.ChannelType), ctypes.c_int, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t]
        self.libssh2.libssh2_channel_read_ex.restype = ctypes.c_ssize_t
        size = self.libssh2.libssh2_channel_read_ex(self.channel, stream_id, buf, len(buf))
        return size
    
    #ssize_t libssh2_channel_read(LIBSSH2_CHANNEL *channel, char *buf, size_t buflen);
    def read(self, buf):
        size = self.read_ex(buf, 0)
        return size
    
    #ssize_t libssh2_channel_read_stderr(LIBSSH2_CHANNEL *channel, char *buf, size_t buflen);
    def read_stderr(self, buf):
        size = self.read_ex(buf, 1)
        return size
    
    #ssize_t libssh2_channel_write_ex(LIBSSH2_CHANNEL *channel,   int stream_id, char *buf,   size_t buflen);
    def write_ex(self, stream_id, buf):
        self.libssh2.libssh2_channel_write_ex.argtypes = [ctypes.POINTER(Channel.ChannelType), ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
        self.libssh2.libssh2_channel_write_ex.restype = ctypes.c_ssize_t
        size = self.libssh2.libssh2_channel_write_ex(self.channel, stream_id, buf, len(buf))
        return size
    
    #ssize_t libssh2_channel_write(LIBSSH2_CHANNEL *channel, const char *buf, size_t buflen);
    def write(self, buf):
        if isinstance(buf, (str)):
            buf = bytes(buf, "utf-8")
        size = self.write_ex(0, buf)
        return size
    
    #ssize_t libssh2_channel_write_stderr(LIBSSH2_CHANNEL *channel, const char *buf, size_t buflen);
    def write_stderr(self, buf):
        size = self.write_ex(1, buf)
        return size
    
    #int libssh2_channel_flush_ex(LIBSSH2_CHANNEL *channel, int streamid);
    def flush_ex(self, streamid):
        self.libssh2.libssh2_channel_flush_ex.argtypes = [ctypes.POINTER(Channel.ChannelType), ctypes.c_int]
        self.libssh2.libssh2_channel_flush_ex.restype = ctypes.c_int
        rc = self.libssh2.libssh2_channel_flush_ex(self.channel, streamid)
        return rc
    
    #int libssh2_channel_flush(LIBSSH2_CHANNEL *channel);
    def flush(self):
        rc = self.flush_ex(0)
        return rc
    
    #int libssh2_channel_flush_stderr(LIBSSH2_CHANNEL *channel);
    def flush_stderr(self):
        rc = self.flush_ex(1)
        return rc





class SFTP:
    
    class SFTPType(ctypes.Structure):
        pass
    
    OPEN = {'FILE' : 0,
            'DIR'  : 1}
    
    FXF = {'READ'   : (1<<0),
           'WRITE'  : (1<<1),
           'APPEND' : (1<<2),
           'CREAT'  : (1<<3),
           'TRUNC'  : (1<<4),
           'EXCL'   : (1<<5)}
    
    S = {'IRWXU' : 700,
         'IRUSR' : 400,
         'IWUSR' : 200,
         'IXUSR' : 100,
         'IRWXG' : 70,
         'IRGRP' : 40,
         'IWGRP' : 20,
         'IXGRP' : 10,
         'IRWXO' : 7,
         'IROTH' : 4,
         'IWOTH' : 2,
         'IXOTH' : 1}
    
    def __init__(self, parent, sftp):
        self.parent = parent
        self.session = parent.session
        self.libssh2 = parent.libssh2
        self.sftp = sftp
    
    #int libssh2_sftp_shutdown(LIBSSH2_SFTP *sftp);
    def __del__(self):
        self.libssh2.libssh2_sftp_shutdown.argtypes = [ctypes.POINTER(SFTP.SFTPType)]
        self.libssh2.libssh2_sftp_shutdown.restype = ctypes.c_int
        rc = self.libssh2.libssh2_sftp_shutdown(self.sftp)
    
    #LIBSSH2_SFTP_HANDLE * libssh2_sftp_open_ex(LIBSSH2_SFTP *sftp, const char *filename,   unsigned int filename_len, unsigned long flags,   long mode, int open_type);
    def open_ex(self, path, flags, mode, open_type):
        self.libssh2.libssh2_sftp_open_ex.argtypes = [ctypes.POINTER(SFTP.SFTPType), ctypes.c_char_p, ctypes.c_uint, ctypes.c_ulong, ctypes.c_long, ctypes.c_int]
        self.libssh2.libssh2_sftp_open_ex.restype = ctypes.POINTER(SFTPHandle.SFTPHandleType)
        sftpHandle = self.libssh2.libssh2_sftp_open_ex(self.sftp, path, len(path), flags, mode, open_type)
        return sftpHandle

    #LIBSSH2_SFTP_HANDLE * libssh2_sftp_open(LIBSSH2_SFTP *sftp, const char *path, unsigned long flags, long mode);
    def openfile(self, path, flags=FXF['READ'], mode=0):
        sftpHandle = self.open_ex(path, flags, mode, SFTP.OPEN['FILE'])
        return SFTPHandle(self, sftpHandle, path)
    
    #unsigned long libssh2_sftp_last_error(LIBSSH2_SFTP *sftp);
    def last_error(self):
        self.libssh2.libssh2_sftp_last_error.argtypes = [ctypes.POINTER(SFTP.SFTPType)]
        self.libssh2.libssh2_sftp_last_error.restype = ctypes.c_ulong
        rc = self.libssh2.libssh2_sftp_last_error(self.sftp)
        return rc


class SFTPHandle:
    
    class SFTPHandleType(ctypes.Structure):
        pass
    
    class SFTPAttributes(ctypes.Structure):
        _fields_ = [('flags', ctypes.c_ulong),
                    ('filesize', ctypes.c_uint64),
                    ('uid', ctypes.c_ulong),
                    ('gid', ctypes.c_ulong),
                    ('permissions', ctypes.c_ulong),
                    ('atime', ctypes.c_ulong),
                    ('mtime', ctypes.c_ulong)]
 
    SEEK_SET = 0
    SEEK_CUR = 1
    SEEK_END = 2
    
    def __init__(self, parent, sftpHandle, path):
        self.parent = parent
        self.session = parent.session
        self.libssh2 = parent.libssh2
        self.sftpHandle = sftpHandle
        self.path = path
    
    #int libssh2_sftp_close_handle(LIBSSH2_SFTP_HANDLE *handle);
    def __del__(self):
        self.libssh2.libssh2_sftp_close_handle.argtypes = [ctypes.POINTER(SFTPHandle.SFTPHandleType)]
        self.libssh2.libssh2_sftp_close_handle.restype = ctypes.c_int
        rc = self.libssh2.libssh2_sftp_close_handle(self.sftpHandle)
    
    #ssize_t libssh2_sftp_read(LIBSSH2_SFTP_HANDLE *handle, char *buffer, size_t buffer_maxlen);
    def read(self, buffer):
        self.libssh2.libssh2_sftp_read.argtypes = [ctypes.POINTER(SFTPHandle.SFTPHandleType), ctypes.POINTER(ctypes.c_char), ctypes.c_size_t]
        self.libssh2.libssh2_sftp_read.restype = ctypes.c_ssize_t
        size = self.libssh2.libssh2_sftp_read(self.sftpHandle, buffer, len(buffer))
        return size
    
    #void libssh2_sftp_seek64(LIBSSH2_SFTP_HANDLE *handle,   libssh2_uint64_t offset);
    def seek64(self, offset):
        self.libssh2.libssh2_sftp_seek64.argtypes = [ctypes.POINTER(SFTPHandle.SFTPHandleType), ctypes.c_uint64]
        self.libssh2.libssh2_sftp_seek64.restype = None
        self.libssh2.libssh2_sftp_seek64(self.sftpHandle, offset)
    
    #libssh2_uint64_t libssh2_sftp_tell64(LIBSSH2_SFTP_HANDLE *handle);
    def tell64(self):
        self.libssh2.libssh2_sftp_tell64.argtypes = [ctypes.POINTER(SFTPHandle.SFTPHandleType)]
        self.libssh2.libssh2_sftp_tell64.restype = ctypes.c_uint64
        pos = self.libssh2.libssh2_sftp_tell64(self.sftpHandle)
        return pos
    
    #int libssh2_sftp_fstat_ex(LIBSSH2_SFTP_HANDLE *handle,   LIBSSH2_SFTP_ATTRIBUTES *attrs, int setstat)
    def fstat_ex(self, attrs, setstat):
        self.libssh2.libssh2_sftp_fstat_ex.argtypes = [ctypes.POINTER(SFTPHandle.SFTPHandleType), ctypes.POINTER(SFTPHandle.SFTPAttributes), ctypes.c_int]
        self.libssh2.libssh2_sftp_fstat_ex.restype = ctypes.c_int
        rc = self.libssh2.libssh2_sftp_fstat_ex(self.sftpHandle, attrs, setstat)
        return rc
    
    #define libbssh2_sftp_fstat(handle, attrs) \   libssh2_sftp_fstat_ex((handle), (attrs), 0)
    def fstat(self):
        attrs = SFTPHandle.SFTPAttributes()
        self.fstat_ex(attrs, 0)
        return attrs
    
    #define libssh2_sftp_fsetstat(handle, attrs) \   libssh2_sftp_fstat_ex((handle), (attrs), 1)
    def fsetstat(self, attrs):
        self.fstat_ex(attrs, 1)
    
    #ssize_t libssh2_sftp_write(LIBSSH2_SFTP_HANDLE *handle,   const char *buffer,   size_t count);
    def write(self, buffer):
        self.libssh2.libssh2_sftp_write.argtypes = [ctypes.POINTER(SFTPHandle.SFTPHandleType), ctypes.c_char_p, ctypes.c_size_t]
        self.libssh2.libssh2_sftp_write.restype = ctypes.c_ssize_t
        count = self.libssh2.libssh2_sftp_write(self.sftpHandle, buffer, len(buffer))
        return count
    
    def asFile(self):
        return SftpFile(self)
    

class SftpFile:
    
    def __init__(self, sftpHandle):
        self._sftpHandle = sftpHandle
        username = self._sftpHandle.parent.parent.username
        (ip, port) = self._sftpHandle.parent.parent.socket.getpeername()
        path = self._sftpHandle.path
        self.name = "sftp://{}@{}:{}{}".format(username, ip, port, path)
    
    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            self._sftpHandle.seek64(offset)
        elif whence == os.SEEK_CUR:
            self._sftpHandle.seek64(self._sftpHandle.tell64()+offset)
        elif whence == os.SEEK_END:
            attrs = SFTPHandle.SFTPAttributes()
            self._sftpHandle.fstat(attrs)
            self._sftpHandle.seek64(attrs.filesize+offset)
    
    def tell(self):
        pos = self._sftpHandle.tell64()
        return pos
    
    def read(self, size=-1):
        result = ""
        if size<0:
            buffer = " "*1024
            count = self._sftpHandle.read(buffer)
            while count>0:
                result += buffer[:count]
                buffer = " "*1024
                count = self._sftpHandle.read(buffer)
        elif size>0:
            buffer = " "*min(1024, size-len(result))
            count = self._sftpHandle.read(buffer)
            while count>0:
                result += buffer[:count]
                buffer = " "*min(1024, size-len(result))
                count = self._sftpHandle.read(buffer)
        return result

def to_bytes(string, encoding="utf-8"):
    return bytes(string, encoding)

def to_string(byte):
    return byte.decode()

def connect(username, password, hostname="localhost", port=22):
    ssh = SSH2(username, password, hostname, port)
    return ssh

class SSH2:
    
    def __init__(self,
                username,
                password,
                hostname="localhost",
                port=22):
        self.__ssh = Ssh2()
        self.__session = self.__ssh.session_init()
        self.__socket = socket.create_connection((hostname, port))
        assert self.__socket != None, ConnectionError("Unable to connect to {}:{}".format(hostname, port))
        self.__socket.setblocking(False)
        self.__session.handshake(self.__socket)
        rc = self.__session.userauth_password(to_bytes(username),
                                              to_bytes(password))
        assert rc == 0, AuthError("Unable to authenticate. Please, check your username and password")
        self.__channel = self.__session.channel_open()
        self.__buffer_size = 200
        self.__buffer = ctypes.create_string_buffer(self.__buffer_size)

    def shell(self, terminal_emulator_type="vt100"):
        return Shell(self.__channel, terminal_emulator_type)
        
    def close(self):
        self.__socket.close()
       
class Shell:

    def __init__(self,
                channel,
                terminal_emulator_type="vt100"):
        self.__channel = channel
        self.__terminal_emulator = terminal_emulator_type
        self.__buffer_size = 200
        self.__buffer = ctypes.create_string_buffer(self.__buffer_size)
        rc = self.__channel.request_pty(to_bytes(self.__terminal_emulator))
        rc = self.__channel.shell()

    def read(self,
            delay=0.6):
        time.sleep(delay)
        result = ""
        #pdb.set_trace()
        while True: 
            size = self.__channel.read(self.__buffer)
            if size < 0:
                raise ReadError("Unable to read from the channel")
            if not size == self.__buffer_size:
                break
            result += to_string(self.__buffer.value)
        result += to_string(self.__buffer.value[:size])
        return result

    def write(self,
             buffer,
             append_new_line=True):
        if append_new_line == True:
            buffer = "{}\n".format(buffer)
        sent_bytes = 0
        while True:
            size = self.__channel.write(buffer[sent_bytes:])
            if size < 0:
                raise WriteError("Unable to write to the channel")
            sent_bytes = sent_bytes + size
            if sent_bytes == len(buffer):
                break
        return sent_bytes


