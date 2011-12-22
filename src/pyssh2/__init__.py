import time
import libssh2
import socket
import ctypes

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
        self.libssh2 = ctypes.CDLL("/opt/local/lib/libssh2.dylib")
        self.libssh2.libssh2_init.restype = ctypes.c_int
        rc = self.libssh2.libssh2_init(0)
    
    #LIBSSH2_SESSION * libssh2_session_init_ex(LIBSSH2_ALLOC_FUNC((*myalloc)), LIBSSH2_FREE_FUNC((*myfree)), LIBSSH2_REALLOC_FUNC((*myrealloc)), void *abstract);
    #LIBSSH2_SESSION * libssh2_session_init(void);
    def session_init(self, myalloc=None, myfree=None, myrealloc=None, abstract=None):
        self.libssh2.libssh2_session_init_ex.restype = ctypes.POINTER(Session.SessionType)
        session = self.libssh2.libssh2_session_init_ex(ctypes.c_void_p(myalloc), ctypes.c_void_p(myfree), ctypes.c_void_p(myrealloc), ctypes.c_void_p(abstract))
        return Session(self, session)


class Session:
    
    class SessionType(ctypes.Structure):
        pass
    
    def __init__(self, parent, session):
        self.parent = parent
        self.libssh2 = parent.libssh2
        self.session = session
    
    #int libssh2_channel_free(LIBSSH2_CHANNEL *channel);
    def __del__(self):
        self.libssh2.libssh2_session_free.restype = ctypes.c_int
        rc = self.libssh2.libssh2_session_free(self.session)
    
    #int libssh2_session_disconnect_ex(LIBSSH2_SESSION *session, int reason, const char *description, const char *lang);
    def disconnect(self, description, reason=SSH_DISCONNECT['BY_APPLICATION'], lang=""):
        self.libssh2.libssh2_disconnect_ex.restype = ctypes.c_int
        rc = self.libssh2.session_disconnect_ex(self.session, ctypes.c_int(reason), ctypes.c_char_p(description), ctypes.c_char_p(lang))
        return rc
    
    #int libssh2_session_banner_set(LIBSSH2_SESSION *session, const char *banner);
    def banner_set(self, banner="SSH-2.0-libssh2_1.3.0"):
        self.libssh2.libssh2_banner_set.restype = ctypes.c_int
        rc = self.libssh2.libssh2_banner_set(self.session, ctypes.c_char_p(banner))
        return rc
    
    #void libssh2_trace(LIBSSH2_SESSION *session, int bitmask);
    def trace(self, bitmask):
        self.libssh2.libssh2_trace.restype = None
        self.libssh2.libssh2_trace(self.session, ctypes.c_int(bitmask))
    
    #int libssh2_session_handshake(LIBSSH2_SESSION *session, libssh2_socket_t socket);
    def handshake(self, socket):
        self.libssh2.libssh2_session_handshake.argtypes = [ctypes.POINTER(Session.SessionType), ctypes.c_int]
        self.libssh2.libssh2_session_handshake.restype = ctypes.c_int
        rc = self.libssh2.libssh2_session_handshake(self.session, socket.fileno())
        return rc
    
    #void libssh2_session_set_blocking(LIBSSH2_SESSION *session, int blocking);
    def set_blocking(self, blocking):
        self.libssh2.libssh2_set_blocking.restype = None
        self.libssh2.libssh2_set_blocking(self.session, ctypes.c_int(blocking))
    
    #LIBSSH2_CHANNEL * libssh2_channel_open_ex(LIBSSH2_SESSION *session, const char *channel_type, unsigned int channel_type_len, unsigned int window_size, unsigned int packet_size, const char *message, unsigned int message_len);
    #LIBSSH2_CHANNEL * libssh2_channel_open_session(LIBSSH2_SESSION *session);
    def channel_open(self, channel_type="session", window_size=256*1024, packet_size=32768, message=""):
        self.libssh2.libssh2_channel_open_ex.restype = ctypes.POINTER(Channel.ChannelType)
        channel = self.libssh2.libssh2_channel_open_ex(self.session, ctypes.c_char_p(channel_type), ctypes.c_uint(len(channel_type)), ctypes.c_uint(window_size), ctypes.c_uint(packet_size), ctypes.c_char_p(message), ctypes.c_uint(len(message)))
        return Channel(self, channel)
    
    #LIBSSH2_AGENT *libssh2_agent_init(LIBSSH2_SESSION *session);
    def agent_init(self):
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
        self.libssh2.libssh2_knownhost_init.restype = ctypes.POINTER(KnownHosts.KnownHostsType)
        knownHosts = self.libssh2.libssh2_knownhost_init(self.session)
        return KnownHosts(self, knownHosts)
    
    #char * libssh2_userauth_list(LIBSSH2_SESSION *session, const char *username, unsigned int username_len);
    def userauth_list(self, username):
        self.libssh2.libssh2_userauth_list.restype = ctypes.c_char_p
        result = self.libssh2.libssh2_userauth_list(self.session, ctypes.c_char_p(username), ctypes.c_uint(len(username)))
        return result
    
    #int libssh2_userauth_password_ex(LIBSSH2_SESSION *session,   const char *username,   unsigned int username_len,   const char *password,   unsigned int password_len,   LIBSSH2_PASSWD_CHANGEREQ_FUNC((*passwd_change_cb)));
    #int libssh2_userauth_password(LIBSSH2_SESSION *session,   const char *username,   const char *password);
    def userauth_password(self, username, password, passwd_change_cb=None):
        #self.libssh2.libssh2_userauth_password_ex.argtypes = [POINTER(LibSsh2Session), c_char_p, c_uint, c_char_p, c_uint, c_void_p]
        self.libssh2.libssh2_userauth_password_ex.restype = ctypes.c_int
        rc = self.libssh2.libssh2_userauth_password_ex(self.session, ctypes.c_char_p(username), ctypes.c_uint(len(username)), ctypes.c_char_p(password), ctypes.c_uint(len(password)), ctypes.c_void_p(passwd_change_cb))
        return rc


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
        self.libssh2.libssh2_agent_free.restype = None
        self.libssh2.libssh2_agent_free(self.agent)
    
    #int libssh2_agent_connect(LIBSSH2_AGENT *agent);
    def connect(self):
        self.libssh2.libssh2_agent_connect.restype = ctypes.c_int
        rc = self.libssh2.libssh2_agent_connect(self.agent)
        return rc
    
    #int libssh2_agent_list_identities(LIBSSH2_AGENT *agent);
    def list_identities(self):
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
        self.libssh2.libssh2_agent_disconnect.restype = ctypes.c_int
        rc = self.libssh2.libssh2_agent_disconnect(self.agent)
        return rc


class Channel:
    
    class ChannelType(ctypes.Structure):
        pass
    
    def __init__(self, parent, channel):
        self.parent = parent
        self.session = parent.session
        self.libssh2 = parent.libssh2
        self.libssh2.libssh2_channel_open_ex.restype = ctypes.POINTER(Channel.ChannelType)
        self.channel = channel
    
    #int libssh2_channel_free(LIBSSH2_CHANNEL *channel);
    def __del__(self):
        self.libssh2.libssh2_channel_free.restype = ctypes.c_int
        rc = self.libssh2.libssh2_channel_free(self.channel)
    
    #int libssh2_channel_close(LIBSSH2_CHANNEL *channel);
    def close(self):
        self.libssh2.libssh2_channel_close.restype = ctypes.c_int
        rc = self.libssh2.libssh2_channel_close(self.channel)
        return rc
    
    #int libssh2_channel_process_startup(LIBSSH2_CHANNEL *channel,   const char *request,   unsigned int request_len,   const char *message,   unsigned int message_len);
    #int libssh2_channel_exec(LIBSSH2_CHANNEL *channel, const char *command);
    def execute(self, message, request="exec"):
        self.libssh2.libssh2_channel_process_startup.restype = ctypes.c_int
        rc = self.libssh2.libssh2_channel_process_startup(self.channel, ctypes.c_char_p(request), ctypes.c_uint(len(request)), ctypes.c_char_p(message), ctypes.c_uint(len(message)))
        return rc
    
    #ssize_t libssh2_channel_read_ex(LIBSSH2_CHANNEL *channel, int stream_id, char *buf, size_t buflen);
    #ssize_t libssh2_channel_read(LIBSSH2_CHANNEL *channel, char *buf, size_t buflen);
    def read(self, buf, stream_id=0):
        self.libssh2.libssh2_channel_read_ex.restype = ctypes.c_ssize_t
        size = self.libssh2.libssh2_channel_read_ex(self.channel, ctypes.c_int(stream_id), ctypes.c_char_p(buf), ctypes.c_size_t(len(buf)))
        return size
    
    #ssize_t libssh2_channel_read_stderr(LIBSSH2_CHANNEL *channel, char *buf, size_t buflen);
    def read_stderr(self, buf):
        size = self.read(buf, stream_id=1)
        return size
