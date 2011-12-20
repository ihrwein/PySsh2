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

LIBSSH2_ERROR = {'NONE'                    :  0,
                 'SOCKET_NONE'             : -1,
                 'BANNER_RECV'             : -2,
                 'BANNER_SEND'             : -3,
                 'INVALID_MAC'             : -4,
                 'KEX_FAILURE'             : -5,
                 'ALLOC'                   : -6,
                 'SOCKET_SEND'             : -7,
                 'KEY_EXCHANGE_FAILURE'    : -8,
                 'TIMEOUT'                 : -9,
                 'HOSTKEY_INIT'            : -10,
                 'HOSTKEY_SIGN'            : -11,
                 'DECRYPT'                 : -12,
                 'SOCKET_DISCONNECT'       : -13,
                 'PROTO'                   : -14,
                 'PASSWORD_EXPIRED'        : -15,
                 'FILE'                    : -16,
                 'METHOD_NONE'             : -17,
                 'AUTHENTICATION_FAILED'   : -18,
                 'PUBLICKEY_UNRECOGNIZED'  : -18, #=AUTHENTICATION_FAILED
                 'PUBLICKEY_UNVERIFIED'    : -19,
                 'CHANNEL_OUTOFORDER'      : -20,
                 'CHANNEL_FAILURE'         : -21,
                 'CHANNEL_REQUEST_DENIED'  : -22,
                 'CHANNEL_UNKNOWN'         : -23,
                 'CHANNEL_WINDOW_EXCEEDED' : -24,
                 'CHANNEL_PACKET_EXCEEDED' : -25,
                 'CHANNEL_CLOSED'          : -26,
                 'CHANNEL_EOF_SENT'        : -27,
                 'SCP_PROTOCOL'            : -28,
                 'ZLIB'                    : -29,
                 'SOCKET_TIMEOUT'          : -30,
                 'SFTP_PROTOCOL'           : -31,
                 'REQUEST_DENIED'          : -32,
                 'METHOD_NOT_SUPPORTED'    : -33,
                 'INVAL'                   : -34,
                 'INVALID_POLL_TYPE'       : -35,
                 'PUBLICKEY_PROTOCOL'      : -36,
                 'EAGAIN'                  : -37,
                 'BUFFER_TOO_SMALL'        : -38,
                 'BAD_USE'                 : -39,
                 'COMPRESS'                : -40,
                 'OUT_OF_BOUNDARY'         : -41,
                 'AGENT_PROTOCOL'          : -42,
                 'SOCKET_RECV'             : -43,
                 'ENCRYPT'                 : -44,
                 'BAD_SOCKET'              : -45}


class LibSSH2:
    
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
    
    #int libssh2_session_banner_set(LIBSSH2_SESSION *session, const char *banner);
    def banner_set(self, banner="SSH-2.0-libssh2_1.3.0"):
        self.libssh2.libssh2_banner_set.restype = ctypes.c_int
        rc = self.libssh2.libssh2_banner_set(self.session, ctypes.c_char_p(banner))
    
    #void libssh2_trace(LIBSSH2_SESSION *session, int bitmask);
    def trace(self, bitmask):
        self.libssh2.libssh2_trace.restype = None
        self.libssh2.libssh2_trace(self.session, ctypes.c_int(bitmask))
    
    #int libssh2_session_startup(LIBSSH2_SESSION *session, int socket);
    def session_startup(self, socket):
        self.libssh2.libssh2_session_startup.restype = ctypes.c_int
        rc = self.libssh2.libssh2_session_startup(self.session, ctypes.c_int(socket))
    
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
        self.libssh2.libssh2_userauth_password_ex(self.session, ctypes.c_char_p(username), ctypes.c_uint(len(username)), ctypes.c_char_p(password), ctypes.c_uint(len(password)), ctypes.c_void_p(passwd_change_cb))


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
    
    def __del__(self):
        #void libssh2_agent_free(LIBSSH2_AGENT *agent);
        self.libssh2.libssh2_agent_free.restype = None
        self.libssh2.libssh2_agent_free(self.agent)
    
    #int libssh2_agent_connect(LIBSSH2_AGENT *agent);
    def connect(self):
        self.libssh2.libssh2_agent_connect.restype = ctypes.c_int
        rc = self.libssh2.libssh2_agent_connect(self.agent)
    
    #int libssh2_agent_list_identities(LIBSSH2_AGENT *agent);
    def list_identities(self):
        self.libssh2.libssh2_agent_list_identities.restype = ctypes.c_int
        self.libssh2.libssh2_agent_list_identities(self.agent)
    
    #int libssh2_agent_get_identity(LIBSSH2_AGENT *agent,   struct libssh2_agent_publickey **store,   struct libssh2_agent_publickey *prev);
    def get_identity(self, store, prev):
        self.libssh2.libssh2_agent_get_identity.restype = ctypes.c_int
        self.libssh2.libssh2_agent_get_identity.argtypes = [ctypes.POINTER(Agent.AgentType), ctypes.POINTER(ctypes.POINTER(Agent.AgentPublicKey)), ctypes.POINTER(Agent.AgentPublicKey)]
        rc = self.libssh2.libssh2_agent_get_identity(self.agent, ctypes.byref(store), prev)
    
    #int libssh2_agent_userauth(LIBSSH2_AGENT *agent,   const char *username,   struct libssh2_agent_publickey *identity);
    def userauth(self, username, identity):
        self.libssh2.libssh2_agent_userauth.restype = ctypes.c_int
        rc = self.libssh2.libssh2_agent_userauth(self.agent, ctypes.c_char_p(username), ctypes.POINTER(Agent.AgentPublicKey)(identity))
    
    #int libssh2_agent_disconnect(LIBSSH2_AGENT *agent);
    def disconnect(self):
        self.libssh2.libssh2_agent_disconnect.restype = ctypes.c_int
        rc = self.libssh2.libssh2_agent_disconnect(self.agent)


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
    
    #int libssh2_channel_process_startup(LIBSSH2_CHANNEL *channel,   const char *request,   unsigned int request_len,   const char *message,   unsigned int message_len);
    #int libssh2_channel_exec(LIBSSH2_CHANNEL *channel, const char *command);
    def execute(self, message, request="exec"):
        self.libssh2.libssh2_channel_process_startup.restype = ctypes.c_int
        rc = self.libssh2.libssh2_channel_process_startup(self.channel, ctypes.c_char_p(request), ctypes.c_uint(len(request)), ctypes.c_char_p(message), ctypes.c_uint(len(message)))
    
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
