from ctypes import *
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


class LibSsh2Session(Structure):
    pass

class LibSsh2Channel(Structure):
    pass

class LibSsh2Agent(Structure):
    pass

class LibSsh2AgentPublicKey(Structure):
    pass


class LibSsh2:
    
    def __init__(self):

        #========== LIBSSH2
        self.libssh2 = CDLL("/opt/local/lib/libssh2.dylib")
        #int libssh2_init(int flags);
        self.init = self.setup('init', [c_int], c_int)
        #void libssh2_exit(void);
        self.exit = self.setup('exit', [], None)
        
        #========== LIBSSH2_SESSION
        #LIBSSH2_SESSION * libssh2_session_init_ex(LIBSSH2_ALLOC_FUNC((*myalloc)), LIBSSH2_FREE_FUNC((*myfree)), LIBSSH2_REALLOC_FUNC((*myrealloc)), void *abstract);
        self.session_init_ex = self.setup('session_init_ex', [c_void_p, c_void_p, c_void_p, c_void_p], POINTER(LibSsh2Session))
        #LIBSSH2_SESSION * libssh2_session_init(void);
        self.session_init = lambda : self.session_init_ex(None, None, None, None)
        #int libssh2_session_disconnect_ex(LIBSSH2_SESSION *session, int reason, const char *description, const char *lang);
        self.session_disconnect_ex = self.setup('session_disconnect_ex', [POINTER(LibSsh2Session), c_int, c_char_p, c_char_p], c_int)
        #int libssh2_session_disconnect(LIBSSH2_SESSION *session, const char *description);
        self.session_disconnect = lambda session, description: self.session_disconnect_ex(session, SSH_DISCONNECT['BY_APPLICATION'], description, "")
        #int libssh2_session_free(LIBSSH2_SESSION *session);
        self.session_free = self.setup('session_free', [POINTER(LibSsh2Session)], c_int)
        #int libssh2_session_banner_set(LIBSSH2_SESSION *session, const char *banner);
        self.session_banner_set = self.setup('banner_set', [POINTER(LibSsh2Session), c_char_p], c_int)
        #void libssh2_trace(LIBSSH2_SESSION *session, int bitmask);
        self.trace_set = self.setup('trace', [POINTER(LibSsh2Session), c_int], None)
        #int libssh2_session_startup(LIBSSH2_SESSION *session, int socket);
        self.session_startup = self.setup('session_startup', [POINTER(LibSsh2Session), c_int], c_int)
        #void libssh2_session_set_blocking(LIBSSH2_SESSION *session, int blocking);
        self.session_set_blocking = self.setup('session_set_blocking', [POINTER(LibSsh2Session), c_int], None)
        
        #========== LIBSSH2_USERAUTH
        #char * libssh2_userauth_list(LIBSSH2_SESSION *session, const char *username, unsigned int username_len);
        self.userauth_list = self.setup('userauth_list', [POINTER(LibSsh2Session), c_char_p, c_uint], c_char_p)
        #int libssh2_userauth_password_ex(LIBSSH2_SESSION *session,   const char *username,   unsigned int username_len,   const char *password,   unsigned int password_len,   LIBSSH2_PASSWD_CHANGEREQ_FUNC((*passwd_change_cb)));
        self.userauth_password_ex = self.setup('userauth_password_ex', [POINTER(LibSsh2Session), c_char_p, c_uint, c_char_p, c_uint, c_void_p], c_int)
        #int libssh2_userauth_password(LIBSSH2_SESSION *session,   const char *username,   const char *password);
        self.userauth_password = lambda session, username, password: self.userauth_password_ex(session, username, len(username), password, len(password), None)
        
        #========== LIBSSH2_CHANNEL
        #LIBSSH2_CHANNEL * libssh2_channel_open_ex(LIBSSH2_SESSION *session, const char *channel_type, unsigned int channel_type_len, unsigned int window_size, unsigned int packet_size, const char *message, unsigned int message_len);
        self.channel_open_ex = self.setup('channel_open_ex', [POINTER(LibSsh2Session), c_char_p, c_uint, c_uint, c_uint, c_char_p, c_uint], POINTER(LibSsh2Channel))
        #LIBSSH2_CHANNEL * libssh2_channel_open_session(session);
        self.channel_open_session = lambda session: self.channel_open_ex(session, 'session', len('session'), 256*1024, 32768, "", len(""))
        #int libssh2_channel_close(LIBSSH2_CHANNEL *channel);
        self.channel_close = self.setup('channel_close', [POINTER(LibSsh2Channel)], c_int)
        #int libssh2_channel_free(LIBSSH2_CHANNEL *channel);
        self.channel_free = self.setup('channel_free', [POINTER(LibSsh2Channel)], c_int)
        #int libssh2_channel_process_startup(LIBSSH2_CHANNEL *channel,   const char *request,   unsigned int request_len,   const char *message,   unsigned int message_len);
        self.channel_process_startup = self.setup('channel_process_startup', [POINTER(LibSsh2Channel), c_char_p, c_uint, c_char_p, c_uint], c_int)
        #int libssh2_channel_exec(LIBSSH2_CHANNEL *channel, const char *command);
        self.channel_exec = lambda channel, command: self.channel_process_startup(channel, "exec", len("exec"), command, len(command))
        #ssize_t libssh2_channel_read_ex(LIBSSH2_CHANNEL *channel, int stream_id, char *buf, size_t buflen);
        self.channel_read_ex = self.setup('channel_read_ex', [POINTER(LibSsh2Channel), c_int, c_char_p, c_size_t], c_ssize_t)
        #ssize_t libssh2_channel_read(LIBSSH2_CHANNEL *channel, char *buf, size_t buflen);
        self.channel_read = lambda channel, buf: self.channel_read_ex(channel, 0, buf, len(buf))
        #ssize_t libssh2_channel_read_stderr(LIBSSH2_CHANNEL *channel, char *buf, size_t buflen);
        self.channel_read_stderr = lambda channel, buf: self.channel_read_ex(channel, 1, buf, len(buf))
        
        #========== LIBSSH2_AGENT
        #LIBSSH2_AGENT *libssh2_agent_init(LIBSSH2_SESSION *session);
        self.agent_init = self.setup('agent_init', [POINTER(LibSsh2Session)], POINTER(LibSsh2Agent))
        #int libssh2_agent_connect(LIBSSH2_AGENT *agent);
        self.agent_connect = self.setup('agent_connect', [POINTER(LibSsh2Agent)], c_int)
        #int libssh2_agent_list_identities(LIBSSH2_AGENT *agent);
        self.agent_list_identities = self.setup('agent_list_identities', [POINTER(LibSsh2Agent)], c_int)
        #int libssh2_agent_get_identity(LIBSSH2_AGENT *agent,   struct libssh2_agent_publickey **store,   struct libssh2_agent_publickey *prev);
        self.agent_get_identity = self.setup('agent_get_identity', [POINTER(LibSsh2Agent), POINTER(POINTER(LibSsh2AgentPublicKey)), POINTER(LibSsh2AgentPublicKey)], c_int)
        #int libssh2_agent_userauth(LIBSSH2_AGENT *agent,   const char *username,   struct libssh2_agent_publickey *identity);
        self.agent_userauth = self.setup('agent_userauth', [POINTER(LibSsh2Agent), c_char_p, POINTER(LibSsh2AgentPublicKey)], c_int)
        #int libssh2_agent_disconnect(LIBSSH2_AGENT *agent);
        self.agent_disconnect = self.setup('agent_disconnect', [POINTER(LibSsh2Agent)], c_int)
        #void libssh2_agent_free(LIBSSH2_AGENT *agent);
        self.agent_free = self.setup('agent_free', [POINTER(LibSsh2Agent)], None)
    
    def __del__(self):
        self.exit()
    
    def setup(self, function, argtypes, restype):
        f = getattr(self.libssh2, "libssh2_"+function)
        f.argtypes = argtypes
        f.restype = restype
        return f
