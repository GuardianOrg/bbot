import ssl


def create_ssl_context_noverify():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_context.options &= ~ssl.OP_NO_SSLv2 & ~ssl.OP_NO_SSLv3
    try:
        ssl_context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass

    legacy_server_connect = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    ssl_context.options |= legacy_server_connect
    return ssl_context


ssl_context_noverify = create_ssl_context_noverify()
