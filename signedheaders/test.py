from signedheaders import add_signed_header, HeaderSignatureCheckingMiddleware


def test_header_signing():
    environ = {'morx' : 'fleem'}
    add_signed_header(environ, 'X-Openplans-User', 'ausername', 'secret')
    assert environ['morx'] == 'fleem'
    assert 'HTTP_X_OPENPLANS_USER' in environ
    header = environ['HTTP_X_OPENPLANS_USER']
    value, sendtime, nonce, authenticator = header.decode("base64").split("\0")
    assert value == 'ausername'
    
    app = lambda environ, start_response: [environ.get('HTTP_X_OPENPLANS_USER', 'no user')]
    middleware = HeaderSignatureCheckingMiddleware(app, 'secret')
    assert middleware(environ, None) == ['ausername']

    #now check a bad signature
    badval = "\0".join(['ausername', sendtime, nonce, "a bad authenticator"])
    environ['HTTP_X_OPENPLANS_USER'] = badval.encode("base64").strip()
    assert middleware(environ, None) != ['ausername']
