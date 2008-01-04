from signedheaders import add_signed_header, HeaderSignatureCheckingMiddleware
import os

def test_header_signing():
    environ = {'morx' : 'fleem'}
    add_signed_header(environ, 'REMOTE_USER', 'ausername', 'secret')
    assert environ['morx'] == 'fleem'
    assert 'HTTP_REMOTE_USER_SIGNED' in environ
    header = environ['HTTP_REMOTE_USER_SIGNED']
    sendtime, nonce, key, authenticator, value = header.split(" ", 5)
    assert value == 'ausername'
    assert key == 'REMOTE_USER'

    app = lambda environ, start_response: [environ.get('REMOTE_USER', 'no user')]

    fname = os.path.join(os.path.dirname(__file__), 'secret.txt')
    middleware = HeaderSignatureCheckingMiddleware(app, {'topp_secret_filename' : fname})
    assert middleware(environ, None) == ['ausername']

    #now check a bad signature
    badval = " ".join([sendtime, nonce, 'REMOTE_USER', "abadauthenticator", 'ausername'])
    environ['HTTP_REMOTE_USER_SIGNED'] = badval
    assert middleware(environ, None) != ['ausername']

    #try a bogus header
    environ['HTTP_REMOTE_USER_SIGNED'] = "morx"
    assert middleware(environ, None) != ['ausername']
