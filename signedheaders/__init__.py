import sha
import hmac
import time
import os
import re

from logging import warning

def _add_warning(environ, warning):
    #quote warning
    warning = warning.replace("\\", "\\\\")
    warning = warning.replace('\"', '\\"')
    header = '299 HeaderSignatureCheckingMiddleware "%s"' % warning
    if 'HTTP_WARNING' in environ:
        environ['HTTP_WARNING'] += ',' + header
    else:
        environ['HTTP_WARNING'] = header

def check_environ_signatures(environ, secret):
    """
    This function searches the environment for HTTP headers which end
    with _SIGNED.  If those headers are not signed with the secret (or
    the signature is bad), they are removed.  If they are signed, the
    signature is stripped, leaving the bare value.
    """
    for k, v in environ.items():
        #if it's signed
        if k.endswith("_SIGNED"):
            del environ[k]
            try:
                decoded = v.split(" ", 5)
                sendtime, nonce, key, authenticator, value = decoded
                sendtime_int = int(sendtime)
            except ValueError:
                _add_warning(environ, "bogus header")
                warning("bogus header in %s: %s" % (k, v))
                continue #bad header

            if time.time() - sendtime_int > 60:
                #the message has expired
                _add_warning(environ, "expired header")
                warning("expired header in %s: %s" % (k, v))
                continue

            message = "\0".join([sendtime, nonce, key, value])
            hash = hmac.new(secret, message, sha).hexdigest()
            if hash != authenticator:
                #the hash is bad
                _add_warning(environ, "bad authenticator")
                warning("bad authenticator in %s: %s" % (k, v))
                continue
            environ[key] = value


class HeaderSignatureCheckingMiddleware:
    """
    This middleware checks signatures using check_environ_signatures.
    """
    def __init__(self, app, secret):
        self.app = app
        self.secret = secret

    def __call__(self, environ, start_response):
        new_environ = dict(environ)
        check_environ_signatures(new_environ, self.secret)
        return self.app(new_environ, start_response)


def add_signed_header(environ, key, value, secret):
    """This adds a new signed HTTP header to a WSGI environment.
    The header is signed with a secret."""
    assert " " not in key
    header = "HTTP_" + key.replace("-", "_").upper() + "_SIGNED"
    assert header not in environ
    sendtime = str(int(time.time()))
    nonce = os.urandom(18).encode("base64").strip()
    message = "\0".join ([sendtime, nonce, key, value])
    authenticator = hmac.new(secret, message, sha).hexdigest()
    signed_value = " ".join([sendtime, nonce, key, authenticator, value])
    environ[header] = signed_value


class SignedHeaderAdder:
    """A helper class for adding signed headers to WSGI environments.
    Saves the secret so it does not need to be passed around."""
    def __init__(self, environ, secret):
        self.secret = secret
        self.environ = environ

    def __call__(self, header, value):
        add_signed_header(self.environ, header, value, self.secret)
