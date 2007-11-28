import sha
import hmac
import time
import os


class HeaderSignatureCheckingMiddleware:
    """
    This middleware searches the environment for headers which
    begin with HTTP_X_OPENPLANS.  If those headers are not
    signed with the secret (or the signature is bad), they
    are removed.  If they are signed, the signature
    is stripped, leaving the bare value.
    """
    def __init__(self, app, secret):
        self.app = app
        self.secret = secret

    def __call__(self, environ, start_response):
        new_environ = dict()
        for k, v in environ.items():
            if k.startswith("HTTP_X_OPENPLANS"):

                decoded = v.decode("base64").split("\0")
                value, sendtime, nonce, authenticator = decoded
                sendtime = int(sendtime)
                if time.time() - sendtime > 60:
                    #the message has expired
                    continue

                message = "%s\0%s\0%s" % (value, sendtime, nonce)
                hash = hmac.new(self.secret, message, sha).hexdigest()
                if hash != authenticator:
                    #the hash is bad
                    continue

                new_environ[k] = value
            else:
                new_environ[k] = v

        return self.app(new_environ, start_response)


def add_signed_header(environ, header, value, secret):
    """This adds a new signed HTTP header to a WSGI environment.
    The header is signed with a secret."""
    munged_header = "HTTP_" + header.replace("-", "_").upper()
    sendtime = str(int(time.time()))
    nonce = os.urandom(16)
    authenticator = hmac.new(secret, "%s\0%s\0%s" % (value, sendtime, nonce), sha).hexdigest()
    signed_value = "\0".join([value, sendtime, nonce, authenticator])
    environ[munged_header] = signed_value.encode("base64").strip()


class SignedHeaderAdder:
    """A helper class for adding signed headers to WSGI environments.
    Saves the secret so it does not need to be passed around."""
    def __init__(self, environ, secret):
        self.secret = secret
        self.environ = environ

    def __call__(self, header, value):
        add_signed_header(self.environ, header, value, self.secret)
