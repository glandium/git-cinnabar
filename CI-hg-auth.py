import base64
from mercurial.hgweb import common


def perform_authentication(hgweb, req, op):
    if req.env.get('REQUEST_METHOD') == 'POST':
        auth = req.env.get('HTTP_AUTHORIZATION')
        if not auth:
            raise common.ErrorResponse(common.HTTP_UNAUTHORIZED, 'who',
                    [('WWW-Authenticate', 'Basic Realm="mercurial"')])
        user, password = base64.b64decode(auth.split()[1]).split(':', 1)
        req.env['REMOTE_USER'] = user


def extsetup():
    common.permhooks.insert(0, perform_authentication)
