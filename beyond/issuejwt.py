from configparser import ConfigParser
from hashlib import sha256
from functools import lru_cache
from os import environ
from traceback import format_exc
from urllib.parse import urlencode
from uuid import uuid4 as uuid
from time import time
from time import perf_counter_ns as perf_time
import json

from boto3.session import Session
from botocore.session import Session as BotocoreSession
from botocore.auth import S3SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from jose import jwt
from urllib3.connectionpool import HTTPSConnectionPool


parser = ConfigParser()
parser.read(environ["LAMBDA_TASK_ROOT"] + "/config.ini")
config = parser["default"]

SYMMETRIC_KEY = "blah"
COOKIE_MAX_AGE = 86400 * 365

SESSION = BotocoreSession()
load_credentials = SESSION.get_component("credential_provider").load_credentials
resource = Session(botocore_session=SESSION).resource


class OIDC:
    def __init__(self, host):
        self.conn = HTTPSConnectionPool(host)

    def request_json(self, method, url, *args, headers=None, **kwargs):
        if headers is None:
            headers = dict()

        headers["accept"] = "application/json"
        response = self.conn.request(method, url, *args, headers=headers, **kwargs)

        if response.status != 200:
            raise RuntimeError("Request failed", method, url, response.data)

        return json.loads(response.data)

    def warmup(self):
        # TODO: implement
        pass

def ttl_cache(fn):
    cache = dict()
    ordered = deque()

    def expire():
        at = time()
        while len(ordered):
            entry = ordered[0]
            if entry["exp"] > at:
                break

            ordered.popleft()
            del cache[key]

    def wrapped(arg):
        i
        insort(

        fn(arg)




class TokenStorage:
    def __init__(self, table_name):
        self.table = resource("dynamodb").Table(table_name)

    def _transform_pk(self, token):
        return sha256(token.encode()).digest()

    def put(self, token, values):
        # TODO: use HKDF to derive an AES key from the original token, and encrypt the
        # data fields
        self.table.put_item(Item=dict(hashed_token=self._transform_pk(token), **values))

    # TODO: convert to ttl cache?
    @lru_cache(maxsize=65536)
    def get(self, token):
        resp = self.table.get_item(Key=dict(hashed_token=self._transform_pk(token)))
        try:
            item = resp["Item"]
        except KeyError:
            return None

        item["exp"] = max(int(time()) + 61, item["exp"])

        return item


tokens = TokenStorage(config["tokens_table"])
oidc = OIDC(config["oidc_host"])
oidc.warmup()


JWKS = oidc.request_json("GET", config["jwks_uri"])


def _headers_wrap(d):
    return {k.lower(): [dict(key=k, value=v)] for (k, v) in d.items()}


def _headers_unwrap(d):
    return {k.lower(): v[0]["value"] for (k, v) in d.items()}


def _make_response(status, body, headers=None, **kwargs):
    if headers is None:
        headers = dict()

    if isinstance(body, str):
        headers.setdefault("content-type", "text/plain")
    else:
        body = json.dumps(body)
        headers["content-type"] = "application/json"

    return dict(
        statusCode=str(status),
        headers=headers,
        body=body,
        **kwargs,
    )


def _oidc_redirect(request):
    redirect_uri = _get_redirect_uri(request)
    if not (auth_cookie := _get_auth_cookie(request)):
        auth_cookie = uuid()

    cookies = [f"a={auth_cookie}; Max-Age={COOKIE_MAX_AGE}; Secure; HttpOnly"]

    host = config["oidc_host"]
    client_id = config["client_id"]
    # XXX: fix use of `state` parameter
    return _make_response(
        302,
        "",
        dict(
            location=f"https://{host}/oauth2/default/v1/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope=openid%20offline_access&state={uuid()}"
        ),
        cookies=cookies,
    )


def _get_cookies(request):
    try:
        return dict(c.split("=", 1) for c in request["cookies"])
    except KeyError:
        pass

    return dict()


def _get_redirect_uri(request):
    headers = request["headers"]
    host = headers["host"]
    return f"https://{host}/auth"


def _get_auth_cookie(request):
    cookies = _get_cookies(request)
    return cookies.get("a")


def _whoami(request):
    auth_cookie = _get_auth_cookie(request)
    if auth_cookie is None:
        return None

    info = tokens.get(auth_cookie)
    if info is None:
        return None

    return dict(
        sub=info["sub"],
        exp=int(info["exp"]),
        iat=int(info["iat"]),
    )


def _refresh(request):
    caller = _whoami(request)
    if caller is None:
        return None

    if time() < caller["exp"]:
        return caller

    redirect_uri = _get_redirect_uri(request)

    auth_cookie = _get_auth_cookie(request)
    token = tokens.get(auth_cookie)

    resp = oidc.request_json(
        "POST",
        config["token_uri"],
        headers={
            "content-type": "application/x-www-form-urlencoded",
        },
        body=urlencode(
            dict(
                grant_type="refresh_token",
                redirect_uri=redirect_uri,
                client_id=config["client_id"],
                client_secret=config["client_secret"],
                refresh_token=token["refresh_token"],
            )
        ),
    )

    # Don't allow the refresh token to change
    resp["refresh_token"] = token["refresh_token"]
    return _store_idp_response(auth_cookie, resp)


def _store_idp_response(auth_cookie, resp):
    access_token = resp["access_token"]
    decoded = jwt.decode(
        access_token,
        JWKS,
        options=dict(verify_aud=False, verify_iss=False, verify_sub=False),
    )

    info = dict(
        sub=decoded["sub"],
        iat=decoded["iat"],
        exp=decoded["exp"],
        refresh_token=resp["refresh_token"],
    )
    tokens.put(auth_cookie, info)
    del info["refresh_token"]
    return info


def store_token(request):
    redirect_uri = _get_redirect_uri(request)
    resp = oidc.request_json(
        "POST",
        config["token_uri"],
        headers={
            "content-type": "application/x-www-form-urlencoded",
        },
        body=urlencode(
            dict(
                grant_type="authorization_code",
                redirect_uri=redirect_uri,
                client_id=config["client_id"],
                client_secret=config["client_secret"],
                code=request["queryStringParameters"]["code"],
            )
        ),
    )

    auth_cookie = _get_auth_cookie(request)
    _store_idp_response(auth_cookie, resp)

    return _make_response(
        302,
        "",
        dict(location="/whoami"),
    )


region = "us-west-2"


def whoami(request):
    return _make_response(200, _whoami(request))


def asset(request):
    auth_info = _refresh(request)

    if auth_info is None:
        return _oidc_redirect(request)

    user = auth_info["sub"]
    path = request["rawPath"]

    bucket = config["bucket"]
    region = "us-west-2"
    credentials = load_credentials()
    auth = S3SigV4QueryAuth(credentials, "s3", region)
    url = f"https://{bucket}.s3.{region}.amazonaws.com{path}?user={user}"
    synthetic_request = AWSRequest(method="GET", url=url, headers=dict())
    auth.add_auth(synthetic_request)
    return _make_response(302, "", headers=dict(location=synthetic_request.url))


ROUTES = {
    "/whoami": whoami,
    "/auth": store_token,
}


def timer_middleware(fn):
    def wrapper(*args, **kwargs):
        start = perf_time()
        result = fn(*args, **kwargs)
        elapsed = perf_time() - start
        result["headers"]["nanos"] = elapsed
        return result

    return wrapper


@timer_middleware
def _handler(request):
    route = ROUTES.get(request["rawPath"])
    if route is not None:
        return route(request)

    return asset(request)


def lambda_handler(event, context):
    try:
        return _handler(event)
    except Exception:
        traceback = format_exc()

    return _make_response(500, traceback, headers={"content-type": "text/plain"})
