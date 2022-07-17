from configparser import ConfigParser
from os import environ
from urllib.parse import parse_qs
from urllib.parse import urlencode
from traceback import format_exc
import json

from jose import jwt
from urllib3.connectionpool import HTTPSConnectionPool

parser = ConfigParser()
parser.read(environ["LAMBDA_TASK_ROOT"] + "/config.ini")
config = parser["default"]


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


oidc = OIDC(config["oidc_host"])
oidc.warmup()


JWKS = oidc.request_json("GET", config["jwks_uri"])


def _headers_wrap(d):
    return {k.lower(): [dict(key=k, value=v)] for (k, v) in d.items()}


def _headers_unwrap(d):
    return {k.lower(): v[0]["value"] for (k, v) in d.items()}


STATUS_DESCRIPTIONS = {
    200: "OK",
    400: "Bad Request",
    500: "Internal Server Error",
}


def _make_response(status, body, headers=None):
    description = STATUS_DESCRIPTIONS[status]
    if headers is None:
        headers = dict()

    if not isinstance(body, str):
        body = json.dumps(body)
        headers["content-type"] = "application/json"

    return dict(
        status=str(status),
        statusDescription=description,
        headers=_headers_wrap(headers),
        body=body,
    )


def _handler(request):
    query_string = parse_qs(request["querystring"])

    headers = _headers_unwrap(request["headers"])
    host = headers["host"]
    redirect_uri = f"https://{host}/auth"

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
                code=query_string["code"][0],
            )
        ),
    )

    return _make_response(200, resp)

    access_token = resp["access_token"]
    decoded = jwt.decode(
        access_token,
        JWKS,
        options=dict(verify_aud=False, verify_iss=False, verify_sub=False),
    )

    data = jwt.encode(
        dict(sub=decoded["sub"], iat=decoded["iat"], exp=decoded["exp"]),
        key=config["hmac_secret"],
    )

    return _make_response(200, data)


def lambda_handler(event, context):
    try:
        request = event["Records"][0]["cf"]["request"]
        return _handler(request)
    except Exception:
        traceback = format_exc()

    return _make_response(500, traceback, headers={"content-type": "text/plain"})
