#!/usr/bin/env python3
"""
Minimal HTTP server implementing TheAuthenticator protocol.

Usage::
    ./grpc_authenticator.py [<port>]
"""

import argparse
import base64
from concurrent import futures
import grpc
from hashlib import sha256, sha1
import hmac
import logging
import re

from authenticator.v1 import authenticator_pb2_grpc as auth_pb2_grpc
from authenticator.v1 import authenticator_pb2 as auth_pb2

# A fixed set of recognised keys, secrets and uids.
# Feel the security.
keys = {
    "0555b35654ad1656d804": {
        "secret": "h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==",
        "uid": "testid",
    },
    b"MAGICWORDS".hex(): {
        "secret": b"SQUEAMISHOSSIFRAGE".hex(),
        "uid": "testid",
    },
    "deadbeef": {
        "secret": "0ddc0ffeebadf00d",
        "uid": "testid2",
    },
}


# Regex to match fields out of the v2 Authorize header.
re_sig_v2 = re.compile(
    r"""
    AWS\s
    (?P<accesskey>[a-z0-9]+):
    (?P<sig>[^\s]+)
    $""",
    re.VERBOSE | re.IGNORECASE,
)

# Regex to match fields out of the v4 Authorize header. Compile this once.
re_sig_v4 = re.compile(
    r"""^
        AWS4-HMAC-SHA256\s
        Credential=(?P<accesskey>[0-9a-f]+)
        /(?P<date>\d+)
        /(?P<region>[0-9a-z-]+)
        /(?P<service>[0-9a-z-]+)
        /aws4_request
        (?:,\s*SignedHeaders=(?P<signhdr>[a-z0-9-;]+))?
        ,\s*Signature=(?P<sig>[0-9a-f]+)
        $""",
    re.VERBOSE | re.IGNORECASE,
)


class SignatureException(Exception):
    code = 401
    message = ""

    def __init__(self, code, message):
        super().__init__()
        self.code = code
        self.message = message

    def __str__(self):
        return "{} {}".format(self.code, self.message)


def reqmethod_to_str(method: auth_pb2.RequestMethod):
    if method == auth_pb2.RequestMethod.REQUEST_METHOD_GET:
        return "GET"
    elif method == auth_pb2.RequestMethod.REQUEST_METHOD_PUT:
        return "PUT"
    elif method == auth_pb2.RequestMethod.REQUEST_METHOD_DELETE:
        return "DELETE"
    elif method == auth_pb2.RequestMethod.REQUEST_METHOD_POST:
        return "POST"
    elif method == auth_pb2.RequestMethod.REQUEST_METHOD_HEAD:
        return "HEAD"
    else:
        return "UNKNOWN"


def aws_sig(req: auth_pb2.AuthRequest):
    logging.info("new request")
    anonymous: bool = False

    if req.user_type == auth_pb2.AuthUserType.AUTH_USER_TYPE_ANONYMOUS:
        logging.debug("anonymous request")
        anonymous = True
    else:
        logging.debug(f"authorization_header: {req.authorization_header}")
        if req.authorization_token_header != "":
            logging.debug(
                f"authorization_token_header: {req.authorization_token_header}"
            )
        logging.debug(f"access_key_id: {req.access_key_id}")
        logging.debug(f"string_to_sign: {req.string_to_sign}")

    if req.HasField("param"):
        logging.debug(
            f"param: method={reqmethod_to_str(req.param.method)}, "
            + f"bucket_name={req.param.bucket_name}, "
            + f"object_key_name={req.param.object_key_name}, "
            + f"request_path={req.param.http_request_path}"
        )
        if req.param.http_headers:
            for k, v in req.param.http_headers.items():
                logging.debug(f"param.http_headers: {k}={v}")
        if req.param.http_query_parameters:
            for k, v in req.param.http_query_parameters.items():
                logging.debug(f"param.query_params: {k}={v}")

    if anonymous:
        return "ANONYMOUS"
    else:
        auth = req.authorization_header
        if auth.startswith("AWS "):
            return aws_sig_v2(req)
        else:
            return aws_sig_v4(req)


def aws_sig_v2(req: auth_pb2.AuthRequest):
    """
    Calculate an AWS S3 v2 signature, given the POST object sent by the
    Handoff engine.

    Apart from the signature calculation itself, operates exactly as
    aws_sig_v4. The v2 signature is much simpler than v4 and uses HMAC-SHA1
    instead of HMAC-SHA256.
    """
    auth = req.authorization_header

    m = re_sig_v2.search(auth)
    if not m:
        raise SignatureException(400, "V2_AUTHORIZATION_HEADER_MALFORMED")

    hdr_access_key = m.group("accesskey").encode("UTF-8")
    hdrsig = m.group("sig")

    # Extract the secret key and userid from our super-secure dict.
    access_key = req.access_key_id
    if not access_key in keys:
        raise SignatureException(401, "ACCESS_KEY_NOT_FOUND")
    lookup = keys[access_key]
    secret_key = lookup["secret"].encode("UTF-8")
    uid = lookup["uid"]
    access_key = access_key.encode("UTF-8")

    # Cross check the access key field with the Credential in the
    # Authorization header.
    if hdr_access_key != access_key:
        raise SignatureException(400, "ACCESS_KEY_MISMATCH")

    ## Implement the signature scheme:
    ##   https://docs.aws.amazon.com/AmazonS3/latest/userguide/RESTAuthentication.html

    # This is the StringToSign in step 1. It is generated by RGW.
    string_to_sign = req.string_to_sign

    # No fancy signing key derivation here.
    sigbytes = hmac.new(secret_key, string_to_sign.encode("utf-8"), sha1).digest()
    signature = base64.b64encode(sigbytes).decode("UTF-8")

    if signature == hdrsig:
        logging.info("SIGNATURE MATCH (uid={})".format(uid))
    else:
        logging.warning("SIGNATURE FAIL")
        raise SignatureException(400, "SIGNATURE_NOT_VERIFIED")

    return uid


def aws_sig_v4(req: auth_pb2.AuthRequest):
    """
    Calculate an AWS S3 v4 signature, given the POST object send by the
    Handoff engine.

    Called with the JSON document passed to /verify:

    {
      "accessKeyId": ...,   // The access key.
      "authorization": ..., // The Authorization header of the request.
      "stringToSign": ...,  // The 'String to Sign' filled by RGW.
    }

    stringToSign is a formed by RGW as a canonicalisation of the original S3
    request. The formulation is tricky and I'm glad it's done for us.

    authorization is the Authorization HTTP header.

    accessKeyId is provided by RGW, and is (presumably) extracted from the
    Authorization HTTP header.

    This will throw a SignatureException on any singature calculation or
    verification error.
    """

    # Everything gets encoded into byte arrays. This is a pain and looks ugly,
    # but keeps Python happy.

    # Split the Authorization header into useful chunks.
    auth = req.authorization_header

    m = re_sig_v4.search(auth)
    if not m:
        raise SignatureException(400, "V4_AUTHORIZATION_HEADER_MALFORMED")

    # This is used to crosscheck.
    hdr_access_key = m.group("accesskey").encode("UTF-8")
    # These are used go generate the Signing Key.
    hdr_shortdate = m.group("date").encode("UTF-8")
    hdr_region = m.group("region").encode("UTF-8")
    hdr_service = m.group("service").encode("UTF-8")
    # This is used to check we agreee.
    hdrsig = m.group("sig")

    # Extract the secret key and userid from our super-secure dict.
    access_key = req.access_key_id
    if not access_key in keys:
        raise SignatureException(401, "ACCESS_KEY_NOT_FOUND")
    lookup = keys[access_key]
    secret_key = lookup["secret"].encode("UTF-8")
    uid = lookup["uid"]
    access_key = access_key.encode("UTF-8")

    # Cross check the access key field with the Credential in the
    # Authorization header.
    if hdr_access_key != access_key:
        raise SignatureException(400, "ACCESS_KEY_MISMATCH")

    ## Implement the signature scheme:
    ##   https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html

    # This is the StringToSign in step 1. It is generated within RGW.
    string_to_sign = req.string_to_sign

    # This is the Signing Key in step 2. It needs the secret key and some
    # components from the Authorization header.
    datekey = hmac.new(b"AWS4" + secret_key, hdr_shortdate, sha256).digest()
    dateregionkey = hmac.new(datekey, hdr_region, sha256).digest()
    dateregionservicekey = hmac.new(dateregionkey, hdr_service, sha256).digest()
    signing_key = hmac.new(dateregionservicekey, b"aws4_request", sha256).digest()

    # This is the Signature, step 3.
    sigbytes = hmac.new(signing_key, string_to_sign.encode("utf-8"), sha256).digest()
    signature = sigbytes.hex()

    if signature == hdrsig:
        logging.info("SIGNATURE MATCH (uid={})".format(uid))
    else:
        logging.warning("SIGNATURE FAIL")
        raise SignatureException(400, "SIGNATURE_NOT_VERIFIED")

    return uid


class AuthServer(auth_pb2_grpc.AuthServiceServicer):
    def Auth(self, request, context):
        try:
            uid = aws_sig(request)
            if uid == "ANONYMOUS":
                user_type = auth_pb2.AuthUserType.AUTH_USER_TYPE_ANONYMOUS
            else:
                user_type = auth_pb2.AuthUserType.AUTH_USER_TYPE_UNSPECIFIED

            return auth_pb2.AuthResponse(
                user_type=user_type,
                uid=uid,
                message="OK",
                code=200,
            )

        except SignatureException as e:
            logging.warning(f"Authentication failed: {e}")
            return auth_pb2.AuthResponse(
                user_type=auth_pb2.AuthUserType.AUTH_USER_TYPE_UNSPECIFIED,
                uid="",
                message=e.message,
                code=e.code,
            )

    def Status(self, request, context):
        return auth_pb2.StatusResponse(
            server_description="grpc_authenticator.py v0.0.1"
        )


def run(port=8002):
    server_address = f"127.0.0.1:{port}"
    logging.info("Starting gRPC service...\n")
    try:
        server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=10),
            options=(
                ("grpc.so_reuseport", 0),
            ),  # This apparently helps detect port reuse - see https://github.com/grpc/grpc/issues/16920
        )
        auth_pb2_grpc.add_AuthServiceServicer_to_server(AuthServer(), server)
        server.add_insecure_port(server_address)
        server.start()
        logging.info(f"Server started, listening on {server_address}")
        server.wait_for_termination()
    except KeyboardInterrupt:
        pass
    logging.info("Stopping gRPC server...\n")


if __name__ == "__main__":
    from sys import argv

    p = argparse.ArgumentParser(description="Auth gRPC server")
    p.add_argument("port", type=int, help="Listen port", nargs="?", default=8002)
    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = p.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    run(args.port)
