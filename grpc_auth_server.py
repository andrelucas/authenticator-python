#!/usr/bin/env python3
"""
Minimal HTTP server implementing TheAuthenticator protocol.

Usage::
    ./grpc_authenticator.py [<port>]
"""

import argparse
import base64
from concurrent import futures
from google.protobuf import any_pb2
from google.rpc import code_pb2
from google.rpc import error_details_pb2
from google.rpc import status_pb2
import grpc
from grpc_status import rpc_status
from hashlib import sha256, sha1
import hmac
import logging
import re
import os
import sys

from authenticator.v1 import authenticator_pb2_grpc as auth_pb2_grpc
from authenticator.v1 import authenticator_pb2 as auth_pb2

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    # ConsoleSpanExporter,
)
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.instrumentation.grpc import GrpcInstrumentorServer

resource = Resource(
    attributes={
        SERVICE_NAME: "grpc_auth_server",
    }
)

provider = TracerProvider(resource=resource)
processor = BatchSpanProcessor(
    OTLPSpanExporter(endpoint="localhost:4317", insecure=True)
)
# processor = BatchSpanProcessor(ConsoleSpanExporter())
provider.add_span_processor(processor)

# Sets the global default tracer provider
trace.set_tracer_provider(provider)

# Creates a tracer from the global tracer provider
tracer = trace.get_tracer(__name__)

grpc_server_instrumentor = GrpcInstrumentorServer()
grpc_server_instrumentor.instrument()

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

# A list of bucket names that are considered public, i.e. can be accessed
# anonymously.
public_buckets = ["bucket", "test", "testnv"]


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


def type_enum():
    "Shortcut to get the enum type."
    return auth_pb2.S3ErrorDetails.Type


class SignatureException(Exception):
    grpc_code = code_pb2.INTERNAL
    s3_error_type = 0  # TYPE_UNSPECIFIED.
    http_error_code = 401  # Unauthorized (and requires authentication).
    message = ""

    def __init__(self, grpc_code, s3_error_type, http_error_code, message):
        super().__init__()
        self.grpc_code = grpc_code
        self.s3_error_type = s3_error_type
        self.http_error_code = http_error_code
        self.message = message

    def __str__(self):
        gcstr = code_pb2.Code.Name(self.grpc_code)  # String form of the gRPC code.
        tstr = (
            type_enum().DESCRIPTOR.values_by_number[self.s3_error_type].name
        )  # String form of the S3 error type.
        return f"SignatureException(grpc_code={gcstr},s3_error_type={tstr},http_error_code={self.http_error_code},message='{self.message}')"


def reqmethod_to_str(method: auth_pb2.AuthenticateRESTRequest.HTTPMethod):
    m = auth_pb2.AuthenticateRESTRequest.HTTPMethod

    if method == m.REQUEST_METHOD_GET:
        return "GET"
    elif method == m.REQUEST_METHOD_HEAD:
        return "HEAD"
    elif method == m.REQUEST_METHOD_POST:
        return "POST"
    elif method == m.REQUEST_METHOD_PUT:
        return "PUT"
    elif method == m.REQUEST_METHOD_DELETE:
        return "DELETE"
    else:
        return "UNKNOWN"


@tracer.start_as_current_span("aws_sig")
def aws_sig(req: auth_pb2.AuthenticateRESTRequest):
    logging.info("new auth request")
    anonymous: bool = False
    if req.authorization_header == "":
        logging.info(
            "Authorization: header is empty, assuming anonymous access attempt"
        )
        anonymous = True
    else:
        logging.debug(f"authorization_header: {req.authorization_header}")
        logging.debug(f"string_to_sign: {req.string_to_sign}")

    for k, v in req.x_amz_headers.items():
        logging.debug(f"x_amz_headers: {k}={v}")

    for k, v in req.query_parameters.items():
        logging.debug(f"query_parameters: {k}={v}")

    if req.HasField("bucket_name"):
        logging.debug(f"bucket_name: {req.bucket_name}")

    if req.HasField("object_key"):
        logging.debug(f"object_key: {req.object_key}")

    if anonymous:
        if req.HasField("bucket_name"):
            if req.bucket_name in public_buckets:
                logging.info(
                    f"Bucket {req.bucket_name} is public, allowing anonymous access"
                )
                return "anonymous"
            else:
                logging.error(f"Bucket {req.bucket_name} is not public")
                raise SignatureException(
                    code_pb2.INVALID_ARGUMENT,
                    type_enum().TYPE_ACCESS_DENIED,
                    403,
                    "ACCESS_DENIED",
                )
        else:
            raise SignatureException(
                code_pb2.INVALID_ARGUMENT,
                type_enum().TYPE_ACCESS_DENIED,
                403,
                "ACCESS_DENIED",
            )

    else:
        auth = req.authorization_header
        if auth.startswith("AWS "):
            return aws_sig_v2(req)
        else:
            return aws_sig_v4(req)


@tracer.start_as_current_span("aws_sig_v2")
def aws_sig_v2(req: auth_pb2.AuthenticateRESTRequest):
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
        raise SignatureException(
            code_pb2.INVALID_ARGUMENT,
            type_enum().TYPE_AUTHORIZATION_HEADER_MALFORMED,
            400,
            "V2_AUTHORIZATION_HEADER_MALFORMED",
        )

    hdr_access_key = m.group("accesskey")
    hdrsig = m.group("sig")

    # Extract the secret key and userid from our super-secure dict.
    if not hdr_access_key in keys:
        logging.warn("ACCESS_KEY_NOT_FOUND")
        raise SignatureException(
            code_pb2.INVALID_ARGUMENT,
            type_enum().TYPE_INVALID_ACCESS_KEY_ID,
            403,
            "ACCESS_KEY_NOT_FOUND",
        )
    lookup = keys[hdr_access_key]
    secret_key = lookup["secret"].encode("UTF-8")
    uid = lookup["uid"]
    access_key = hdr_access_key.encode("UTF-8")

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
        raise SignatureException(
            code_pb2.INVALID_ARGUMENT,
            type_enum().TYPE_SIGNATURE_DOES_NOT_MATCH,
            403,
            "SIGNATURE_NOT_VERIFIED",
        )

    return uid


@tracer.start_as_current_span("aws_sig_v2")
def aws_sig_v4(req: auth_pb2.AuthenticateRESTRequest):
    """
    Calculate an AWS S3 v4 signature, given the POST object send by the
    Handoff engine.

    Called with an authenticator.v1.AuthenticateRESTRequest message.

    stringToSign is a formed by RGW as a canonicalisation of the original S3
    request. The formulation is tricky and I'm glad it's done for us.

    authorization_header is the Authorization HTTP header.

    Several fields are optional. Many requests don't have a bucket or object
    key.

    This will throw a SignatureException on any singature calculation or
    verification error.
    """

    # Everything gets encoded into byte arrays. This is a pain and looks ugly,
    # but keeps Python happy.

    # Split the Authorization header into useful chunks.
    auth = req.authorization_header

    m = re_sig_v4.search(auth)
    if not m:
        raise SignatureException(
            code_pb2.INVALID_ARGUMENT,
            type_enum().TYPE_AUTHORIZATION_HEADER_MALFORMED,
            400,
            "V4_AUTHORIZATION_HEADER_MALFORMED",
        )

    # We'll use the access key to look up the secret.
    hdr_access_key = m.group("accesskey")
    logging.debug(f"hdr_access_key: {hdr_access_key}")

    # These are used to generate the Signing Key.
    hdr_shortdate = m.group("date").encode("UTF-8")
    hdr_region = m.group("region").encode("UTF-8")
    hdr_service = m.group("service").encode("UTF-8")
    # This is used to check we agreee.
    hdrsig = m.group("sig")

    # Extract the secret key and userid from our super-secure dict.
    if not hdr_access_key in keys:
        logging.warning("ACCESS_KEY_NOT_FOUND")
        raise SignatureException(
            code_pb2.INVALID_ARGUMENT,
            type_enum().TYPE_INVALID_ACCESS_KEY_ID,
            401,
            "ACCESS_KEY_NOT_FOUND",
        )
    lookup = keys[hdr_access_key]
    secret_key = lookup["secret"].encode("UTF-8")
    uid = lookup["uid"]
    access_key = hdr_access_key.encode("UTF-8")

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
        raise SignatureException(
            code_pb2.INVALID_ARGUMENT,
            type_enum().TYPE_SIGNATURE_DOES_NOT_MATCH,
            403,
            "SIGNATURE_NOT_VERIFIED",
        )

    return uid


def v4_signing_key(req: auth_pb2.GetSigningKeyRequest):
    """
    Copy the signature generation from aws_sig_v4 and return the signature as
    a byte array.

    XXX should probably be refactored. Even if it's only a prototype.
    """

    logging.info("new signing key request")

    # Everything gets encoded into byte arrays. This is a pain and looks ugly,
    # but keeps Python happy.

    # Split the Authorization header into useful chunks.
    auth = req.authorization_header

    m = re_sig_v4.search(auth)
    if not m:
        raise SignatureException(
            code_pb2.INVALID_ARGUMENT,
            type_enum().TYPE_AUTHORIZATION_HEADER_MALFORMED,
            400,
            "V4_AUTHORIZATION_HEADER_MALFORMED",
        )

    # We'll use the access key to look up the secret.
    hdr_access_key = m.group("accesskey")
    logging.debug(f"hdr_access_key: {hdr_access_key}")

    # These are used to generate the Signing Key.
    hdr_shortdate = m.group("date").encode("UTF-8")
    hdr_region = m.group("region").encode("UTF-8")
    hdr_service = m.group("service").encode("UTF-8")
    # This is used to check we agreee.
    hdrsig = m.group("sig")

    # Extract the secret key and userid from our super-secure dict.
    if not hdr_access_key in keys:
        logging.warning("ACCESS_KEY_NOT_FOUND")
        raise SignatureException(
            code_pb2.INVALID_ARGUMENT,
            type_enum().TYPE_INVALID_ACCESS_KEY_ID,
            401,
            "ACCESS_KEY_NOT_FOUND",
        )
    lookup = keys[hdr_access_key]
    secret_key = lookup["secret"].encode("UTF-8")
    uid = lookup["uid"]
    access_key = hdr_access_key.encode("UTF-8")

    # This is the Signing Key in step 2. It needs the secret key and some
    # components from the Authorization header.
    datekey = hmac.new(b"AWS4" + secret_key, hdr_shortdate, sha256).digest()
    dateregionkey = hmac.new(datekey, hdr_region, sha256).digest()
    dateregionservicekey = hmac.new(dateregionkey, hdr_service, sha256).digest()
    signing_key = hmac.new(dateregionservicekey, b"aws4_request", sha256).digest()

    logging.debug(f"signing key: {signing_key.hex()}")
    return signing_key


def auth_error_status(e: SignatureException):
    """
    Create a gRPC status response embedding the given code and error message.

    This is fiddly: See https://grpc.io/docs/guides/error/ .
    """

    # The standard Status takes an Any field for message-specific error
    # details. We'll use this to embed the S3 error type and HTTP status code.

    detail = any_pb2.Any()
    detail.Pack(
        auth_pb2.S3ErrorDetails(
            type=e.s3_error_type,
            http_status_code=e.http_error_code,
        )
    )
    return status_pb2.Status(
        code=e.grpc_code,
        message=e.message,
        details=[detail],
    )


class AuthServer(auth_pb2_grpc.AuthenticatorServiceServicer):

    c_auth = 0
    c_sign = 0

    @tracer.start_as_current_span("AuthenticateREST")
    def AuthenticateREST(self, request, context):
        self.c_auth += 1
        logging.info(f"AuthenticateREST count {self.c_auth}")
        try:
            # aws_sig will raise SignatureException on any error.
            uid = aws_sig(request)
            return auth_pb2.AuthenticateRESTResponse(
                canonical_user_id=uid,
            )

        except SignatureException as e:
            logging.warning(f"Authentication failed: {e}")
            context.abort_with_status(rpc_status.to_status(auth_error_status(e)))

    def GetSigningKey(self, request, context):
        self.c_sign += 1
        logging.info(f"SetSigningKey count {self.c_auth}")
        try:
            key = v4_signing_key(request)
            return auth_pb2.GetSigningKeyResponse(signing_key=key)

        except Exception as e:
            logging.warning(f"Failed to get signature: {e}")
            context.abort_with_status(rpc_status.to_status(auth_error_status(e)))


def _load_credential_from_file(filepath):
    """https://github.com/grpc/grpc/blob/master/examples/python/auth/_credentials.py"""
    real_path = os.path.join(os.path.dirname(__file__), filepath)
    with open(real_path, "rb") as f:
        return f.read()


def run(args):
    server_address = f"127.0.0.1:{args.port}"
    logging.info("Starting gRPC service...\n")
    try:
        server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=10),
            options=(
                ("grpc.so_reuseport", 0),
            ),  # This apparently helps detect port reuse - see https://github.com/grpc/grpc/issues/16920
        )
        auth_pb2_grpc.add_AuthenticatorServiceServicer_to_server(AuthServer(), server)

        if args.tls:
            server_crt = _load_credential_from_file(args.server_cert)
            server_key = _load_credential_from_file(args.server_key)
            server_credentials = grpc.ssl_server_credentials(
                (
                    (
                        server_key,
                        server_crt,
                    ),
                )
            )
            server.add_secure_port(server_address, server_credentials)

        else:
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
    p.add_argument(
        "-t", "--tls", help="connect to the server using TLS", action="store_true"
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    ptls = p.add_argument_group("TLS arguments")
    ptls.add_argument("--ca-cert", help="CA certificate file (NOT YET USED)")
    ptls.add_argument("--server-cert", help="client certificate file")
    ptls.add_argument("--server-key", help="client key file")

    args = p.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.tls:
        if not args.server_cert:
            logging.error("TLS requires a server certificate")
            sys.exit(1)
        if not args.server_key:
            logging.error("TLS requires a server key")
            sys.exit(1)

    run(args)
