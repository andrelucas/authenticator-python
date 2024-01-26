#!/usr/bin/env python3
"""
Simple test client for the AuthService gRPC protocol.
"""

import argparse
import base64
from google.rpc import code_pb2
from google.rpc import error_details_pb2
from google.rpc import status_pb2
import grpc
from grpc_status import rpc_status
import logging
import os
import sys

from authenticator.v1 import authenticator_pb2_grpc as auth_pb2_grpc
from authenticator.v1 import authenticator_pb2 as auth_pb2


def method_string_to_enum(method: str):
    m = auth_pb2.AuthenticateRESTRequest.HTTPMethod

    if method == "GET":
        return m.HTTP_METHOD_GET
    elif method == "POST":
        return m.HTTP_METHOD_POST
    elif method == "PUT":
        return m.HTTP_METHOD_PUT
    elif method == "DELETE":
        return m.HTTP_METHOD_DELETE
    elif method == "HEAD":
        return m.HTTP_METHOD_HEAD
    else:
        return auth_pb2.HTTP_METHOD_UNSPECIFIED


def auth(stub: auth_pb2_grpc.AuthenticatorServiceStub, args):
    req = auth_pb2.AuthenticateRESTRequest()
    req.string_to_sign = base64.b64decode(args.string_to_sign_base64).decode()
    req.authorization_header = args.authorization_header
    req.http_method = method_string_to_enum(args.method)
    try:
        response = stub.AuthenticateREST(req)
        logging.info(f"server responses: uid='{response.user_id}'")
        return True

    except grpc.RpcError as e:
        # Unpack the error.
        status = rpc_status.from_call(e)
        if status is None:
            logging.error(f"RPC failed: {e}")
        else:
            logging.error(
                f"PC failed: error={e} code={status.code} message='{status.details}'"
            )
            for detail in status.details:
                # Unpack the ANY if it's a specific type.
                if detail.Is(auth_pb2.S3ErrorDetails.DESCRIPTOR):
                    s3_error = auth_pb2.S3ErrorDetails()
                    detail.Unpack(s3_error)
                    tstr = auth_pb2.S3ErrorDetails.Type.DESCRIPTOR.values_by_number[
                        s3_error.type
                    ].name  # String form of the S3 error type.
                    logging.error(
                        f"S3ErrorDetails: type={tstr} http_status_code={s3_error.http_status_code}"
                    )

        return False


def issue(channel, args):
    """
    Issue the RPC. Factored out so we can use different types of channel.
    """
    stub = auth_pb2_grpc.AuthenticatorServiceStub(channel)

    if args.command == "auth":
        success = auth(stub, args)
    else:
        logging.error(f"Unknown command '{args.command}'")
        sys.exit(2)


def _load_credential_from_file(filepath):
    """https://github.com/grpc/grpc/blob/master/examples/python/auth/_credentials.py"""
    real_path = os.path.join(os.path.dirname(__file__), filepath)
    with open(real_path, "rb") as f:
        return f.read()


def main(argv):
    p = argparse.ArgumentParser(description="AuthService client")
    p.add_argument("command", help="command to run", choices=["auth"])
    p.add_argument("--access-key-id", help="AWS_ACCESS_KEY_ID value")
    p.add_argument("--authorization-header", help="Authorization: header contents")
    p.add_argument("--method", help="HTTP method", default="GET")
    p.add_argument("--string-to-sign-base64", help="stringToSign field")
    p.add_argument(
        "-t", "--tls", help="connect to the server using TLS", action="store_true"
    )
    p.add_argument("--uri", help="server uri (will override address and port!)")
    p.add_argument("-a", "--address", help="server address", default="127.0.0.1")
    p.add_argument("-p", "--port", type=int, default=8002, help="server listen port")
    p.add_argument("-v", "--verbose", action="store_true")
    ptls = p.add_argument_group("TLS arguments")
    ptls.add_argument("--ca-cert", help="CA certificate file")
    ptls.add_argument("--client-cert", help="client certificate file (NOT YET USED)")
    ptls.add_argument("--client-key", help="client key file (NOT YET USED)")

    args = p.parse_args(argv)
    if not args.command:
        p.usage()
        sys.exit(1)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.tls:
        if not args.ca_cert:
            logging.error("TLS requires a CA certificate")
            sys.exit(1)

    # Set up a channel string first.
    server_address = f"dns:{args.address}:{args.port}"
    if args.uri:
        server_address = args.uri
    logging.debug(f"using server_address {server_address}")
    success = False

    if args.tls:
        root_crt = _load_credential_from_file(args.ca_cert)
        channel_credential = grpc.ssl_channel_credentials(root_crt)
        with grpc.secure_channel(server_address, channel_credential) as channel:
            issue(channel, args)
    else:
        with grpc.insecure_channel(server_address) as channel:
            issue(channel, args)

    if success:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
