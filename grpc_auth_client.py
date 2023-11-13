#!/usr/bin/env python3
"""
Simple test client for the AuthService gRPC protocol.
"""

import argparse
import grpc
import logging
import sys

from rgw.auth.v1 import auth_pb2_grpc
from rgw.auth.v1 import auth_pb2


def status(stub: auth_pb2_grpc.AuthServiceStub, args):
    req = auth_pb2.StatusRequest()
    response: auth_pb2.StatusResponse = stub.Status(req)
    logging.info(f"server responds: server_description='{response.server_description}'")


def auth(stub: auth_pb2_grpc.AuthServiceStub, args):
    req = auth_pb2.AuthRequest()
    req.string_to_sign = args.string_to_sign
    req.authorization_header = args.authorization_header
    req.access_key_id = args.access_key_id
    response = stub.Auth(req)
    logging.info(
        f"server responses: uid='{response.uid}' message='{response.message}' code='{response.code}'"
    )


def main(argv):
    p = argparse.ArgumentParser(description="AuthService client")
    p.add_argument("command")
    p.add_argument("-p", "--port", type=int, default=8002, help="server listen port")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--string-to-sign", help="stringToSign field")
    p.add_argument("--authorization-header", help="Authorization: header contents")
    p.add_argument("--access-key-id", help="AWS_ACCESS_KEY_ID value")

    args = p.parse_args(argv)
    if not args.command:
        p.usage()
        sys.exit(1)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Set up a channel first.
    port = args.port
    server_address = f"dns:127.0.0.1:{port}"
    logging.debug(f"using server_address {server_address}")
    success = False

    with grpc.insecure_channel(server_address) as channel:
        stub = auth_pb2_grpc.AuthServiceStub(channel)

        if args.command == "auth":
            success = auth(stub, args)
        elif args.command == "status":
            success = status(stub, args)
        else:
            logging.error(f"Unknown command '{args.command}'")
            sys.exit(2)

    if success:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
