#!/usr/bin/env python3
"""
Minimal HTTP server implementing TheAuthenticator protocol.

Usage::
    ./authenticator.py [<port>]
"""

import base64
from hashlib import sha256
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
import re

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
}

# Regex to match fields out of the Authorize header. Compile this once.
re_sig = re.compile(
    r"""^
        AWS4-HMAC-SHA256\s
        Credential=(?P<accesskey>[0-9a-f]+)
        /(?P<date>\d+)
        /(?P<region>[0-9a-z-]+)
        /(?P<service>[0-9a-z-]+)
        /aws4_request
        ,SignedHeaders=(?P<signhdr>[a-z0-9-;]+)
        ,Signature=(?P<sig>[0-9a-f]+)
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


def aws_sig_v4(post):
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
    auth = post["authorization"]

    m = re_sig.search(auth)
    if not m:
        raise SignatureException(400, "AUTHORIZATION_HEADER_MALFORMED")

    # This is used to crosscheck.
    hdr_access_key = m.group("accesskey").encode("UTF-8")
    # These are used go generate the Signing Key.
    hdr_shortdate = m.group("date").encode("UTF-8")
    hdr_region = m.group("region").encode("UTF-8")
    hdr_service = m.group("service").encode("UTF-8")
    # This is used to check we agreee.
    hdrsig = m.group("sig")

    # Extract the secret key and userid from our super-secure dict.
    access_key = post["accessKeyId"]
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
    string_to_sign = base64.b64decode(post["stringToSign"])

    # This is the Signing Key in step 2. It needs the secret key and some
    # components from the Authorization header.
    datekey = hmac.new(b"AWS4" + secret_key, hdr_shortdate, sha256).digest()
    dateregionkey = hmac.new(datekey, hdr_region, sha256).digest()
    dateregionservicekey = hmac.new(dateregionkey, hdr_service, sha256).digest()
    signing_key = hmac.new(dateregionservicekey, b"aws4_request", sha256).digest()

    # This is the Signature, step 3.
    sigbytes = hmac.new(signing_key, string_to_sign, sha256).digest()
    signature = sigbytes.hex()

    if signature == hdrsig:
        logging.info("SIGNATURE MATCH (uid={})".format(uid))
    else:
        logging.warning("SIGNATURE FAIL")
        raise SignatureException(400, "SIGNATURE_NOT_VERIFIED")

    return uid


class AWSAuthHandler(BaseHTTPRequestHandler):
    def _set_response(self):
        "Provide a 404 response."
        self.send_response(404)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(
            b"<html><head><title>Not found</title></head><body><h1>Not found</h1></body></html>"
        )

    def do_GET(self):
        "Log the GET request and do nothing."
        logging.info(
            "GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers)
        )
        if self.path.startswith("/verify"):
            logging.warning("You must use POST for authentication.")
        self._set_response()

    def do_POST(self):
        """
        Log the POST request. If it's to /verify, perform the authenticator's
        role. Otherwise, do nothing.
        """
        if "Content-Length" in self.headers:
            content_length = int(
                self.headers["Content-Length"]
            )  # <--- Gets the size of data
        else:
            content_length = 0
        post_data = self.rfile.read(content_length)  # <--- Gets the data itself
        logging.info(
            "POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
            str(self.path),
            str(self.headers),
            post_data.decode("utf-8"),
        )

        if self.path.startswith("/verify"):
            logging.info("POST AWS auth")
            self.do_aws_auth(post_data)
        else:
            self._set_response()

    def do_aws_auth(self, post_data):
        """
        Take a POST request to /verify, assume it's coming from the RGW
        handoff engine and process it appropriately.
        """
        post = json.loads(post_data.decode("utf-8"))
        logging.info("json: {}".format(post))
        try:
            uid = aws_sig_v4(post)
        except SignatureException as e:
            logging.warning("Authentication failed: {}".format(e))
            self.send_response(e.code, e.message)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        body = json.dumps({"uid": uid, "message": "OK"})
        logging.info("Response body: {}".format(body))
        self.wfile.write(body.encode("utf-8"))


def run(server_class=HTTPServer, handler_class=AWSAuthHandler, port=8001):
    logging.basicConfig(level=logging.INFO)
    server_address = ("", port)
    httpd = server_class(server_address, handler_class)
    logging.info("Starting httpd...\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info("Stopping httpd...\n")


if __name__ == "__main__":
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()