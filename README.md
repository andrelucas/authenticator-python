# authenticator-python

Simple Python prototype of The Authenticator.

This service comes in two flavours. The OG authenticator uses REST over HTTP,
but the gRPC version is the version to use for real work.

# HTTP server

## Starting the server

```sh
# Start an authenticator server on port 8001.
./authenticator.py

# Start on a different port.
./authenticator.py 8002
```

The server can be stopped with CTRL-C.

## Configure RGW

Obviously you'll need an RGW with the Handoff authenticator patched in and
enabled. This configuration disables gRPC mode, which is required to test HTTP mode.

```ini
...
# Enable the Handoff engine.
rgw_s3_auth_use_handoff = true
# Disable gRPC mode.
rgw_handoff_enable_grpc = false
# Not an https endpoint, so it doesn't matter.
rgw_handoff_verify_ssl  = true
# This is actually the default.
rgw_handoff_uri         = http://127.0.0.1:8001/
...
```


# gRPC server

The gRPC-based server is forked from the HTTP server as of 20231113. gRPC and
HTTP are both being maintained in the short term, but HTTP will be deprecated
in early 2024.

## Prereqs

```sh
pip3 install grpcio grpcio-status grpcio-tools
```

## Grab gRPC and protobuf generated code.

From a C++ build dir (not the source dir - these are generated files), grab
`bufgen/authenticator/v1/*.py` and copy to `authenticator/v1/` in
the authenticator-python source tree.

```sh
cp MYBUILDDIR/bufgen/authenticator/v1/*.py authenticator/v1
```

The path is so the Python code can be imported as a module, using the proper
path. (It has to match the protobuf source's expected path.)

## Starting the server

```sh
# Start an authenticator server on port 8001.
./grpc_auth_server.py

# Start on a different port.
./grpc_auth_server.py 8002

# Start in verbose mode (useful!)
./grpc_auth_server.py --verbose
```

The server can be stopped with CTRL-C.

If you get this:

```sh
$ ./grpc_auth_server.py
Traceback (most recent call last):
  File "./grpc_auth_server.py", line 18, in <module>
    from authenticator.v1 import auth_pb2_grpc
ImportError: cannot import name 'auth_pb2_grpc' from 'authenticator.v1' (unknown location)
```

then you've not installed the gRPC generated source as directed above. Pay attention!

## Testing the gRPC server in standalone mode

There's a standalone gRPC client that's useful for checking the server without
too much machinery.

```sh
$ ./grpc_auth_client.py -v status
DEBUG:root:using server_address dns:127.0.0.1:8002
INFO:root:server responds: server_description='grpc_authenticator.py v0.0.1'

$ ./grpc_auth_client.py -v auth --string-to-sign=foo \
        --authorization-header=bar --access-key-id=baz
DEBUG:root:using server_address dns:127.0.0.1:8002
INFO:root:server responses: uid='' message='V4_AUTHORIZATION_HEADER_MALFORMED' code='400'
```

Here's a v4 authentication that should work (yes, I know it's a lot):

```sh
$ ./grpc_auth_client.py -v auth \
--string-to-sign="QVdTNC1ITUFDLVNIQTI1NgoyMDIzMTExM1QxNTA4MzNaCjIwMjMxMTEzL3VzLWVhc3QtMS9zMy9hd3M0X3JlcXVlc3QKOTFmM2ZlYmQ1NjFhMTgyNDU1M2RmNTQxMzJiMDVhNGFjZDk2ZDRlOTI4OWE0M2EzMWM5YmY5NWM5M2Q3OTY5Ng==" \
--authorization-header="AWS4-HMAC-SHA256 Credential=0555b35654ad1656d804/20231113/us-east-1/s3/aws4_request, SignedHeaders=content-md5;host;x-amz-content-sha256;x-amz-date, Signature=2d139a3564b7795d859f5ce788b0d7a0f0c9028c8519b381c9add9a72345aace"
DEBUG:root:using server_address dns:127.0.0.1:8002
INFO:root:server responses: uid='testid'
```

And here's a v2 authentication that should work:

```sh
$ ./grpc_auth_client.py -v auth \
--string-to-sign="R0VUCgoKCngtYW16LWRhdGU6VHVlLCAxMSBKdWwgMjAyMyAxNzoxMDozOCArMDAwMAovdGVzdC8=" \
--authorization-header="AWS 0555b35654ad1656d804:ZbQ5cA54KqNak3O2KTRTwX5YzUE="
DEBUG:root:using server_address dns:127.0.0.1:8002
INFO:root:server responses: uid='testid'
```

# General testing

## Configure RGW

You'll need an RGW with the Handoff authenticator patched in and
enabled. This configuration applies to a regular cluster, but can be applied
to a vstart.sh cluster by using the '-o' option to vstart.sh.

```ini
...
# Enable the Handoff engine (false by default).
rgw_s3_auth_use_handoff = true
# Enable gRPC mode (true by default).
rgw_handoff_enable_grpc = true
# Set a URI. (The value shown is the default.)
rgw_handoff_grpc_uri = dns:127.0.0.1:8002
...
```

A vstart equivalent might be:

```sh
$ cd git/ceph/build  # Assuming that's where you've build it.

$ ../src/stop.sh;
env CEPH_PORT=40000 FS=0 RGW=1 MON=1 MDS=0 OSD=1 \
    ../src/vstart.sh -d -n -x \
    -o "rgw_s3_auth_use_handoff = true" -o "rgw_s3_auth_order = external" \
    -o "rgw_beast_enable_async = false" -o "rgw_dns_name = $(hostname -f)"
```

# Test

I use the dbstore backend for Ceph, which automatically installs a user with a
set keypair, mapping to uid 'testid'. I test with `s3cmd`.

If you don't have s3cmd configured already, this will do it for a server on
`localhost:3000` and using the Ceph default keypair. Clearly, this will
overwrite any existing `~/.s3cfg`. Note that this setting doesn't support
virtual hosting, which will break some commands:

```sh
s3cmd --access_key='0555b35654ad1656d804' \
  --secret_key='h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==' \
  --host=127.0.0.1:8000 \
  --host-bucket=127.0.0.1:8000 \
  --no-encrypt \
  --no-ssl \
  --dump-config >~/.s3cfg
```

These keys are configured into the authenticator. Notice they both map onto
the same uid. This is deliberate.

| UID | AWS_ACCESS_KEY | AWS_SECRET_ACCESS_KEY |
|---|---|---|
| `testid`| `0555b35654ad1656d804` | `h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==`|
| `testid` | `4d41474943574f524453` | `53515545414d4953484f5353494652414745`|

If you want different keys and user IDs, edit variable `keys` in the source
file.

Now any s3 command that works with rgw should work here. Note you can swap in
the alternative access/secret keys and everything works as before, because it
all maps back to the same uid.

```sh
s3cmd mb s3://test
s3cmd ls s3://test
dd if=/dev/urandom bs=4096 count=1 | s3cmd put - s3://test/rand1
# etc.
```

