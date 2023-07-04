# authenticator-python

Simple Python prototype of The Authenticator.

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
enabled.

```ini
...
# Enable the Handoff engine.
rgw_s3_auth_use_handoff = true
# Not an https endpoint, so it doesn't matter.
rgw_handoff_verify_ssl  = true
# This is actually the default.
rgw_handoff_uri         = http://127.0.0.1:8001/
...
```

## Test

If you don't have s3cmd configured already, this will do it for a server on
`localhost:3000` and using the Ceph default keypair.

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

If you want different keys and user IDs, edit variable `keys` in the source file.

```sh
s3cmd mb s3://test
s3cmd ls s3://test
dd if=/dev/urandom bs=4096 count=1 | s3cmd put - s3://test/rand1
# etc.
```
