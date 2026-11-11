# Sample integration: Python

Package: [`sdk/python/arkeep_sdk`](../../sdk/python/arkeep_sdk) — standard
library only (`socket`, `json`), Python 3.9+.

```bash
pip install ./sdk/python/arkeep_sdk
# (or, once published) pip install arkeep-sdk
```

```python
import os
from arkeep_sdk import Client, DeniedError

client = Client(os.environ["ARKEEP_SOCKET"])
token = os.environ["ARKEEP_TOKEN"]

client.set(token, "myapp/DB_PASSWORD", b"s3cr3t")
value = client.get(token, "myapp/DB_PASSWORD")
assert value == b"s3cr3t"

try:
    client.get(token, "someone-elses/SECRET")
except DeniedError:
    print("correctly denied")
```

This exact flow is what
[`sdk/python/arkeep_sdk/examples/smoke.py`](../../sdk/python/arkeep_sdk/examples/smoke.py)
runs for real in CI (`scripts/sdk-smoke.sh`).

## Server mode (TLS / mutual TLS)

```python
client = Client.connect_tls(
    addr="arkeep.example.internal:8443",
    server_name="arkeep.example.internal",
    ca_cert_path="/path/to/ca.pem",
    # client_cert_path/client_key_path: set both together only if the
    # server requires mutual TLS ($ARKEEP_TLS_CLIENT_CA).
)
```

Uses Python's own `ssl` module — no third-party TLS library. TLS 1.3
only (`minimum_version`/`maximum_version` both pinned to `TLSv1_3`),
`PROTOCOL_TLS_CLIENT`'s secure defaults (`check_hostname=True`,
`verify_mode=CERT_REQUIRED`) are never weakened, and this client's trust
store contains only the CA you provide (`load_default_certs()` is never
called, so Python's system/public root store is never trusted here).
Proven for real — including rejecting a wrong hostname, rejecting a
connection with no client cert against an mTLS-only server, and
rejecting a client cert signed by a different, untrusted CA — by
[`sdk/python/arkeep_sdk/examples/smoke_tls.py`](../../sdk/python/arkeep_sdk/examples/smoke_tls.py),
run by `scripts/server-mode-smoke.sh`.
