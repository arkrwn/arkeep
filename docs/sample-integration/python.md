# Sample integration: Python

Package: [`sdk/python/mikavt_sdk`](../../sdk/python/mikavt_sdk) — standard
library only (`socket`, `json`), Python 3.9+.

```bash
pip install ./sdk/python/mikavt_sdk
# (or, once published) pip install mikavt-sdk
```

```python
import os
from mikavt_sdk import Client, DeniedError

client = Client(os.environ["MIKAVT_SOCKET"])
token = os.environ["MIKAVT_TOKEN"]

client.set(token, "myapp/DB_PASSWORD", b"s3cr3t")
value = client.get(token, "myapp/DB_PASSWORD")
assert value == b"s3cr3t"

try:
    client.get(token, "someone-elses/SECRET")
except DeniedError:
    print("correctly denied")
```

This exact flow is what
[`sdk/python/mikavt_sdk/examples/smoke.py`](../../sdk/python/mikavt_sdk/examples/smoke.py)
runs for real in CI (`scripts/sdk-smoke.sh`).
