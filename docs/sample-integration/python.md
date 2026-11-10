# Sample integration: Python

Package: [`sdk/python/cofferak_sdk`](../../sdk/python/cofferak_sdk) — standard
library only (`socket`, `json`), Python 3.9+.

```bash
pip install ./sdk/python/cofferak_sdk
# (or, once published) pip install cofferak-sdk
```

```python
import os
from cofferak_sdk import Client, DeniedError

client = Client(os.environ["COFFERAK_SOCKET"])
token = os.environ["COFFERAK_TOKEN"]

client.set(token, "myapp/DB_PASSWORD", b"s3cr3t")
value = client.get(token, "myapp/DB_PASSWORD")
assert value == b"s3cr3t"

try:
    client.get(token, "someone-elses/SECRET")
except DeniedError:
    print("correctly denied")
```

This exact flow is what
[`sdk/python/cofferak_sdk/examples/smoke.py`](../../sdk/python/cofferak_sdk/examples/smoke.py)
runs for real in CI (`scripts/sdk-smoke.sh`).
