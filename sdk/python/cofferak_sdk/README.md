# cofferak-sdk (Python)

Minimal, dependency-free Python client for [cofferak](https://github.com/arkrwn/cofferak).

```python
from cofferak_sdk import Client

client = Client("/run/cofferak/cofferakd.sock")
client.set("my-token", "myapp/DB_PASSWORD", b"s3cr3t")
value = client.get("my-token", "myapp/DB_PASSWORD")
```

See [`examples/smoke.py`](examples/smoke.py) for a complete, runnable
example, and [`docs/sample-integration/python.md`](../../../docs/sample-integration/python.md)
in the main repo for a walkthrough.
