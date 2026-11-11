# arkeep-sdk (Python)

Minimal, dependency-free Python client for [arkeep](https://github.com/arkrwn/arkeep).

```python
from arkeep_sdk import Client

client = Client("/run/arkeep/arkeepd.sock")
client.set("my-token", "myapp/DB_PASSWORD", b"s3cr3t")
value = client.get("my-token", "myapp/DB_PASSWORD")
```

See [`examples/smoke.py`](examples/smoke.py) for a complete, runnable
example, and [`docs/sample-integration/python.md`](../../../docs/sample-integration/python.md)
in the main repo for a walkthrough.
