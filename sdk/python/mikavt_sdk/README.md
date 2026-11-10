# mikavt-sdk (Python)

Minimal, dependency-free Python client for [mikavt](https://github.com/arkrwn/mikavt).

```python
from mikavt_sdk import Client

client = Client("/run/mikavt/mikavtd.sock")
client.set("my-token", "myapp/DB_PASSWORD", b"s3cr3t")
value = client.get("my-token", "myapp/DB_PASSWORD")
```

See [`examples/smoke.py`](examples/smoke.py) for a complete, runnable
example, and [`docs/sample-integration/python.md`](../../../docs/sample-integration/python.md)
in the main repo for a walkthrough.
