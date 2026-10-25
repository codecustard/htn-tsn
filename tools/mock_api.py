#!/usr/bin/env python3
"""Offline stand-in for the Kaspa/Hoosat REST API, used by demo.sh to exercise `tsn send`.

Serves fixed UTXOs for one address and accepts POST /transactions, saving the body to --save.
It does no validation; demo.sh re-verifies the saved transaction with the chain engines.
"""
import argparse
import hashlib
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

p = argparse.ArgumentParser()
p.add_argument("--port", type=int, required=True)
p.add_argument("--address", required=True)
p.add_argument("--script", required=True, help="scriptPublicKey hex of --address")
p.add_argument("--utxos", required=True, help="comma-separated amounts in sompi")
p.add_argument("--save", required=True)
args = p.parse_args()

UTXOS = [
    {
        "address": args.address,
        "outpoint": {"transactionId": hashlib.sha256(f"{args.address}/{i}".encode()).hexdigest(), "index": 0},
        "utxoEntry": {
            "amount": str(int(a)),
            "scriptPublicKey": {"scriptPublicKey": args.script},
            "blockDaaScore": "1000",
            "isCoinbase": False,
        },
    }
    for i, a in enumerate(args.utxos.split(","))
]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == f"/addresses/{args.address}/utxos":
            self.reply(200, UTXOS)
        elif self.path.startswith("/addresses/") and self.path.endswith("/utxos"):
            self.reply(200, [])
        elif self.path == "/info/fee-estimate":
            self.reply(200, {"priorityBucket": {"feerate": 1}, "normalBuckets": [{"feerate": 1}], "lowBuckets": []})
        elif self.path == "/info/blockdag":
            self.reply(200, {"virtualDaaScore": "1000000"})
        else:
            self.reply(404, {"detail": "Not Found"})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        if self.path == "/transactions":
            req = json.loads(body)
            with open(args.save, "w") as f:
                json.dump(req, f, indent=2)
            self.reply(200, {"transactionId": "mock-" + hashlib.sha256(body).hexdigest()[:16]})
        else:
            self.reply(404, {"detail": "mock API has no " + self.path})


HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
