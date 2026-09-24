"""Bounded loopback HTTP service. Local access is not user authentication."""
from __future__ import annotations

import argparse
import hashlib
import json
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import engine
from .merkle_ledger import MerkleLedger, LedgerError

API_VERSION = "v2"
MAX_BODY_BYTES = 65536
SOCKET_TIMEOUT = 3
MAX_WORKERS = 8


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(_):
    raise ValueError("nonfinite JSON constant")


class CalculatorV2Handler(BaseHTTPRequestHandler):
    server_version = "E01MerkleCalculator/0.1.2a1"
    sys_version = ""
    ledger = None  # Compatibility for direct handler construction in tests.

    def setup(self):
        self.request.settimeout(SOCKET_TIMEOUT)
        super().setup()

    def log_message(self, fmt, *args):
        pass

    def _send(self, status, payload):
        body = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("utf-8")
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass

    def _error(self, status, code, message):
        self._send(status, {"error": {"code": code, "message": message}})

    def _local_request(self):
        expected = f"127.0.0.1:{self.server.server_address[1]}"
        hosts = self.headers.get_all("Host", [])
        origins = self.headers.get_all("Origin", [])
        if len(hosts) != 1 or hosts[0] != expected:
            self._error(403, "E_ORIGIN", "invalid loopback host")
            return False
        if origins and (len(origins) != 1 or origins[0] != "http://" + expected):
            self._error(403, "E_ORIGIN", "cross-origin requests are not permitted")
            return False
        return True

    def _ledger(self):
        ledger = getattr(self.server, "ledger", None) or self.ledger
        if ledger is None:
            raise LedgerError("no ledger sink")
        return ledger

    def do_GET(self):
        if not self._local_request():
            return
        if self.path == f"/{API_VERSION}/health":
            try:
                self._send(200, {"status": "ok", "api": API_VERSION, "ledger": self._ledger().snapshot()})
            except (LedgerError, OSError):
                self._error(503, "E_LEDGER", "ledger unavailable")
        elif self.path.startswith(f"/{API_VERSION}/proof/"):
            index = self.path.rsplit("/", 1)[1]
            if not index.isascii() or not index.isdigit() or len(index) > 5:
                self._error(404, "E_PROOF", "no such leaf")
                return
            try:
                self._send(200, self._ledger().proof(int(index)))
            except (ValueError, IndexError):
                self._error(404, "E_PROOF", "no such leaf")
            except (LedgerError, OSError):
                self._error(503, "E_LEDGER", "ledger unavailable")
        else:
            self._error(404, "E_ROUTE", "unknown route")

    def do_POST(self):
        if not self._local_request():
            return
        if self.path != f"/{API_VERSION}/calculate":
            self._error(404, "E_ROUTE", "unknown route")
            return
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get_all("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
            self._error(400, "E_REQUEST", "one decimal Content-Length is required; transfer encoding is unsupported")
            return
        if len(lengths[0]) > 10:
            self._error(413, "E_LIMIT", "body too large")
            return
        length = int(lengths[0])
        if not 1 <= length <= MAX_BODY_BYTES:
            self._error(413, "E_LIMIT", "body length outside supported range")
            return
        content_types = self.headers.get_all("Content-Type", [])
        if len(content_types) != 1 or content_types[0].split(";")[0].strip().lower() != "application/json":
            self._error(415, "E_REQUEST", "Content-Type must be application/json")
            return
        try:
            raw = self.rfile.read(length)
        except (socket.timeout, OSError):
            self._error(408, "E_REQUEST", "request body timed out")
            return
        if len(raw) != length:
            self._error(400, "E_REQUEST", "incomplete request body")
            return
        try:
            request = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                                 parse_constant=_invalid_constant)
            if type(request) is not dict or set(request) - {"expression", "precision"}:
                raise ValueError("invalid request fields")
            expression = request["expression"]
            precision = request.get("precision", engine.DEFAULT_PRECISION)
            if type(expression) is not str or type(precision) is not int:
                raise ValueError("invalid expression or precision")
            expression.encode("utf-8")
        except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
            self._error(400, "E_REQUEST", "body must contain a string expression and optional integer precision")
            return

        started, monotonic_started = time.time(), time.perf_counter()
        try:
            canonical = engine.canonicalize(engine.parse(expression))
            result = engine.evaluate(expression, precision=precision)
            payload = {"api": API_VERSION, "expression": expression,
                       "canonical": canonical, "result": result.as_strings()}
            status = 200
        except engine.CalcError as exc:
            payload = {"api": API_VERSION, "expression": expression,
                       "error": {"code": exc.code, "message": str(exc)}}
            status = 422
        except Exception:
            payload = {"api": API_VERSION, "error": {"code": "E_INTERNAL", "message": "internal failure"}}
            status = 500
        receipt = {"ts": started, "engine_version": "0.1.2a1", "precision": precision,
            "expression_sha256": hashlib.sha256(expression.encode("utf-8")).hexdigest(),
            "response_sha256": hashlib.sha256(json.dumps(payload, sort_keys=True,
                separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()).hexdigest(),
            "status": status, "outcome": "ok" if status == 200 else payload["error"]["code"],
            "duration_ms": round((time.perf_counter() - monotonic_started) * 1000, 3)}
        try:
            entry = self._ledger().append(receipt)
        except Exception:
            self._error(500, "E_AUDIT", "audit receipt could not be recorded; result withheld")
            return
        payload["receipt"] = {k: entry[k] for k in ("leaf_sha256", "tree_size", "merkle_root")}
        self._send(status, payload)


class CalculatorHTTPServer(ThreadingHTTPServer):
    """Loopback binding and bounded active workers for the supported service factory."""
    daemon_threads = True

    def __init__(self, address, writer):
        if address[0] != "127.0.0.1":
            raise ValueError("loopback host required")
        self.ledger = writer
        self._workers = threading.BoundedSemaphore(MAX_WORKERS)
        super().__init__(address, CalculatorV2Handler)

    def process_request(self, request, client_address):
        if not self._workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._workers.release()


def create_server(port, ledger_path, host="127.0.0.1"):
    if host != "127.0.0.1":
        raise SystemExit("refusing to bind: loopback-only exposure is mandatory")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port must be an integer in 0..65535")
    return CalculatorHTTPServer((host, port), MerkleLedger(ledger_path))


def serve(port, ledger_path, host="127.0.0.1"):
    httpd = create_server(port, ledger_path, host)
    print(json.dumps({"listening": f"http://127.0.0.1:{httpd.server_address[1]}",
                      "api": API_VERSION}), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="E01 Merkle calculator")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ledger", default="audit/merkle_ledger.jsonl")
    args = parser.parse_args(argv)
    serve(args.port, args.ledger)


if __name__ == "__main__":
    sys.exit(main())
