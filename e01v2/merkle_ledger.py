"""Bounded, strict JSONL Merkle receipts using the retained merklecpp scheme.

Hashes detect changes relative to a trusted root; this is not authenticated or
tamper-proof storage. One process owns a ledger path. Recovery never truncates
files automatically. Legacy well-formed entries retain their hash encoding.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import stat
import threading
import weakref

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_RECORD_BYTES = 65536
MAX_RECEIPTS = 10000
_registry_lock = threading.Lock()
_states = weakref.WeakValueDictionary()


class LedgerError(Exception):
    code = "E_LEDGER"


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def leaf_hash(receipt_json: str) -> bytes:
    return _h(receipt_json.encode("utf-8"))


def _digest(value):
    return type(value) is bytes and len(value) == 32


def _leaves_valid(leaves):
    if type(leaves) is not list or len(leaves) > MAX_RECEIPTS or not all(_digest(x) for x in leaves):
        raise ValueError("invalid or oversized leaf sequence")

def merkle_root(leaves: list[bytes]) -> bytes:
    _leaves_valid(leaves)
    if not leaves:
        return _h(b"")          # provisional empty-tree sentinel
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(_h(level[i] + level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])          # carry odd node up unchanged
        level = nxt
    return level[0]


def inclusion_proof(leaves: list[bytes], index: int) -> list[tuple[str, str]]:
    """Return [(side, hex_digest)] path from leaf to root."""
    _leaves_valid(leaves)
    if type(index) is not int or not (0 <= index < len(leaves)):
        raise IndexError("leaf index out of range")
    proof = []
    level = list(leaves)
    i = index
    while len(level) > 1:
        nxt = []
        for j in range(0, len(level) - 1, 2):
            nxt.append(_h(level[j] + level[j + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        sib = i ^ 1
        if sib < len(level) and not (len(level) % 2 == 1 and i == len(level) - 1):
            side = "L" if sib < i else "R"
            proof.append((side, level[sib].hex()))
        i //= 2
        level = nxt
    return proof


def verify_inclusion(leaf: bytes, proof: list[tuple[str, str]], root: bytes) -> bool:
    """Verify membership against the supplied root, without index/size claims."""
    if not _digest(leaf) or not _digest(root) or type(proof) is not list or len(proof) > 14:
        return False
    value = leaf
    for step in proof:
        if type(step) not in (tuple, list) or len(step) != 2:
            return False
        side, sibling = step
        if side not in ("L", "R") or not _hex(sibling):
            return False
        digest = bytes.fromhex(sibling)
        value = _h(digest + value) if side == "L" else _h(value + digest)
    return value == root


def _hex(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def verify_proof(payload):
    """Validate both positional path shape and hash membership of a proof response."""
    if type(payload) is not dict or set(payload) != {"index", "tree_size", "leaf_sha256", "merkle_root", "proof"}:
        return False
    index, size, proof = payload["index"], payload["tree_size"], payload["proof"]
    if type(index) is not int or type(size) is not int or not 0 <= index < size <= MAX_RECEIPTS:
        return False
    if not _hex(payload["leaf_sha256"]) or not _hex(payload["merkle_root"]) or type(proof) is not list:
        return False
    expected = []
    while size > 1:
        if index ^ 1 < size:
            expected.append("L" if index % 2 else "R")
        index //= 2
        size = (size + 1) // 2
    if len(proof) != len(expected) or any(type(p) not in (list, tuple) or len(p) != 2 or p[0] != side for p, side in zip(proof, expected)):
        return False
    return verify_inclusion(bytes.fromhex(payload["leaf_sha256"]), proof, bytes.fromhex(payload["merkle_root"]))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _invalid(_):
    raise ValueError("nonfinite JSON value")


def _json(value):
    # Preserve baseline separators and Unicode encoding for existing valid hashes.
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)


def _receipt_body(receipt):
    if type(receipt) is not dict:
        raise LedgerError("receipt must be a JSON object")
    pending = [(receipt, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 32 or count > 10000:
            raise LedgerError("receipt structure budget exceeded")
        if type(item) is dict:
            if len(item) > 10000 or any(type(k) is not str or len(k) > MAX_RECORD_BYTES for k in item):
                raise LedgerError("receipt keys must be strings")
            pending.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            if len(item) > 10000:
                raise LedgerError("receipt sequence budget exceeded")
            pending.extend((v, depth + 1) for v in item)
        elif type(item) is str and len(item) > MAX_RECORD_BYTES:
            raise LedgerError("receipt string budget exceeded")
        elif type(item) is int and item.bit_length() > 8192:
            raise LedgerError("receipt integer budget exceeded")
        elif item is not None and type(item) not in (str, int, float, bool):
            raise LedgerError("unsupported receipt value")
    try:
        body = _json(receipt)
        if len(body.encode("utf-8")) > MAX_RECORD_BYTES - 512:
            raise LedgerError("receipt byte budget exceeded")
        return body
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise LedgerError("receipt is not bounded strict JSON") from exc


def _extend(frontier, leaf):
    result = list(frontier)
    level = 0
    while level < len(result) and result[level] is not None:
        leaf = _h(result[level] + leaf)
        result[level] = None
        level += 1
    if level == len(result):
        result.append(leaf)
    else:
        result[level] = leaf
    return result


def _frontier_root(frontier):
    value = None
    for item in frontier:
        if item is not None:
            value = item if value is None else _h(item + value)
    return _h(b"") if value is None else value


def _signature(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def _stat(path):
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:
        raise LedgerError("ledger must be a regular non-reparse file")
    if st.st_size > MAX_FILE_BYTES:
        raise LedgerError("ledger file byte budget exceeded")
    return st


def _read(path):
    initial = _stat(path)
    leaves, frontier = [], []
    with open(path, "rb") as stream:
        if _signature(os.fstat(stream.fileno())) != _signature(initial):
            raise LedgerError("ledger changed while opening")
        for lineno in range(1, MAX_RECEIPTS + 2):
            raw = stream.readline(MAX_RECORD_BYTES + 1)
            if not raw:
                break
            if lineno > MAX_RECEIPTS or len(raw) > MAX_RECORD_BYTES or not raw.endswith(b"\n"):
                raise LedgerError(f"line {lineno}: oversized ledger or incomplete line; file left unchanged")
            try:
                entry = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_invalid)
                if type(entry) is not dict or set(entry) != {"receipt", "leaf_sha256", "tree_size", "merkle_root"}:
                    raise ValueError("invalid entry fields")
                leaf = leaf_hash(_receipt_body(entry["receipt"]))
                frontier = _extend(frontier, leaf)
                if not _hex(entry["leaf_sha256"]) or entry["leaf_sha256"] != leaf.hex():
                    raise ValueError("leaf hash mismatch")
                if type(entry["tree_size"]) is not int or entry["tree_size"] != lineno:
                    raise ValueError("tree size mismatch")
                if entry["merkle_root"] != _frontier_root(frontier).hex():
                    raise ValueError("root mismatch")
                leaves.append(leaf)
            except (ValueError, KeyError, TypeError, UnicodeError, RecursionError) as exc:
                raise LedgerError(f"line {lineno}: invalid ledger entry; file left unchanged") from exc
        if _signature(os.fstat(stream.fileno())) != _signature(initial) or _signature(_stat(path)) != _signature(initial):
            raise LedgerError("ledger changed while reading")
    return leaves, frontier, _signature(initial)


class _State:
    def __init__(self):
        self.lock = threading.RLock()
        self.loaded = False
        self.failed = False


class MerkleLedger:
    def __init__(self, path: str):
        self.path = os.path.normcase(os.path.abspath(os.fspath(path)))
        self.recovered_tail_bytes = 0  # Retained compatibility field: no automatic recovery.
        with _registry_lock:
            state = _states.get(self.path)
            if state is None:
                state = _State()
                _states[self.path] = state
            self._state = state
        with state.lock:
            if state.loaded:
                self._check()
                return
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            if not os.path.lexists(self.path):
                try:
                    descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    pass
                else:
                    os.close(descriptor)
            state.leaves, state.frontier, state.signature = _read(self.path)
            state.loaded = True

    def _check(self):
        state = self._state
        if state.failed or _signature(_stat(self.path)) != state.signature:
            raise LedgerError("ledger changed externally or a prior write failed; reopen after investigation")

    def snapshot(self):
        with self._state.lock:
            self._check()
            return {"size": len(self._state.leaves), "merkle_root": _frontier_root(self._state.frontier).hex()}

    @property
    def size(self):
        return self.snapshot()["size"]

    def root_hex(self):
        return self.snapshot()["merkle_root"]

    def append(self, receipt):
        body = _receipt_body(receipt)
        detached = json.loads(body)
        leaf = leaf_hash(body)
        state = self._state
        with state.lock:
            self._check()
            if len(state.leaves) >= MAX_RECEIPTS:
                raise LedgerError("ledger receipt budget exceeded")
            frontier = _extend(state.frontier, leaf)
            entry = {"receipt": detached, "leaf_sha256": leaf.hex(),
                "tree_size": len(state.leaves) + 1, "merkle_root": _frontier_root(frontier).hex()}
            raw = (_json(entry) + "\n").encode("utf-8")
            if len(raw) > MAX_RECORD_BYTES or state.signature[2] + len(raw) > MAX_FILE_BYTES:
                raise LedgerError("ledger byte budget exceeded")
            try:
                with open(self.path, "r+b") as stream:
                    if _signature(os.fstat(stream.fileno())) != state.signature:
                        raise LedgerError("ledger changed before append")
                    stream.seek(0, os.SEEK_END)
                    if stream.write(raw) != len(raw):
                        raise OSError("incomplete ledger write")
                    stream.flush()
                    os.fsync(stream.fileno())
                    signature = _signature(os.fstat(stream.fileno()))
                if _signature(_stat(self.path)) != signature:
                    raise LedgerError("ledger changed during append")
            except Exception as exc:
                state.failed = True
                raise LedgerError("ledger write failed; further use refused") from exc
            # Publish in-memory state only after the durable write succeeds.
            state.leaves.append(leaf)
            state.frontier, state.signature = frontier, signature
            return entry

    def proof(self, index):
        with self._state.lock:
            self._check()
            leaves = list(self._state.leaves)
            if type(index) is not int or not 0 <= index < len(leaves):
                raise IndexError("leaf index out of range")
            return {"index": index, "leaf_sha256": leaves[index].hex(),
                "proof": inclusion_proof(leaves, index), "tree_size": len(leaves),
                "merkle_root": _frontier_root(self._state.frontier).hex()}


def verify_ledger(path):
    """Read-only verification. Invalid files are reported, never repaired."""
    try:
        leaves, frontier, _ = _read(path)
        return {"ok": True, "receipts": len(leaves), "merkle_root": _frontier_root(frontier).hex()}
    except (LedgerError, OSError) as exc:
        return {"ok": False, "error": str(exc)}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="Verify a Merkle receipt ledger without changing it")
    parser.add_argument("ledger")
    args = parser.parse_args(argv)
    report = verify_ledger(args.ledger)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
