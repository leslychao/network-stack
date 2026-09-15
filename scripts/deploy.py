"""The server-side owner of release activation, consistent backups and rollback."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys

from settings import StackError, private_write
from stack import Stack


def atomic_json(path, value):
    temporary = path.with_suffix(".tmp")
    private_write(temporary, json.dumps(value) + "\n")
    temporary.replace(path)


@contextmanager
def deployment_lock(root):
    import fcntl  # Server only; other modules and unit tests also run on Windows.
    with open(root / "deploy.lock", "a", encoding="utf-8") as lock:
        os.chmod(lock.name, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StackError("Another deployment holds the server lock") from None
        yield


class Deployment:
    def __init__(self, root, stack_factory=Stack):
        self.root = Path(root).resolve()
        self.factory = stack_factory
        self.state = self.root / "state"
        self.transaction = self.root / "transaction.json"
        self.current = self.root / "current.json"
        self.last = self.root / "last-deployment.json"

    def release(self, name):
        if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}", name):
            raise StackError("Invalid release identifier")
        path = self.root / "releases" / name
        if path.resolve().parent != (self.root / "releases").resolve() or path.is_symlink():
            raise StackError("Release must stay inside the releases directory")
        return path

    def stack(self, name):
        return self.factory(self.release(name), self.state)

    def current_name(self):
        return json.loads(self.current.read_text())["release"] if self.current.exists() else None

    def restore(self, transaction):
        candidate = self.stack(transaction["candidate"])
        candidate.command("stop", "caddy", "xui", "mtg", label="Stop unsuccessful release")
        previous = transaction["previous"]
        if previous:
            if transaction["snapshot_ready"]:
                # Both endpoints are derived from a validated release ID under our root.
                snapshot = self.root / "backups" / self.release(transaction["candidate"]).name / "xui"
                if not snapshot.is_dir() or snapshot.is_symlink():
                    raise StackError("Rollback snapshot is missing")
                target = self.state / "xui"
                if target.is_symlink() or target.resolve().parent != self.state.resolve():
                    raise StackError("Unsafe panel state path")
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(snapshot, target)
            self.stack(previous).start()
            atomic_json(self.current, {"release": previous})
            print("Previous release and panel database restored.", flush=True)
        else:
            # Keep incomplete first-run state so the next attempt can resume safely.
            self.current.unlink(missing_ok=True)
            print("First installation stopped; partial bootstrap state retained.", flush=True)

    def recover(self):
        if self.transaction.exists():
            transaction = json.loads(self.transaction.read_text())
            print("Recovering an interrupted deployment.", flush=True)
            self.restore(transaction)
            self.transaction.unlink()

    def apply(self, name):
        self.recover()
        candidate = self.stack(name)
        candidate.prepare_directories()
        print("Validating candidate images and configuration.", flush=True)
        candidate.preflight()
        previous = self.current_name()
        if previous == name:
            raise StackError("Release already active; create a new deployment attempt")
        transaction = {"candidate": name, "previous": previous, "snapshot_ready": False}
        atomic_json(self.transaction, transaction)
        try:
            if previous:
                print("Closing panel and taking a consistent database snapshot.", flush=True)
                self.stack(previous).command("stop", "caddy", "xui", label="Quiesce panel")
                backup = self.root / "backups" / name
                backup.mkdir(parents=True, mode=0o700)
                shutil.copytree(self.state / "xui", backup / "xui")
                transaction["snapshot_ready"] = True
                atomic_json(self.transaction, transaction)
            print("Initializing or preserving panel-managed access.", flush=True)
            candidate.bootstrap()
            print("Starting services and checking trusted HTTPS.", flush=True)
            candidate.start()
            atomic_json(self.current, {"release": name})
            atomic_json(self.last, transaction)
            self.transaction.unlink()
            print("Deployment completed.", flush=True)
        except Exception:
            print("Deployment failed; restoring the previous state.", flush=True)
            self.restore(transaction)
            self.transaction.unlink()
            raise

    def rollback(self):
        self.recover()
        if not self.last.exists():
            raise StackError("No previous deployment snapshot is available")
        transaction = json.loads(self.last.read_text())
        if not transaction["previous"] or self.current_name() != transaction["candidate"]:
            raise StackError("No matching previous release to restore")
        atomic_json(self.transaction, transaction)
        self.restore(transaction)
        self.transaction.unlink()
        self.last.unlink()


def interrupted(_signum, _frame):
    # Permit the rollback to finish after the first termination request.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise StackError("Deployment interrupted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["apply", "rollback"])
    parser.add_argument("--release")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        raise StackError("Server deployment requires Linux root privileges")
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    deployment = Deployment("/opt/network-stack")
    with deployment_lock(deployment.root):
        if args.action == "apply":
            deployment.apply(args.release)
        else:
            deployment.rollback()


if __name__ == "__main__":
    try:
        main()
    except StackError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("Deployment failed unexpectedly; inspect the private server state before retrying.", file=sys.stderr)
        sys.exit(1)

