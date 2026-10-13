#!/usr/bin/env python3
"""Install a built auth binary outside the disposable Cargo/source tree."""

import argparse
import os
from pathlib import Path
import shutil
import tempfile


def replace_file(source: Path, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        shutil.copy2(destination, destination.with_name(destination.name + ".previous"))
    descriptor, temporary = tempfile.mkstemp(dir=destination.parent)
    os.close(descriptor)
    try:
        shutil.copyfile(source, temporary)
        os.chmod(temporary, mode)
        with open(temporary, "rb") as stream:
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def install(binary: Path, home: Path, install_unit: bool = False) -> Path:
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("binary must be an existing executable file")
    destination = home / ".local/lib/volta-auth/bin/volta-auth-server"
    if binary.resolve() == destination.resolve():
        raise ValueError("source and destination must differ")
    replace_file(binary, destination, 0o755)
    if install_unit:
        units = home / ".config/systemd/user"
        templates = Path(__file__).resolve().parent
        replace_file(templates / "volta-auth-rust.service", units / "volta-auth-rust.service", 0o644)
        socket = units / "volta-auth-rust.socket"
        if not socket.exists():
            replace_file(templates / socket.name, socket, 0o644)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--install-unit", action="store_true")
    args = parser.parse_args()
    try:
        destination = install(args.binary, Path.home(), args.install_unit)
    except (OSError, ValueError) as error:
        parser.exit(1, f"install failed: {error}\n")
    print(f"Installed: {destination}")
    print("No services enabled or restarted. Reload/restart explicitly after verification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
