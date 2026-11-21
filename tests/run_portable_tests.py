#!/usr/bin/env python3
"""Compile and run portable C++17 regression tests without requiring CMake."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


TESTS = ("external_ip_cache", "claude_risk", "ip_text_provider")


def run_tests(compiler, build_dir, repo_root):
    for name in TESTS:
        source = repo_root / "tests" / (name + "_tests.cpp")
        executable = build_dir / (name + "_tests" + (".exe" if os.name == "nt" else ""))
        print("Building " + name, flush=True)
        subprocess.run(
            [compiler, "-std=c++17", "-Wall", "-Wextra", "-Wpedantic", "-O2",
             "-I", str(repo_root / "src"), str(source), "-o", str(executable)],
            check=True,
        )
        print("Running " + name, flush=True)
        subprocess.run([str(executable)], check=True)
    print("All {} portable test executables passed.".format(len(TESTS)), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cxx", default=os.environ.get("CXX"),
                        help="C++ compiler executable (default: CXX, clang++, or g++)")
    parser.add_argument("--build-dir", type=Path,
                        help="Keep test executables in this directory instead of temporary storage")
    args = parser.parse_args()
    compiler = args.cxx or shutil.which("clang++") or shutil.which("g++")
    if not compiler:
        parser.error("No C++ compiler found; set CXX or pass --cxx")

    repo_root = Path(__file__).resolve().parents[1]
    try:
        if args.build_dir:
            build_dir = args.build_dir.resolve()
            build_dir.mkdir(parents=True, exist_ok=True)
            run_tests(compiler, build_dir, repo_root)
        else:
            scratch_root = repo_root / "work"
            scratch_root.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="portable-tests-", dir=scratch_root) as directory:
                run_tests(compiler, Path(directory), repo_root)
    except subprocess.CalledProcessError as error:
        print("Command failed with exit status {}".format(error.returncode), file=sys.stderr)
        return error.returncode if 0 < error.returncode <= 255 else 1
    except OSError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
