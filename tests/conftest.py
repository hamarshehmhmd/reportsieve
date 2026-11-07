import os
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, "examples", "tinyhdr")
sys.path.insert(0, os.path.join(ROOT, "src"))


def _bwrap_works() -> bool:
    if not shutil.which("bwrap"):
        return False
    try:
        p = subprocess.run(["bwrap", "--ro-bind", "/", "/", "--unshare-all", "true"], capture_output=True, timeout=20)
        return p.returncode == 0
    except Exception:
        return False


BWRAP = _bwrap_works()
CC = shutil.which("cc") is not None or shutil.which("gcc") is not None


def _asan_works() -> bool:
    if not CC:
        return False
    import tempfile
    d = tempfile.mkdtemp()
    try:
        src = os.path.join(d, "a.c")
        with open(src, "w") as fh:
            fh.write("int main(void){return 0;}\n")
        p = subprocess.run(["cc", "-fsanitize=address", src, "-o", os.path.join(d, "a")], capture_output=True)
        return p.returncode == 0 and subprocess.run([os.path.join(d, "a")]).returncode == 0
    except Exception:
        return False
    finally:
        shutil.rmtree(d, ignore_errors=True)


ASAN = _asan_works()
needs_bwrap = pytest.mark.skipif(not BWRAP, reason="bubblewrap not usable here")
needs_asan = pytest.mark.skipif(not (BWRAP and ASAN), reason="needs bubblewrap + a C compiler with ASan")
needs_docker = pytest.mark.skipif(not os.environ.get("REPORTSIEVE_DOCKER"), reason="set REPORTSIEVE_DOCKER=1 to run docker tests")
live = pytest.mark.skipif(not os.environ.get("REPORTSIEVE_LIVE"), reason="set REPORTSIEVE_LIVE=1 for network tests")


@pytest.fixture
def example():
    return EXAMPLE
