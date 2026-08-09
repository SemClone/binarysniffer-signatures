"""Build and sign the signature bundle for a release (runs in CI)."""
import os
import sys
from pathlib import Path

from bsbundle import bundle

tag = sys.argv[1] if len(sys.argv) > 1 else "signatures-dev"
out = Path("dist") / f"{tag}.zip"
bundle.build_bundle(Path("data"), out)
key = os.environ.get("BINARYSNIFFER_SIGNING_KEY")
if key:
    bundle.sign_bundle(out, key)
    print(f"built+signed {out}")
else:
    print(f"built (UNSIGNED) {out}")
