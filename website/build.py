"""Build the standalone product site from source assets and shared Rust-rendered docs."""
import json
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parent
repo = root.parent
out = root / 'dist'
out.mkdir(exist_ok=True)
for source in (root / 'src').iterdir():
    if source.is_file():
        shutil.copy2(source, out / source.name)
result = subprocess.run(['cargo', 'run', '--quiet', '--locked', '--manifest-path', str(repo / 'gateway/Cargo.toml'), '--example', 'export-documentation'], check=True, capture_output=True, text=True)
data = json.loads(result.stdout)
(out / 'documentation.json').write_text(json.dumps(data, ensure_ascii=False))
print(f'Built {out}: product site and {len(data["guides"])} shared documentation guides')
