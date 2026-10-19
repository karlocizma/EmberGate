# EmberGate product website

Live at https://embergate.niftyisle1.chatgpt.site. The site is public; GitHub repository visibility is managed separately.

The HTML/CSS/JavaScript lives in `src/`. `build.py` creates `dist/` and exports the same Markdown-rendered documentation used by in-app Help through the Rust `export-documentation` example. Update the original guides in `docs/`; do not hand-edit generated JSON. The dashboard screenshot contains isolated fixture data.

From the repository root, with Rust and Python installed:

```sh
python3 website/build.py
python3 -m http.server 17684 --bind 127.0.0.1 --directory website/dist
# In another terminal:
node website/test.mjs
```

Set `BROWSER_BIN` if Chromium is installed elsewhere. Build output has no runtime dependencies or accounts and can be served by any static host. `.openai/hosting.json` records the existing Sites identity. Publishing uses the Sites source/package workflow; never create another Site for this directory or store publishing credentials in files.
