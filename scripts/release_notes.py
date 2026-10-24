#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
from release import ROOT, validate_tag


def notes(tag,commit,image,manifest):
    v=validate_tag(tag)
    if manifest['version']!=v or manifest['commit']!=commit:raise ValueError('tested archives do not match release source')
    text=(ROOT/'CHANGELOG.md').read_text()
    section=re.split(r'^## \['+re.escape(v)+r'\][^\n]*\n',text,maxsplit=1,flags=re.M)[1]
    section=re.split(r'^## \[',section,maxsplit=1,flags=re.M)[0].strip()
    return f'''{section}

Source commit: `{commit}`. See `release.json` and the `buildinfo.json` inside each archive.

Binary assets: Linux/macOS AMD64 and ARM64, Windows AMD64. Verify `SHA256SUMS` before installation. Archives and checksums have GitHub build provenance attestations; see [installation verification](https://github.com/bishoku/jvmdiag/blob/{tag}/docs/INSTALL.md).

Multi-architecture Linux images (AMD64/ARM64):
- `{image}:{v}` — native server
- `{image}:{v}-diagnostic-jdk17` — HotSpot JDK 17 diagnostic CLI
- `{image}:{v}-diagnostic-jdk25` — HotSpot JDK 25 diagnostic CLI

Pin image digests for deployment. Diagnostic data can contain secrets; AI and live capture have the limits documented in the repository.
'''

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--tag',required=True);p.add_argument('--commit',required=True);p.add_argument('--image',required=True);p.add_argument('--out',required=True)
    a=p.parse_args();manifest=json.loads(pathlib.Path('dist/release.json').read_text())
    pathlib.Path(a.out).write_text(notes(a.tag,a.commit,a.image,manifest))
