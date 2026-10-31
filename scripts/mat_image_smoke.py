#!/usr/bin/env python3
"""Opt-in Docker test: bundled MAT performs real HPROF analysis without egress."""
import argparse
import gzip
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def smoke(image):
    with tempfile.TemporaryDirectory(prefix='jvmdiag-mat-smoke-') as temporary:
        directory = pathlib.Path(temporary)
        directory.chmod(0o755)
        fixture = directory / 'heap.hprof'
        fixture.write_bytes(gzip.decompress((ROOT / 'tests/corpus/jvm-v1/temurin17-g1/heap.hprof.gz').read_bytes()))
        fixture.chmod(0o644)
        # Exercise the standard image identity and the OpenShift-like identity.
        for identity in ('10001:10001', '1000710000:0'):
            command = ['docker', 'run', '--rm', '--network', 'none', '--read-only',
                       '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
                       '--user', identity, '--tmpfs', '/data:rw,mode=0777',
                       '--tmpfs', '/tmp:rw,mode=1777',
                       '-e', 'MAT_HEAP_SIZE=512m',
                       '-v', str(directory) + ':/fixtures:ro',
                       '--entrypoint', '/bin/sh', image, '-ec',
                       'test -x /opt/mat/MemoryAnalyzer; test -x /opt/mat/ParseHeapDump.sh; '
                       'cp /fixtures/heap.hprof /data/test.hprof; '
                       'jvmdiag analyze /data/test.hprof --deep-mat --no-ai']
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, timeout=180)
            if result.returncode or 'ECLIPSE MAT' not in result.stdout or 'MAT SECTION 1' not in result.stdout:
                raise RuntimeError(f'MAT analysis failed for {identity}:\n{result.stdout[-8000:]}')
            if 'Requested MAT analysis failed' in result.stdout or 'MAT is unavailable' in result.stdout:
                raise RuntimeError('MAT fallback was reported instead of successful deep analysis')
            print(f'PASS: real MAT HPROF report; no network; read-only image; UID/GID {identity}', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    smoke(parser.parse_args().image)
