#!/usr/bin/env python3
"""Promote tested native digests; never rebuild images during publication."""
import argparse
import json
import os
import pathlib
import re
import subprocess
from release import version

VARIANTS={'server':'', 'diagnostic17':'-diagnostic-jdk17', 'diagnostic25':'-diagnostic-jdk25'}
ALIASES={'server':'latest','diagnostic17':'diagnostic-jdk17','diagnostic25':'diagnostic-jdk25'}

def plan(directory,image,tag,commit):
    v=version(tag)
    if not re.fullmatch(r'ghcr\.io/[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*',image):raise ValueError('unexpected registry/repository')
    if not re.fullmatch('[0-9a-f]{40}',commit):raise ValueError('invalid source commit')
    result={key:{} for key in VARIANTS}
    files=list(pathlib.Path(directory).glob('*.json'))
    if len(files)!=6:raise ValueError('exactly six native image manifests are required')
    for path in files:
        d=json.loads(path.read_text())
        if d['IMAGE']!=image or d['VERSION']!=v or d['COMMIT']!=commit:raise ValueError('mixed release image provenance')
        variant,arch=d['VARIANT'],d['ARCH']
        if variant not in result or arch not in ('amd64','arm64') or arch in result[variant]:raise ValueError('unexpected or duplicate native image')
        if not re.fullmatch('sha256:[0-9a-f]{64}',d['digest']):raise ValueError('invalid digest')
        result[variant][arch]=d['digest']
    if any(set(images)!=set(('amd64','arm64')) for images in result.values()):raise ValueError('incomplete architecture set')
    return result

def docker(*args):
    return subprocess.check_output(['docker','buildx','imagetools',*args],text=True,timeout=120)

def inspect(reference):
    p=subprocess.run(['docker','buildx','imagetools','inspect',reference,'--raw'],capture_output=True,text=True,timeout=60)
    if p.returncode:
        if any(x in p.stderr.lower() for x in ('not found','manifest unknown','no such manifest','name unknown')):return None
        raise RuntimeError(p.stderr)
    return json.loads(p.stdout)

def digest(reference):
    d=json.loads(docker('inspect',reference,'--format','{{json .Manifest}}'))['digest']
    if not re.fullmatch('sha256:[0-9a-f]{64}',d):raise ValueError('registry returned invalid digest')
    return d

def output(key,value):
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'],'a') as f:f.write(key+'='+value+'\n')

def promote(directory,image,tag,commit,aliases=False):
    images=plan(directory,image,tag,commit);v=version(tag)
    if aliases and '-' in v:
        output('latest','false');print('Prerelease: stable aliases unchanged');return
    newest=True
    for variant,sources in images.items():
        reference=image+':'+v+VARIANTS[variant]
        if not aliases:
            existing=inspect(reference)
            if existing is not None:
                annotations=existing.get('annotations',{})
                observed={m['digest'] for m in existing.get('manifests',[])}
                if annotations.get('org.opencontainers.image.revision')!=commit or observed!=set(sources.values()):
                    raise ValueError('refusing to replace an existing version tag with different image contents: '+reference)
            else:
                docker('create','--annotation','index:org.opencontainers.image.version='+v,
                       '--annotation','index:org.opencontainers.image.revision='+commit,
                       '--tag',reference,*[image+'@'+sources[a] for a in ('amd64','arm64')])
            output(variant,digest(reference))
        else:
            alias=image+':'+ALIASES[variant]
            existing=inspect(alias)
            if existing is not None:
                previous=existing.get('annotations',{}).get('org.opencontainers.image.version')
                if previous is None:raise ValueError('cannot verify stable alias version: '+alias)
                previous=version('v'+previous)
                if '-' not in previous and tuple(map(int,previous.split('.')))>tuple(map(int,v.split('.'))):
                    newest=False;continue # A maintenance release must not downgrade stable channels.
            docker('create','--tag',alias,image+'@'+digest(reference))
    if aliases:output('latest',str(newest).lower())
    print('Validated and promoted tested image digests')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--directory',required=True);p.add_argument('--image',required=True)
    p.add_argument('--tag',required=True);p.add_argument('--commit',required=True);p.add_argument('--aliases',action='store_true')
    a=p.parse_args();promote(a.directory,a.image,a.tag,a.commit,a.aliases)
