#!/usr/bin/env python3
"""Run the candidate image, without AI credentials or production JVMs."""
import argparse
import gzip
import json
import os
import pathlib
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT=pathlib.Path(__file__).resolve().parents[1]

def docker(*args):
    return subprocess.check_output(['docker',*args],text=True,timeout=120,stderr=subprocess.STDOUT)

def smoke(image,kind,version,expect_mat=False):
    output=docker('run','--rm','--network','none',image,'version')
    if 'jvmdiag version '+version not in output:raise ValueError('container version mismatch')
    config=json.loads(docker('image','inspect',image))[0]['Config']
    if config['User']!='10001:10001':raise ValueError('image must default to the documented non-root identity')
    if kind=='server':
        name='jvmdiag-smoke-'+uuid.uuid4().hex[:10]
        token='synthetic-smoke-admin-token-00000000000000'
        try:
            docker('run','-d','--name',name,'--cap-drop=ALL','--security-opt=no-new-privileges:true',
                   '-e','JVMDIAG_ADMIN_TOKEN='+token,'-e','JVMDIAG_WORKSPACE_TOKENS={"smoke":"synthetic-workspace-token-00000000000000"}',
                   '-p','127.0.0.1::8080',image)
            port=json.loads(docker('inspect',name))[0]['NetworkSettings']['Ports']['8080/tcp'][0]['HostPort']
            url='http://127.0.0.1:'+port
            deadline=time.monotonic()+30
            while True:
                try:
                    with urllib.request.urlopen(url,timeout=2) as r:
                        if r.status==200:break
                except (OSError,urllib.error.URLError):pass
                if time.monotonic()>deadline:raise ValueError('server never became ready: '+docker('logs',name))
                time.sleep(0.1) # condition-based readiness; never an assumed startup delay
            try:
                urllib.request.urlopen(url+'/api/settings',timeout=5)
                raise ValueError('shared API accepted unauthenticated access')
            except urllib.error.HTTPError as e:
                if e.code!=401:raise
            request=urllib.request.Request(url+'/api/settings',headers={'Authorization':'Bearer '+token})
            with urllib.request.urlopen(request,timeout=5) as r:
                if r.status!=200:raise ValueError('authenticated settings API failed')
            if expect_mat:
                request=urllib.request.Request(url+'/api/mat/status',headers={'Authorization':'Bearer '+token})
                with urllib.request.urlopen(request,timeout=5) as r:status=json.load(r)
                if not status.get('available') or status.get('scriptPath')!='/opt/mat/ParseHeapDump.sh':
                    raise ValueError('server did not discover bundled MAT: '+str(status))
        finally:
            subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
    else:
        docker('run','--rm','--network','none','--entrypoint','jcmd',image,'-h')
        with tempfile.TemporaryDirectory(prefix='jvmdiag-image-fixtures-') as temp:
            directory=pathlib.Path(temp);directory.chmod(0o755)
            for name in ('heap.hprof','recording.jfr','threads.txt'):
                path=directory/name
                path.write_bytes(gzip.decompress((ROOT/'tests/corpus/jvm-v1/temurin17-g1'/(name+'.gz')).read_bytes()))
                path.chmod(0o644)
                report=docker('run','--rm','--network','none','--cap-drop=ALL','--security-opt=no-new-privileges:true',
                              '-v',temp+':/fixtures:ro',image,'analyze','/fixtures/'+name,'--no-ai')
                if len(report)<100:raise ValueError('empty diagnostic report')
                if name=='recording.jfr' and 'jdk-jfr-cli' not in report:raise ValueError('binary JFR was not decoded by the bundled JDK')
    print('PASS: native image version, non-root runtime and '+('HTTP authentication' if kind=='server' else 'bundled JDK + actual HPROF/JFR/thread analysis'))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--image',required=True);p.add_argument('--kind',choices=['server','diagnostic'],required=True);p.add_argument('--version',required=True)
    p.add_argument('--expect-mat',action='store_true')
    a=p.parse_args();smoke(a.image,a.kind,a.version,a.expect_mat)
