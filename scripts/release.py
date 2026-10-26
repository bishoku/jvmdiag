#!/usr/bin/env python3
"""Deterministic release packaging and native archive smoke tests; standard library only."""
import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import pathlib
import platform
import re
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLATFORMS = ('linux_amd64', 'linux_arm64', 'darwin_amd64', 'darwin_arm64', 'windows_amd64')
FILES = {'LICENSE':'LICENSE', 'NOTICE':'NOTICE', 'LICENSE-Go.txt':'LICENSE-Go.txt', 'README.md':'README.md', 'THIRD_PARTY_NOTICES.md':'THIRD_PARTY_NOTICES.md',
         'internal/server/assets/js/LICENSE.marked.txt':'LICENSE.marked.txt',
         'docs/INSTALL.md':'docs/INSTALL.md', 'docs/RELEASING.md':'docs/RELEASING.md',
         'CONTRIBUTING.md':'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md':'CODE_OF_CONDUCT.md',
         'SECURITY.md':'SECURITY.md', 'CHANGELOG.md':'CHANGELOG.md',
         'deploy/kubernetes/README.md':'deploy/kubernetes/README.md',
         'deploy/kubernetes/rbac.yaml':'deploy/kubernetes/rbac.yaml',
         'deploy/kubernetes/profile-restricted.json':'deploy/kubernetes/profile-restricted.json'}
for directory in ('docs', 'deploy'):
    for path in (ROOT / directory).rglob('*'):
        if path.is_file():
            relative = path.relative_to(ROOT).as_posix()
            FILES[relative] = relative

SEMVER = re.compile(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z')

def version(tag):
    m = SEMVER.fullmatch(tag)
    if not m or (m[4] and any(x.isdigit() and len(x)>1 and x[0]=='0' for x in m[4].split('.'))):
        raise ValueError('expected vMAJOR.MINOR.PATCH with optional SemVer prerelease; no build metadata')
    return tag[1:]

def validate_tag(tag):
    v = version(tag)
    major=int(v.split('.')[0])
    expected='github.com/bishoku/jvmdiag'+('/v'+str(major) if major>=2 else '')
    module=(ROOT/'go.mod').read_text().splitlines()[0].split()[1]
    if module!=expected:raise ValueError('Go module path must match the release major version')
    if (ROOT/'VERSION').read_text().strip()!=v:
        raise ValueError('tag must match VERSION exactly')
    notes = (ROOT/'CHANGELOG.md').read_text()
    if not re.search(r'^## \['+re.escape(v)+r'\](?:\s|$)', notes, re.M):
        raise ValueError('CHANGELOG.md must contain a section for this version')
    return v

def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, timeout=180, **kwargs)

def build(tag, target, output, commit, date):
    v = version(tag)
    if target not in PLATFORMS:
        raise ValueError('unsupported platform')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('commit must be a full lowercase SHA-1')
    timestamp = dt.datetime.strptime(date,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.timezone.utc)
    epoch = int(timestamp.timestamp())
    goos, goarch = target.split('_')
    executable = 'jvmdiag.exe' if goos=='windows' else 'jvmdiag'
    ext = '.zip' if goos=='windows' else '.tar.gz'
    output = pathlib.Path(output);output.mkdir(parents=True,exist_ok=True)
    archive = output/f'jvmdiag_{v}_{target}{ext}'
    if archive.exists():
        raise ValueError('refusing to overwrite archive')
    env = dict(os.environ,GOOS=goos,GOARCH=goarch,CGO_ENABLED='0',SOURCE_DATE_EPOCH=str(epoch))
    with tempfile.TemporaryDirectory(prefix='jvmdiag-build-') as temp:
        binary = pathlib.Path(temp)/executable
        run(['go','build','-trimpath','-buildvcs=false','-ldflags',
             f'-s -w -buildid= -X main.version={v} -X main.commit={commit} -X main.buildDate={date}',
             '-o',binary,'./cmd/jvmdiag'],cwd=ROOT,env=env)
        data = {name:(ROOT/src).read_bytes() for src,name in FILES.items()}
        data[executable]=binary.read_bytes()
        metadata = {'version':v,'commit':commit,'buildDate':date,'platform':target,
                    'goVersion':subprocess.check_output(['go','version'],text=True).split()[2],
                    'binarySha256':hashlib.sha256(data[executable]).hexdigest()}
        data['buildinfo.json']=(json.dumps(metadata,sort_keys=True,indent=2)+'\n').encode()
        if goos=='windows':
            with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
                for name in sorted(data):
                    info=zipfile.ZipInfo(name,timestamp.timetuple()[:6]);info.create_system=3
                    info.external_attr=(0o100755 if name==executable else 0o100644)<<16
                    info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,data[name])
        else:
            with archive.open('xb') as f, gzip.GzipFile(filename='',fileobj=f,mode='wb',mtime=epoch,compresslevel=9) as gz, tarfile.open(fileobj=gz,mode='w',format=tarfile.USTAR_FORMAT) as tar:
                for name in sorted(data):
                    info=tarfile.TarInfo(name);info.size=len(data[name]);info.mtime=epoch
                    info.mode=0o755 if name==executable else 0o644
                    info.uid=info.gid=0;info.uname=info.gname=''
                    tar.addfile(info,io.BytesIO(data[name]))
    archive.with_name(archive.name+'.sha256').write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
    return archive

def read_archive(archive):
    archive=pathlib.Path(archive)
    if archive.suffix=='.zip':
        with zipfile.ZipFile(archive) as z:
            names=z.namelist()
            if len(names)!=len(set(names)):
                raise ValueError('duplicate archive member')
            data={name:z.read(name) for name in names}
    else:
        with tarfile.open(archive,'r:gz') as tar:
            members=tar.getmembers();names=[m.name for m in members]
            if any(not m.isfile() for m in members) or len(names)!=len(set(names)):
                raise ValueError('non-regular or duplicate archive member')
            data={m.name:tar.extractfile(m).read() for m in members}
    executable='jvmdiag.exe' if 'jvmdiag.exe' in data else 'jvmdiag'
    if set(data)!=set(FILES.values())|{executable,'buildinfo.json'}:
        raise ValueError('unexpected archive contents')
    metadata=json.loads(data['buildinfo.json'])
    v=version('v'+metadata['version'])
    target=metadata['platform']
    if target not in PLATFORMS:raise ValueError('unknown archive platform')
    expected_executable='jvmdiag.exe' if target.startswith('windows_') else 'jvmdiag'
    suffix='.zip' if target.startswith('windows_') else '.tar.gz'
    if executable!=expected_executable or archive.name!=f'jvmdiag_{v}_{target}{suffix}':
        raise ValueError('archive filename/platform mismatch')
    if hashlib.sha256(data[executable]).hexdigest()!=metadata['binarySha256']:
        raise ValueError('binary digest mismatch')
    return data,metadata,executable

def smoke(archive):
    archive=pathlib.Path(archive)
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    if archive.with_name(archive.name+'.sha256').read_text()!=digest+'  '+archive.name+'\n':
        raise ValueError('archive checksum mismatch')
    data,metadata,executable=read_archive(archive)
    machine={'x86_64':'amd64','amd64':'amd64','arm64':'arm64','aarch64':'arm64'}[platform.machine().lower()]
    host=platform.system().lower()+'_'+machine
    if host!=metadata['platform']:
        raise ValueError(f'native smoke must run on {metadata["platform"]}, actual host is {host}')
    with tempfile.TemporaryDirectory(prefix='jvmdiag-install-') as temp:
        home=pathlib.Path(temp);binary=home/executable;binary.write_bytes(data[executable]);binary.chmod(0o755)
        env={key:os.environ[key] for key in ('PATH','SystemRoot','SYSTEMROOT','WINDIR','COMSPEC','PATHEXT') if key in os.environ}
        env.update(HOME=temp,USERPROFILE=temp,TMPDIR=temp,TEMP=temp,TMP=temp)
        result=subprocess.check_output([binary,'version'],env=env,cwd=home,text=True,timeout=15)
        for expected in ('jvmdiag version '+metadata['version'],metadata['commit'],metadata['buildDate']):
            if expected not in result:raise ValueError('embedded version metadata mismatch')
        fixture=ROOT/'tests/corpus/jvm-v1/temurin17-g1/threads.txt.gz'
        path=home/'threads.txt';path.write_bytes(gzip.decompress(fixture.read_bytes()))
        result=subprocess.check_output([binary,'analyze',path,'--type','thread','--no-ai'],env=env,cwd=home,text=True,timeout=30)
        if 'fixture-blocked' not in result:raise ValueError('installed binary failed real thread-dump regression')
    print('PASS: archive checksum, safe contents, embedded metadata and installed native JVM analysis')

def collect(directory):
    directory=pathlib.Path(directory)
    archives=sorted(list(directory.glob('*.tar.gz'))+list(directory.glob('*.zip')))
    if len(archives)!=len(PLATFORMS):raise ValueError('release must contain exactly all supported platform archives')
    seen=set();identities=set();lines=[]
    for archive in archives:
        _,meta,_=read_archive(archive);seen.add(meta['platform']);identities.add((meta['version'],meta['commit'],meta['buildDate']))
        line=hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n'
        if archive.with_name(archive.name+'.sha256').read_text()!=line:raise ValueError('sidecar digest mismatch')
        lines.append(line)
    if seen!=set(PLATFORMS) or len(identities)!=1:raise ValueError('mixed or incomplete release')
    (directory/'SHA256SUMS').write_text(''.join(lines))
    v,commit,date=identities.pop()
    (directory/'release.json').write_text(json.dumps({'version':v,'commit':commit,'buildDate':date,'platforms':sorted(seen)},indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
    v=sub.add_parser('validate');v.add_argument('tag')
    b=sub.add_parser('build');b.add_argument('--version',required=True);b.add_argument('--platform',choices=PLATFORMS,required=True)
    b.add_argument('--out',required=True);b.add_argument('--commit',required=True);b.add_argument('--date',required=True)
    s=sub.add_parser('smoke');s.add_argument('archive')
    c=sub.add_parser('collect');c.add_argument('directory')
    a=p.parse_args()
    if a.command=='validate':print(validate_tag(a.tag))
    elif a.command=='build':print(build(a.version,a.platform,a.out,a.commit,a.date))
    elif a.command=='smoke':smoke(a.archive)
    else:collect(a.directory)
