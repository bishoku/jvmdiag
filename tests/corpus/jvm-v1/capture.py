#!/usr/bin/env python3
"""Capture a private synthetic JVM and build independent reference counts. No Go parser is invoked."""
import argparse, collections, datetime, getpass, gzip, hashlib, json, os, pathlib, re, shutil, struct, subprocess, tempfile

EVENTS = ','.join(['jdk.ExecutionSample','jdk.NativeMethodSample','jdk.ObjectAllocationInNewTLAB','jdk.ObjectAllocationOutsideTLAB','jdk.ObjectAllocationSample','jdk.JavaMonitorEnter','jdk.VirtualThreadPinned','jdk.GarbageCollection','jdk.GCPhasePause','jdk.SocketRead','jdk.FileRead'])
COLLECTORS = {'g1':'UseG1GC', 'parallel':'UseParallelGC', 'serial':'UseSerialGC', 'zgc':'UseZGC'}
ROOT = pathlib.Path(__file__).resolve().parents[2]

def run(args, env, **kw):
    return subprocess.run([str(a) for a in args], env=env, check=True, capture_output=True, timeout=60, **kw).stdout

def heap_reference(data):
    # Independent format audit; counts raw INSTANCE/ARRAY records and payload lengths, never runtime heap.
    pos=data.index(b'\0')+1; size=struct.unpack_from('>I',data,pos)[0]; pos+=12
    assert size in (4,8)
    counts=collections.Counter(); roots=collections.Counter(); payload=0; duplicates=0
    def u2(p): return struct.unpack_from('>H',data,p)[0]
    def u4(p): return struct.unpack_from('>I',data,p)[0]
    def value_width(t): return {2:size,4:1,5:2,6:4,7:8,8:1,9:2,10:4,11:8}[t]
    root_width={0xff:size,1:size*2,2:size+8,3:size+8,4:size+4,5:size,6:size+4,7:size,8:size+8}
    while pos<len(data):
        tag=data[pos]; length=u4(pos+5); pos+=9; end=pos+length; assert end<=len(data)
        if tag in (0x0c,0x1c):
            while pos<end:
                kind=data[pos]; pos+=1
                if kind in root_width: roots[str(kind)]+=1; pos+=root_width[kind]
                elif kind==0x20:
                    pos+=size+4+size*6+4
                    n=u2(pos); pos+=2
                    for _ in range(n): t=data[pos+2]; pos+=3+value_width(t)
                    n=u2(pos); pos+=2
                    for _ in range(n): t=data[pos+size]; pos+=size+1+value_width(t)
                    n=u2(pos); pos+=2+n*(size+1)
                elif kind==0x21:
                    pos+=size+4+size; n=u4(pos); pos+=4+n; counts['instances']+=1; payload+=n
                elif kind==0x22:
                    pos+=size+4; n=u4(pos); pos+=4+size+n*size; counts['objectArrays']+=1; payload+=n*size
                elif kind==0x23:
                    pos+=size+4; n=u4(pos); t=data[pos+4]; pos+=5; n*=value_width(t)
                    raw=data[pos:pos+n]; pos+=n; counts['primitiveArrays']+=1; payload+=n
                    if t==8 and raw==b'jvmdiag-fixture-array-content-2026': duplicates+=1
                else: raise ValueError(f'Unknown heap tag {kind:#x}')
                assert pos<=end
            assert pos==end
        else: pos=end
    return {'payloadBytes':payload,'records':sum(counts.values()),'recordKinds':dict(sorted(counts.items())),'rootTags':dict(sorted(roots.items())),'markerArrays':duplicates,'identifierBytes':size}

def duration(value):
    if isinstance(value,(int,float)): return value/1e6
    m=re.fullmatch(r'PT(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?',value)
    assert m and any(m.groups()),value
    return sum(float(x or 0)*f for x,f in zip(m.groups(),(3600000,60000,1000)))

def reference(files):
    events=json.loads(files['events.json'])['recording']['events']; counts=collections.Counter(e['type'] for e in events)
    pause=[]; cycle=[]; allocated=collections.Counter(); tlab=0
    for event in events:
        name=event['type'];v=event['values']
        if name=='jdk.GarbageCollection':
            if 'duration' in v: cycle.append(duration(v['duration']))
            if 'longestPause' in v: pause.append(duration(v['longestPause']))
        if name=='jdk.GCPhasePause' and 'duration' in v: pause.append(duration(v['duration']))
        field='weight' if name=='jdk.ObjectAllocationSample' else 'allocationSize'
        if name.startswith('jdk.ObjectAllocation') and field in v: allocated[name]+=v[field]
        if name=='jdk.ObjectAllocationInNewTLAB': tlab+=v.get('tlabSize',0)
    # Independent GC oracle counts terminal pause lines, not start lines or concurrent cycle durations.
    pauses=[]
    for line in files['gc.log'].decode().splitlines():
        m=re.search(r'\bPause .+? ([0-9]+(?:\.[0-9]+)?)ms\s*$',line)
        if m: pauses.append(float(m[1]))
    text=files['threads.txt'].decode();states=collections.Counter()
    sections=re.split(r'^"',text,flags=re.M)[1:]
    for section in sections:
        state=re.search(r'^\s*java.lang.Thread.State:\s+(\S+)',section,re.M)
        states[state[1] if state else 'JVM_INTERNAL']+=1
    return {'heap':heap_reference(files['heap.hprof']), 'jfr':{'counts':dict(sorted(counts.items())),'total':len(events),'maxPauseMs':max(pause,default=0),'maxCycleMs':max(cycle,default=0),'allocationBytesByEvent':dict(sorted(allocated.items())),'tlabReservedBytes':tlab},'gc':{'pauseCount':len(pauses),'totalPauseMs':sum(pauses),'maxPauseMs':max(pauses,default=0)},'threads':{'total':len(sections),'states':dict(sorted(states.items())),'blockedName':'fixture-blocked'}}

def redact(data):
    # Byte-width-preserving replacement of operator home/name, including UTF-16. Record lengths stay intact.
    needles=[str(pathlib.Path.home()), getpass.getuser()]
    for text in sorted(set(needles),key=len,reverse=True):
        if len(text)<3: continue
        for encoding in ('utf-8','utf-16-be','utf-16-le'):
            old=text.encode(encoding); new=('x'*len(text)).encode(encoding)
            assert len(old)==len(new)
            data=data.replace(old,new)
    return data

def capture(jdk,label,gc,output):
    with tempfile.TemporaryDirectory(prefix='jvmdiag-reference-') as raw:
        work=pathlib.Path(raw)
        # Whitelist child environment; inherited JAVA_TOOL_OPTIONS/JFR/CLASSPATH/proxy secrets are never injected.
        env={'PATH':str(jdk/'bin')+os.pathsep+os.defpath,'HOME':str(work),'TMPDIR':str(work),'LANG':'C','LC_ALL':'C','TZ':'UTC'}
        version=run([jdk/'bin/java','-version'],env) if False else subprocess.run([str(jdk/'bin/java'),'-version'],env=env,capture_output=True,check=True,timeout=15).stderr.decode()
        run([jdk/'bin/javac','--release','17','-d',work,ROOT/'tests/fixtures/GenerateDiagnostics.java'],env)
        flags=['-Xms64m','-Xmx128m','-XX:ActiveProcessorCount=2','-XX:NativeMemoryTracking=summary','-XX:+'+COLLECTORS[gc],'-Xlog:gc*:file='+str(work/'gc.log')+':uptime,level,tags','-Duser.name=fixture','-Duser.home=/fixture','-Djava.io.tmpdir='+str(work)]
        proc=subprocess.Popen([str(jdk/'bin/java'),*flags,'-cp',str(work),'GenerateDiagnostics',str(work),'capture'],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        # communicate is bounded by a controller timeout even if fixture setup fails.
        import selectors, time
        selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ)
        ready=False; deadline=time.monotonic()+45
        try:
            while time.monotonic()<deadline:
                if not selector.select(timeout=1):
                    if proc.poll() is not None: break
                    continue
                line=proc.stdout.readline()
                if line.startswith(b'READY '): ready=True;break
                if not line: break
            if not ready: raise RuntimeError('fixture failed to become ready: '+proc.stderr.read().decode() if proc.poll() is not None else 'fixture readiness timeout')
            (work/'threads.txt').write_bytes(run([jdk/'bin/jcmd',str(proc.pid),'Thread.print','-l'],env))
            (work/'nmt.txt').write_bytes(run([jdk/'bin/jcmd',str(proc.pid),'VM.native_memory','summary'],env))
            proc.communicate(b'\n',timeout=15)
            if proc.returncode: raise RuntimeError('synthetic JVM exited unsuccessfully')
        finally:
            selector.close()
            if proc.poll() is None: proc.kill();proc.communicate(timeout=5)
        (work/'events.json').write_bytes(run([jdk/'bin/jfr','print','--json','--stack-depth','8','--events',EVENTS,work/'recording.jfr'],env))
        (work/'summary.txt').write_bytes(run([jdk/'bin/jfr','summary',work/'recording.jfr'],env))
        names=['heap.hprof','recording.jfr','events.json','gc.log','threads.txt','nmt.txt','summary.txt']
        original={name:(work/name).read_bytes() for name in names}
        files={name:redact(data) for name,data in original.items()}
        expected=reference(files)
        assert expected['heap']['markerArrays']>=10 and expected['jfr']['total']>0 and expected['gc']['pauseCount']>0
        key=label+'-'+gc;dest=output/key
        if dest.exists(): raise RuntimeError('refusing to overwrite '+str(dest))
        dest.mkdir(parents=True)
        artifacts={}
        for name,data in files.items():
            stored=gzip.compress(data,compresslevel=9,mtime=0);(dest/(name+'.gz')).write_bytes(stored)
            artifacts[name]={'file':name+'.gz','sha256':hashlib.sha256(data).hexdigest(),'compressedSha256':hashlib.sha256(stored).hexdigest(),'bytes':len(data),'originalSha256':hashlib.sha256(original[name]).hexdigest()}
        runtime=(work/'runtime.txt').read_text().splitlines()
        return {'id':key,'jdk':runtime[0],'vendor':runtime[1],'platform':runtime[2],'gc':gc,'actualCollectors':runtime[3:],'javaVersionOutput':version,'flags':[f.replace(str(work),'<capture-dir>') for f in flags],'source':'fresh synthetic JVM; JDK jcmd/jfr outputs; byte-width-preserving operator identity redaction','artifacts':artifacts,'expected':expected}

def main():
    p=argparse.ArgumentParser();p.add_argument('--jdk',action='append',required=True,help='label=/absolute/jdk/home');p.add_argument('--collectors',default=','.join(COLLECTORS));p.add_argument('--out',type=pathlib.Path,required=True);args=p.parse_args()
    args.out.mkdir(parents=True,exist_ok=True)
    if (args.out/'manifest.json').exists(): raise SystemExit('refusing to overwrite a committed manifest; capture into a new directory and review')
    entries=[]
    for spec in args.jdk:
        label,home=spec.split('=',1)
        if not re.fullmatch('[a-z0-9-]+',label): raise SystemExit('invalid JDK label')
        jdk=pathlib.Path(home).resolve()
        for gc in args.collectors.split(','):
            if gc not in COLLECTORS: raise SystemExit('unknown collector '+gc)
            print('Capturing '+label+'/'+gc,flush=True)
            entries.append(capture(jdk,label,gc,args.out))
    manifest={'schemaVersion':1,'capturedAtUTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'generatorSha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'workloadSha256':hashlib.sha256((ROOT/'tests/fixtures/GenerateDiagnostics.java').read_bytes()).hexdigest(),'events':EVENTS,'normalization':'Source recordings are immutable captures, not reproducible executions. Capture timestamps, IDs and sampling differ on recapture. Only operator identity is redacted with equal-width bytes. Gzip mtime=0. Expected values come from independent Python extraction, not the Go analyzers.','entries':entries}
    (args.out/'manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    print('Captured '+str(len(entries))+' matrix entries',flush=True)
if __name__=='__main__': main()
