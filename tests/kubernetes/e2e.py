#!/usr/bin/env python3
"""Opt-in, real ephemeral-container tests. Runs against explicitly selected local kind or MicroK8s contexts."""
import argparse
import json
import pathlib
import subprocess
import tempfile
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('--kubeconfig', required=True)
p.add_argument('--kubectl', default='kubectl')
p.add_argument('--context', required=True)
p.add_argument('--allow-microk8s', action='store_true',
               help='Explicitly permit the microk8s context; creates/deletes only a unique test namespace')
p.add_argument('--allow-unrestricted-rbac', action='store_true',
               help='Report RBAC denial checks as skipped when cluster authorization is unrestricted')
p.add_argument('--results-dir', type=pathlib.Path,
               help='New directory for synthetic logs, Pod snapshots and copied artifacts')
p.add_argument('--image', default='jvmdiag-diagnostic:k8s-test')
p.add_argument('--fixture-image', default='jvmdiag-fixture:k8s-test')
a = p.parse_args()
if not (a.context.startswith('kind-') or (a.context == 'microk8s' and a.allow_microk8s)):
    p.error('select a kind context, or microk8s with --allow-microk8s')
if a.results_dir:
    a.results_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
ns = 'jvmdiag-test-' + uuid.uuid4().hex[:8]
base = [a.kubectl, '--kubeconfig', a.kubeconfig, '--context', a.context]

def k(*args, data=None, check=True, operator=False, timeout=150):
    cmd = base + (['--as=jvmdiag-test-operator', '--as-group=jvmdiag-operators'] if operator else []) + list(args)
    result = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'{args}: {result.stderr}\n{result.stdout}')
    return result

def pod(name, nmt=True, disabled=False, shared=False):
    command = ['java', '-Xms32m', '-Xmx64m', '-XX:ActiveProcessorCount=2']
    if nmt:
        command += ['-XX:NativeMemoryTracking=summary']
    if disabled:
        command += ['-XX:+DisableAttachMechanism']
    command += ['-cp', '/fixture', 'Fixture']
    spec = {'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':ns},'spec':{
        'automountServiceAccountToken':False, 'shareProcessNamespace':shared,
        'securityContext':{'runAsUser':10001,'runAsGroup':10001,'runAsNonRoot':True,
                           'seccompProfile':{'type':'RuntimeDefault'}},
        'containers':[{'name':'java','image':a.fixture_image,'imagePullPolicy':'Never','command':command,
            'resources':{'requests':{'cpu':'100m','memory':'128Mi'},'limits':{'cpu':'1','memory':'384Mi'}},
            'securityContext':{'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']}}}]}}
    k('apply','-f','-',data=json.dumps(spec))
    k('-n',ns,'wait','--for=condition=Ready','pod/'+name,'--timeout=90s')

def debug(podname, name, command, profile, expected=0, attach=False):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as f:
        json.dump(profile,f);f.flush()
        k('-n',ns,'debug',podname,'--target=java','--container='+name,'--image='+a.image,
          '--image-pull-policy=Never','--profile=restricted','--custom='+f.name,
          '--attach='+str(attach).lower(),'--stdin='+str(attach).lower(),'--',*command,
          data='done\n' if attach else None,operator=True)
    selector='{.status.ephemeralContainerStatuses[?(@.name=="'+name+'")].state.terminated}'
    k('-n',ns,'wait','--for=jsonpath='+selector,'pod/'+podname,'--timeout=120s')
    data=json.loads(k('-n',ns,'get','pod',podname,'-o','json').stdout)
    status=next(s for s in data['status']['ephemeralContainerStatuses'] if s['name']==name)
    log=k('-n',ns,'logs',podname,'-c',name,operator=True).stdout
    assert status['state']['terminated']['exitCode']==expected, (name,status,log)
    print(f'PASS: {podname}/{name} (exit {expected})', flush=True)
    if a.results_dir:
        (a.results_dir / f'{podname}-{name}.log').write_text(log)
        (a.results_dir / f'{podname}-{name}.json').write_text(json.dumps(data, indent=2))
    return log,data

profile=json.loads((ROOT/'deploy/kubernetes/profile-restricted.json').read_text())
try:
    k('create','namespace',ns)
    k('label','namespace',ns,'pod-security.kubernetes.io/enforce=restricted')
    rbac=(ROOT/'deploy/kubernetes/rbac.yaml').read_text().replace('namespace: jvmdiag-demo','namespace: '+ns)
    k('apply','-f','-',data=rbac)
    unrestricted = k('-n',ns,'auth','can-i','list','secrets',operator=True,check=False).stdout.strip() == 'yes'
    if unrestricted and not a.allow_unrestricted_rbac:
        raise RuntimeError('Cluster permits operator secret access; RBAC denial tests cannot pass. '
                           'Use --allow-unrestricted-rbac to explicitly skip denial checks.')
    if unrestricted:
        print('SKIP: RBAC denial enforcement (cluster permits operator secret access)', flush=True)
    for verb,resource,allowed in [('list','pods',True),('watch','pods',True),('patch','pods/ephemeralcontainers',True),('create','pods/exec',True),
                                  ('get','pods/log',True),('delete','pods',False),('list','secrets',False),('get','nodes',False)]:
        if unrestricted and not allowed:
            continue
        res, _, sub = resource.partition('/')
        auth_args = ['-n',ns,'auth','can-i',verb,res] + (['--subresource='+sub] if sub else [])
        result=k(*auth_args,operator=True,check=False)
        assert (result.stdout.strip()=='yes')==allowed,(verb,resource,result.stdout,result.stderr)
    pod('java')
    log,_=debug('java','discovery',['/bin/sh','-ec','jvmdiag ps; read -r response'],profile,attach=True)
    assert 'Fixture' in log,log
    # The target is a JRE; the debugger supplies jcmd, and mount namespaces differ.
    missing=k('-n',ns,'exec','java','-c','java','--','jcmd','-l',check=False)
    assert missing.returncode!=0,'fixture unexpectedly contains jcmd'
    log,_=debug('java','mount-check',['/bin/sh','-ec',
        'test ! -e /tmp/target-only-marker; test -e /proc/1/root/tmp/target-only-marker'],profile)
    log,data=debug('java','capture',['jvmdiag','capture','--pid','1','--container','--count','2',
        '--interval','1ms','--with-heap','--jfr-duration','2s','--timeout','90s','--out-dir','/tmp/result',
        '--out','/tmp/result/report.txt','--no-ai'],profile)
    assert data['status']['containerStatuses'][0].get('restartCount')==0,'target restarted'
    assert data['spec']['ephemeralContainers'][-1]['targetContainerName']=='java'
    # A completed ephemeral container cannot be exec'd. A helper with the same
    # target mount namespace cannot read the debugger's private output either.
    # A second invocation validates artifacts and emits its report before exiting.
    log,_=debug('java','capture-check',['/bin/sh','-ec',
        'jvmdiag capture --pid 1 --container --count 1 --with-heap --jfr-duration 1s '
        '--out-dir /tmp/checked --no-ai --out /tmp/checked/report.txt; '
        'test -s /tmp/checked/report.txt; test -s /tmp/checked/heap.hprof; '
        'test -s /tmp/checked/recording.jfr; test -s /tmp/checked/nmt_summary.txt; '
        'cat /tmp/checked/capture.json; cat /tmp/checked/report.txt'],profile)
    assert '"status": "complete"' in log and 'JFR' in log and 'Fixture' in log,log
    assert 'NMT Total Committed:' in log and 'Total Committed (RSS)' not in log,log
    log,_=debug('java','invalid-inputs',['/bin/sh','-ec',
        'jvmdiag capture --pid 1 --container --count 1 --capture-only --out-dir /tmp/validation; '
        'printf "not JVM diagnostic data" > /tmp/invalid.tdump; '
        'for kind in thread nmt; do '
        'if jvmdiag analyze /tmp/invalid.tdump --type "$kind" --no-ai > /tmp/rejected 2>&1; then '
        'cat /tmp/rejected; exit 1; fi; '
        'grep -q "Analysis failed" /tmp/rejected; cat /tmp/rejected; done; '
        'if jvmdiag incident --thread /tmp/validation/threaddump_1.txt,/tmp/missing.tdump '
        '--no-ai > /tmp/rejected 2>&1; then cat /tmp/rejected; exit 1; fi; '
        'grep -q "missing.tdump" /tmp/rejected; cat /tmp/rejected'],profile)
    # Exercise the documented live-container extraction path with operator exec/cp.
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as f:
        json.dump(profile,f);f.flush()
        k('-n',ns,'debug','java','--target=java','--container=export','--image='+a.image,
          '--image-pull-policy=Never','--profile=restricted','--custom='+f.name,
          '--','/bin/sleep','120',operator=True)
    k('-n',ns,'wait','--for=jsonpath={.status.ephemeralContainerStatuses[?(@.name=="export")].state.running}',
      'pod/java','--timeout=30s')
    k('-n',ns,'exec','java','-c','export','--','jvmdiag','capture','--pid','1','--container',
      '--count','1','--with-heap','--jfr-duration','1s','--out-dir','/tmp/exported','--out','/tmp/exported/report.txt','--no-ai',operator=True)
    with tempfile.TemporaryDirectory(prefix='jvmdiag-export-') as destination:
        k('-n',ns,'cp','-c','export','java:/tmp/exported',destination+'/capture',operator=True)
        exported=pathlib.Path(destination)/'capture'
        assert json.loads((exported/'capture.json').read_text())['status']=='complete'
        assert (exported/'report.txt').stat().st_size>0
        assert (exported/'heap.hprof').read_bytes().startswith(b'JAVA PROFILE ')
        assert (exported/'recording.jfr').read_bytes().startswith(b'FLR\0')
        assert (exported/'nmt_summary.txt').stat().st_size>0
        permissions=k('-n',ns,'exec','java','-c','export','--','stat','-c','%a',
                      '/tmp/exported','/tmp/exported/heap.hprof','/tmp/exported/recording.jfr',
                      '/tmp/exported/capture.json',operator=True).stdout.split()
        assert permissions==['700','600','600','600'],permissions
        if a.results_dir:
            import shutil
            shutil.copytree(exported, a.results_dir / 'exported')
    cleanup_check=k('-n',ns,'exec','java','-c','export','--','/bin/sh','-ec',
      'test -z "$(find /proc/1/root/tmp -maxdepth 1 -name \"jvmdiag-stage-*\" -print)"; '
      'test ! -L /tmp/.java_pid1; ln -s /proc/1/root/tmp/.java_pid1 /tmp/.java_pid1; '
      'trap \'rm -f /tmp/.java_pid1\' EXIT; jcmd 1 JFR.check',operator=True)
    assert 'No available recordings' in cleanup_check.stdout, cleanup_check.stdout
    print('PASS: artifact copy, private permissions, staging/bridge/JFR cleanup', flush=True)
    pod('shared-pid',shared=True)
    log,_=debug('shared-pid','discovery',['jvmdiag','ps'],profile)
    java_line=next(line for line in log.splitlines() if 'Fixture' in line)
    visible_pid=java_line.split()[0]
    assert visible_pid!='1','shared namespace did not expose the expected non-init Java PID'
    log,_=debug('shared-pid','capture',['jvmdiag','capture','--pid',visible_pid,'--container',
        '--count','1','--capture-only'],profile)
    assert '"status": "complete"' in log,log
    wrong=json.loads(json.dumps(profile));wrong['securityContext']['runAsUser']=10002
    log,_=debug('java','wrong-uid',['jvmdiag','capture','--pid','1','--container','--count','1'],wrong,expected=1)
    assert 'matching effective UID/GID' in log,log
    wrong=json.loads(json.dumps(profile));wrong['securityContext']['runAsGroup']=10002
    log,_=debug('java','wrong-gid',['jvmdiag','capture','--pid','1','--container','--count','1'],wrong,expected=1)
    assert 'matching effective UID/GID' in log,log
    log,_=debug('java','missing-pid',['jvmdiag','capture','--pid','999999','--container','--count','1'],profile,expected=1)
    assert 'not accessible' in log,log
    pod('no-nmt',nmt=False)
    log,_=debug('no-nmt','capture',['jvmdiag','capture','--pid','1','--container','--count','1','--capture-only'],profile)
    assert 'NMT unavailable' in log and '"status": "complete"' in log,log
    pod('attach-disabled',disabled=True)
    log,_=debug('attach-disabled','capture',['jvmdiag','capture','--pid','1','--container','--count','1',
        '--command-timeout','2s','--timeout','10s','--capture-only'],profile,expected=1)
    assert 'Live capture failed' in log and 'Partial artifacts' in log,log
    for name in ['java', 'shared-pid', 'no-nmt', 'attach-disabled']:
        state=json.loads(k('-n',ns,'get','pod',name,'-o','json').stdout)
        assert state['status']['containerStatuses'][0]['restartCount']==0, (name, 'target restarted')
    print('PASS: restricted namespace; operator allowed operations; proc discovery; separate mount namespaces; JRE target; thread/heap/JFR/NMT analysis; operator artifact copy; non-init shared PID; no target restart; UID/PID/attach failures; missing NMT')
finally:
    deleted=k('delete','namespace',ns,'--wait=true','--timeout=60s',check=False,timeout=70)
    if deleted.returncode:
        raise RuntimeError(f'Failed to clean test namespace {ns}: {deleted.stderr}')
    print(f'CLEANUP: deleted namespace {ns}', flush=True)
