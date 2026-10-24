import hashlib
import io
import json
import os
import pathlib
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
import release
import promote_images

COMMIT='a'*40
DATE='2026-10-24T00:00:00Z'

class ReleaseSafetyTests(unittest.TestCase):
    def test_action_pins_and_release_gates_cannot_be_silently_weakened(self):
        import re
        root=release.ROOT
        for path in (root/'.github/workflows').glob('*.yml'):
            source=path.read_text()
            self.assertNotIn('pull_request_target',source)
            self.assertNotIn('continue-on-error:',source)
            actions=re.findall(r'^\s*(?:-\s*)?uses:\s*(\S+)',source,re.M)
            self.assertTrue(actions,path.name+' has no verifiable Actions references')
            for action in actions:
                if not action.startswith('./'):
                    self.assertRegex(action,r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$')
        source=(root/'.github/workflows/release.yml').read_text()
        self.assertIn('needs: [metadata, verify, images]',source)
        publish=source.split('  publish:',1)[1]
        self.assertIn('group: release-publication',publish)
        self.assertIn('cancel-in-progress: false',publish)
        for name in ('Dockerfile','Dockerfile.diagnostic'):
            self.assertIn('golang:'+ (root/'.go-version').read_text().strip()+'-bookworm',(root/name).read_text())

    def test_semver_rejects_malformed_or_injectable_tags(self):
        for tag in ('3.0.0','v01.0.0','v1.02.0','v1.0.03','v1.0.0-01','v1.0.0-rc.01',
                    'v1.0.0+build','v1.0.0;echo bad','v1.0.0\n','v1.0.0-','v1.0.0-a..b'):
            with self.subTest(tag=tag),self.assertRaises(ValueError):release.version(tag)
        for tag in ('v0.0.0','v3.0.0','v3.1.0-rc.1','v3.1.0-2026a'):
            self.assertEqual(release.version(tag),tag[1:])

    def test_tag_requires_matching_source_version_and_changelog(self):
        current=(release.ROOT/'VERSION').read_text().strip()
        self.assertEqual(release.validate_tag('v'+current),current)
        with self.assertRaises(ValueError):release.validate_tag('v999999.0.0')

    def archive(self,directory,target,v='3.0.0',commit=COMMIT,extra=None,duplicate=False):
        binary='jvmdiag.exe' if target=='windows_amd64' else 'jvmdiag'
        data={name:b'notice' for name in release.FILES.values()}
        data[binary]=b'synthetic binary'
        data['buildinfo.json']=json.dumps({'version':v,'commit':commit,'buildDate':DATE,'platform':target,
            'binarySha256':hashlib.sha256(data[binary]).hexdigest()}).encode()
        if extra:data.update(extra)
        extension='.zip' if target=='windows_amd64' else '.tar.gz'
        path=pathlib.Path(directory)/f'jvmdiag_{v}_{target}{extension}'
        if extension=='.zip':
            with zipfile.ZipFile(path,'w') as z:
                for name,value in data.items():z.writestr(name,value)
        else:
            with tarfile.open(path,'w:gz') as tar:
                for name,value in data.items():
                    info=tarfile.TarInfo(name);info.size=len(value);tar.addfile(info,io.BytesIO(value))
                if duplicate:
                    info=tarfile.TarInfo(binary);info.size=1;tar.addfile(info,io.BytesIO(b'x'))
        path.with_name(path.name+'.sha256').write_text(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name+'\n')
        return path

    def test_archive_rejects_paths_duplicates_and_modified_binary(self):
        with tempfile.TemporaryDirectory() as temp:
            p=self.archive(temp,'linux_amd64',extra={'../outside':b'bad'})
            with self.assertRaises(ValueError):release.read_archive(p)
            p=self.archive(temp,'linux_amd64',duplicate=True)
            with self.assertRaises(ValueError):release.read_archive(p)
            p=self.archive(temp,'linux_amd64',extra={'buildinfo.json':json.dumps({'version':'3.0.0','platform':'linux_amd64','binarySha256':'0'*64}).encode()})
            with self.assertRaises(ValueError):release.read_archive(p)
            p=self.archive(temp,'windows_amd64',extra={'../outside.exe':b'bad'})
            with self.assertRaises(ValueError):release.read_archive(p)

    def test_archive_rejects_symlink_and_wrong_platform_filename(self):
        with tempfile.TemporaryDirectory() as temp:
            p=pathlib.Path(temp)/'jvmdiag_3.0.0_linux_amd64.tar.gz'
            with tarfile.open(p,'w:gz') as tar:
                info=tarfile.TarInfo('jvmdiag');info.type=tarfile.SYMTYPE;info.linkname='/etc/passwd';tar.addfile(info)
            with self.assertRaises(ValueError):release.read_archive(p)
            p=self.archive(temp,'linux_amd64');wrong=p.with_name('jvmdiag_3.0.0_linux_arm64.tar.gz');p.rename(wrong)
            with self.assertRaises(ValueError):release.read_archive(wrong)

    def test_collect_requires_complete_consistent_and_checksummed_archives(self):
        with tempfile.TemporaryDirectory() as temp:
            for target in release.PLATFORMS[:-1]:self.archive(temp,target)
            with self.assertRaises(ValueError):release.collect(temp)
            self.archive(temp,release.PLATFORMS[-1]);release.collect(temp)
            self.assertEqual(len((pathlib.Path(temp)/'SHA256SUMS').read_text().splitlines()),5)
            p=self.archive(temp,'linux_amd64',commit='b'*40)
            with self.assertRaises(ValueError):release.collect(temp)
            self.archive(temp,'linux_amd64');p.with_name(p.name+'.sha256').write_text('tampered')
            with self.assertRaises(ValueError):release.collect(temp)

    def candidates(self,temp):
        for variant in promote_images.VARIANTS:
            for i,arch in enumerate(('amd64','arm64')):
                (pathlib.Path(temp)/(variant+'-'+arch+'.json')).write_text(json.dumps({
                    'IMAGE':'ghcr.io/bishoku/jvmdiag','VERSION':'3.0.0','COMMIT':COMMIT,
                    'VARIANT':variant,'ARCH':arch,'digest':'sha256:'+str(i+1)*64}))

    def test_image_promotion_rejects_mixed_missing_and_invalid_candidates(self):
        with tempfile.TemporaryDirectory() as temp:
            self.candidates(temp);args=(temp,'ghcr.io/bishoku/jvmdiag','v3.0.0',COMMIT)
            self.assertEqual(len(promote_images.plan(*args)),3)
            p=pathlib.Path(temp)/'server-amd64.json';d=json.loads(p.read_text());d['COMMIT']='b'*40;p.write_text(json.dumps(d))
            with self.assertRaises(ValueError):promote_images.plan(*args)
            self.candidates(temp);p.unlink()
            with self.assertRaises(ValueError):promote_images.plan(*args)
            self.candidates(temp);d=json.loads(p.read_text());d['digest']='sha256:nope';p.write_text(json.dumps(d))
            with self.assertRaises(ValueError):promote_images.plan(*args)

    def test_prerelease_never_touches_stable_aliases(self):
        with tempfile.TemporaryDirectory() as temp:
            self.candidates(temp)
            for p in pathlib.Path(temp).glob('*.json'):
                d=json.loads(p.read_text());d['VERSION']='3.1.0-rc.1';p.write_text(json.dumps(d))
            with mock.patch.object(promote_images,'inspect',side_effect=AssertionError('registry access forbidden')),mock.patch.object(promote_images,'docker',side_effect=AssertionError('promotion forbidden')):
                promote_images.promote(temp,'ghcr.io/bishoku/jvmdiag','v3.1.0-rc.1',COMMIT,aliases=True)

    def test_failed_registry_authorization_is_not_treated_as_absent_tag(self):
        response=mock.Mock(returncode=1,stderr='unauthorized: denied',stdout='')
        with mock.patch.object(promote_images.subprocess,'run',return_value=response),self.assertRaises(RuntimeError):
            promote_images.inspect('ghcr.io/bishoku/jvmdiag:3.0.0')

    def test_promotion_refuses_to_replace_an_existing_version(self):
        with tempfile.TemporaryDirectory() as temp:
            self.candidates(temp)
            with mock.patch.object(promote_images,'inspect',return_value={'annotations':{'org.opencontainers.image.revision':'b'*40},'manifests':[]}),mock.patch.object(promote_images,'docker',side_effect=AssertionError('must not overwrite')),self.assertRaises(ValueError):
                promote_images.promote(temp,'ghcr.io/bishoku/jvmdiag','v3.0.0',COMMIT)

    def test_older_stable_release_cannot_downgrade_aliases(self):
        with tempfile.TemporaryDirectory() as temp:
            self.candidates(temp)
            existing={'annotations':{'org.opencontainers.image.version':'3.1.0'}}
            with mock.patch.object(promote_images,'inspect',return_value=existing),mock.patch.object(promote_images,'docker',side_effect=AssertionError('must not downgrade')):
                promote_images.promote(temp,'ghcr.io/bishoku/jvmdiag','v3.0.0',COMMIT,aliases=True)

if __name__=='__main__':unittest.main()
