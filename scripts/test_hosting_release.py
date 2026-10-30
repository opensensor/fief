import copy
import unittest
import hosting_release as agent
from hosting_runtime import verify,NAME
from hosting_release_manifest import platform_digest

IMAGE='ghcr.io/opensensor/fief@sha256:'+'a'*64
COMMIT='b'*40
TARGET=dict(format='fief-release-v1',repository=agent.REPO,commit=COMMIT,run_id=100,run_attempt=1,image=IMAGE)
WORKFLOW=dict(event='push',head_branch='main',path=agent.WORKFLOW,repository={'full_name':agent.REPO},head_sha=COMMIT,id=100,run_attempt=1)

class ReleaseTests(unittest.TestCase):
    def test_release_belongs_to_main_build(self):
        self.assertEqual(agent.validate(TARGET,WORKFLOW),TARGET)
        for key,value in [('run_id',99),('run_attempt',2),('image','ghcr.io/opensensor/fief:latest')]:
            with self.subTest(key=key),self.assertRaises(ValueError):agent.validate({**TARGET,key:value},WORKFLOW)
        with self.assertRaises(ValueError):agent.validate(TARGET,{**WORKFLOW,'event':'pull_request'})
    def test_older_build_cannot_replace_newer_build(self):
        with self.assertRaises(RuntimeError):agent.choose({},TARGET,{**TARGET,'run_id':101,'state':'success'})
    def test_ready_old_image_is_rejected(self):
        deployment={'metadata':{'generation':1},'spec':{'replicas':1},'status':{'observedGeneration':1,'replicas':1,'updatedReplicas':1,'readyReplicas':1}}
        pod={'metadata':{'annotations':{'opensensor.io/source-revision':COMMIT}},'spec':{'containers':[{'name':NAME,'image':IMAGE}]},'status':{'containerStatuses':[{'name':NAME,'ready':True,'imageID':IMAGE}]}}
        verify(deployment,[pod],IMAGE,COMMIT)
        old=copy.deepcopy(pod);old['status']['containerStatuses'][0]['imageID']='old'
        with self.assertRaises(RuntimeError):verify(deployment,[old],IMAGE,COMMIT)
        with self.assertRaises(RuntimeError):verify(deployment,[pod,old],IMAGE,COMMIT)
    def test_platform_digest_excludes_attestation(self):
        doc={'manifests':[{'platform':{'os':'unknown','architecture':'unknown'},'digest':'other'},
            {'platform':{'os':'linux','architecture':'amd64'},'digest':'runtime'}]}
        self.assertEqual(platform_digest(doc,'index'),'runtime')

if __name__=='__main__':unittest.main()
