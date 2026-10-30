"""Roll out the latest Fief build without replacing its production configuration."""
import json
import subprocess
import time

CLOUD='do-nyc1-k8s-1-33-1-do-1-nyc1-1752275240114'
NS='whitewhale'
NAME='opensensor-fief'


def kube(*args):
    return subprocess.check_output(['kubectl','--context',CLOUD,'-n',NS,*args],text=True,timeout=650)


def get(*args):return json.loads(kube('get',*args,'-o','json'))


def verify(deployment,pods,image,commit):
    spec,status=deployment['spec'],deployment.get('status',{})
    count=spec.get('replicas',0)
    if count<1 or status.get('observedGeneration',0)<deployment['metadata']['generation']:
        raise RuntimeError('Fief rollout not observed')
    if any(status.get(k,0)!=count for k in ('replicas','updatedReplicas','readyReplicas')):
        raise RuntimeError('Fief rollout not complete')
    if len(pods)!=count:raise RuntimeError('Old Fief pods remain')
    for pod in pods:
        if pod['metadata'].get('deletionTimestamp'):raise RuntimeError('Fief pod still terminating')
        if pod['metadata'].get('annotations',{}).get('opensensor.io/source-revision')!=commit:
            raise RuntimeError('Wrong Fief source revision')
        containers={c['name']:c for c in pod['spec']['containers']}
        statuses={c['name']:c for c in pod.get('status',{}).get('containerStatuses',[])}
        c=containers.get(NAME,{});s=statuses.get(NAME,{})
        if c.get('image')!=image or not s.get('ready') or not s.get('imageID','').endswith(image.split('@')[1]):
            raise RuntimeError('Fief actual running image differs from this build')


def deploy(target,directory):
    deployment=get('deployment',NAME)
    template=deployment['spec']['template']
    annotations=template.setdefault('metadata',{}).setdefault('annotations',{})
    current=int(annotations.get('opensensor.io/build-run','0'))
    if current>target['run_id']:raise RuntimeError('A newer Fief build is already deployed')
    annotations.update({'opensensor.io/source-revision':target['commit'],'opensensor.io/build-run':str(target['run_id'])})
    containers=template['spec']['containers']
    matches=[c for c in containers if c['name']==NAME]
    if len(matches)!=1:raise RuntimeError('Fief container identity changed')
    matches[0]['image']=target['image']
    patch=[{'op':'test','path':'/metadata/resourceVersion','value':deployment['metadata']['resourceVersion']},
           {'op':'replace','path':'/spec/template','value':template}]
    kube('patch','deployment',NAME,'--type=json','-p',json.dumps(patch))
    kube('rollout','status','deployment/'+NAME,'--timeout=600s')
    deadline=time.monotonic()+120
    while True:
        actual=get('deployment',NAME)
        selector=','.join(k+'='+v for k,v in actual['spec']['selector']['matchLabels'].items())
        try:verify(actual,get('pods','-l',selector)['items'],target['image'],target['commit']);break
        except RuntimeError:
            if time.monotonic()>=deadline:raise
            time.sleep(3)
    return {'production_ready':True}


def save_progress(path,state):
    temp=path.with_suffix('.tmp');temp.write_text(json.dumps(state));temp.replace(path)
