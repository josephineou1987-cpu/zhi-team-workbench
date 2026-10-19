import json,urllib.request,urllib.error,getpass,uuid,concurrent.futures
BASE='https://khlvpcmfygqyakhzpoax.supabase.co/functions/v1/zhi-workbench'
password=getpass.getpass('Initial password: ')
def call(path,method='GET',body=None,token=None):
 h={'Content-Type':'application/json','Origin':'https://josephineou1987-cpu.github.io'}
 if token:h['Authorization']='Bearer '+token
 req=urllib.request.Request(BASE+path,data=None if body is None else json.dumps(body).encode(),headers=h,method=method)
 try:
  with urllib.request.urlopen(req,timeout=40) as r:return r.status,json.load(r)
 except urllib.error.HTTPError as e:return e.code,json.load(e)
def login(name):
 status,u=call('/auth/login','POST',{'name':name,'password':password});assert status==200,(name,status,u);return name,u
names=['吴权','杨瑞','李越洋','陈恒丽','曾飞','李若清','严钦佩','蒋云亭','欧欧','罗慧']
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:sessions=dict(pool.map(login,names))
print('All ten accounts verified; 吴权 resolves to David',flush=True)
assert sessions['吴权']['name']=='David'
assert call('/state')[0]==401
assert call('/auth/login','POST',{'name':'杨瑞','password':'wrong-password'})[0]==401
owner=sessions['杨瑞']['token'];admin=sessions['吴权']['token'];other=sessions['罗慧']['token'];testid='verification-'+str(uuid.uuid4())
record={'id':testid,'owner':'杨瑞','title':'Temporary connectivity verification','status':'未开始','project':'admin','due':'2026-10-19'}
def patch(before,after,token):return call('/state','PATCH',{'ops':[{'collection':'tasks','key':testid,'before':before,'after':after}]},token)
try:
 assert patch(None,record,owner)[0]==200
 assert any(x['id']==testid for x in call('/state',token=admin)[1]['data']['tasks'])
 assert all(x['id']!=testid for x in call('/state',token=other)[1]['data']['tasks'])
 assert patch(record,{**record,'title':'Unauthorized edit'},other)[0]==403
 owner2=login('杨瑞')[1]['token']
 assert any(x['id']==testid for x in call('/state',token=owner2)[1]['data']['tasks'])
 updated={**record,'status':'进行中'};assert patch(record,updated,owner2)[0]==200
 assert patch(record,{**record,'title':'Stale edit'},owner)[0]==409
 print('Persistent reads, second session, manager visibility, ownership checks, conflict checks passed',flush=True)
finally:
 data=call('/state',token=owner)[1]['data'];found=next((x for x in data['tasks'] if x['id']==testid),None)
 if found:assert patch(found,None,owner)[0]==200
 for u in sessions.values():call('/auth/logout','POST',{},u['token'])
print('Temporary record removed; test sessions revoked',flush=True)
