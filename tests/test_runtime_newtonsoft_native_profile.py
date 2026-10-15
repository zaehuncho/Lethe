"""V4 finite two-family NI contract; no compiler/debugger/fixture launch."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import copy,hashlib,json,os,struct
import pytest
from lifter import runtime_coff_compile as r
from lifter import runtime_compiler_trace as t
pytestmark=pytest.mark.skipif(os.name!='nt',reason='closed Win64 profile')
T=Path(r'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64')
SDK=Path(r'C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0')
RNI=Path(r'C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.V8f370856#\c4c9d7fd5bf04be34be80f649b419ccd\Microsoft.VisualStudio.RemoteControl.ni.dll')
NNI=Path(r'C:\Windows\assembly\NativeImages_v4.0.30319_64\Newtonsoft.Json\e7031ee81a19ccb1f96401fa814a55d6\Newtonsoft.Json.ni.dll')
RIL=T/'Microsoft.VisualStudio.RemoteControl.dll';NIL=T/'Newtonsoft.Json.dll'
RSHA='6bd9b8b7fc3ba9e0f3efee4532aa9f8fa6d32f25bbaca0fd8db2b640d19ecd2d'
NSHA='d3915a402322ea1b5d855cf88ffd40af05611d112728566565cf6b13230a6db5'
RISHA='cc52e19735d6152702672feb5911c8ba77f60fdc73df5ed0d601b37415f3a7ed'
NISHA='a4096c8ab7c4dc5c21485b43f81b8f87699b748d39c4c24dc5dab6df61111219'
V3='msvc-14.44.35207-sdk-10.0.26100.0-raw-v3';V4='msvc-14.44.35207-sdk-10.0.26100.0-raw-v4'
def need(v,m='contract failed'):
    if not v:raise AssertionError(m)
def forbidden(*a,**k):raise AssertionError('unexpected I/O or process effect')
def inputs():
    h=SDK/'ucrt/stdio.h'
    return r.RuntimeCompileInputs(Path(r'D:\a\newton_shape_capsule'),T,(T.parents[2]/'include',*(SDK/n for n in ('ucrt','shared','um','winrt','cppwinrt'))),tuple(r.RuntimeFilePin(T/n,'a'*64) for n in ('cl.exe','ml64.exe','vctip.exe'))+(r.RuntimeFilePin(RIL,RISHA),r.RuntimeFilePin(NIL,NISHA)),(r.RuntimeFilePin(h,'b'*64),),tuple((role,(str(h),)) for role,_ in r._ROLES[:4]),V4,(r.RuntimeFilePin(r._SETUP_SUPPORT,'c'*64),),(r.RuntimeFilePin(RNI,RSHA),r.RuntimeFilePin(NNI,NSHA)))

@pytest.mark.parametrize('reverse',[False,True])
def test_V4_exact_finite_profile_positive_before_any_IO(reverse,monkeypatch):
    monkeypatch.setattr(r,'_ordinary',forbidden);v=inputs()
    if reverse:v=replace(v,native_image_pins=v.native_image_pins[::-1])
    r.validate_runtime_compile_inputs(v)

@pytest.mark.parametrize('profile',[r._PROFILE,V3])
def test_old_profiles_cannot_optin_second_family(profile,monkeypatch):
    monkeypatch.setattr(r,'_ordinary',forbidden)
    with pytest.raises(r.RuntimeCompileError):r.validate_runtime_compile_inputs(replace(inputs(),profile=profile))

def test_V2_and_V3_deliberate_valid_behavior_remains(monkeypatch):
    monkeypatch.setattr(r,'_ordinary',forbidden);v=inputs()
    r.validate_runtime_compile_inputs(replace(v,profile=r._PROFILE,native_image_pins=()))
    r.validate_runtime_compile_inputs(replace(v,profile=V3,native_image_pins=v.native_image_pins[:1]))

@pytest.mark.parametrize('pins',[None,[],True,(),(r.RuntimeFilePin(NNI,NSHA),),(r.RuntimeFilePin(RNI,RSHA),),(r.RuntimeFilePin(RNI,RSHA),)*2,(r.RuntimeFilePin(NNI,NSHA),)*2,(r.RuntimeFilePin(RNI,RSHA),r.RuntimeFilePin(RNI.parent.parent/('0'*32)/RNI.name,NSHA)),(r.RuntimeFilePin(RNI,RSHA),None),(r.RuntimeFilePin(RNI,RSHA),r.RuntimeFilePin(str(NNI),NSHA)),(r.RuntimeFilePin(RNI,RSHA),r.RuntimeFilePin(NNI,NSHA.upper())),(r.RuntimeFilePin(RNI,RSHA),r.RuntimeFilePin(NNI,None)),(r.RuntimeFilePin(RNI,RSHA),r.RuntimeFilePin(NNI,NSHA),r.RuntimeFilePin(NNI,NSHA))])
def test_V4_bad_inventory_rejects_before_effects(pins,monkeypatch):
    monkeypatch.setattr(r,'_ordinary',forbidden);v=replace(inputs(),native_image_pins=pins)
    with pytest.raises(r.RuntimeCompileError):r.validate_runtime_compile_inputs(v)
    with pytest.raises(r.RuntimeCompileError):
        with r.runtime_compile_session(v):forbidden()

@pytest.mark.parametrize('missing',[RIL,NIL])
def test_V4_requires_corresponding_exact_IL_pins(missing,monkeypatch):
    monkeypatch.setattr(r,'_ordinary',forbidden);v=inputs()
    with pytest.raises(r.RuntimeCompileError):r.validate_runtime_compile_inputs(replace(v,tool_files=tuple(p for p in v.tool_files if p.path!=missing)))

@pytest.mark.parametrize('path',[Path(str(NNI).replace('C:\\Windows','c:\\Windows')),Path(str(NNI).replace('Newtonsoft.Json\\','Newtonsoft.JSON\\')),NNI.parent/('newtonsoft.Json.ni.dll'),NNI.with_suffix('.exe'),Path(str(NNI).replace('e7031ee8','E7031ee8')),Path(str(NNI).replace('e7031ee81a19ccb1f96401fa814a55d6','f'*31)),Path(str(NNI)+':data'),Path(r'C:\Windows\System32')/NNI.name,Path(r'C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Vf87aed9a#\cc6c5b5218dda37f6b73c41f3194c1e9\Microsoft.VisualStudio.Telemetry.ni.dll')])
def test_NI_path_family_boundaries_not_general_cache_allowlist(path,monkeypatch):
    monkeypatch.setattr(r,'_ordinary',forbidden)
    with pytest.raises(r.RuntimeCompileError):r.validate_runtime_compile_inputs(replace(inputs(),native_image_pins=(r.RuntimeFilePin(RNI,RSHA),r.RuntimeFilePin(path,NSHA))))
    with pytest.raises(t.CompilerTraceError):t._native_image_path(path)

@pytest.mark.parametrize('pins',[(),((RNI,RSHA),),((RNI,RSHA),(NNI,NSHA)),((NNI,NSHA),(RNI,RSHA))])
def test_trace_explicit_family_sets_positive(pins):
    families=t._native_image_pin_shape(pins)
    need(families=={p.name.casefold() for p,h in pins})

@pytest.mark.parametrize('pins',[None,[],True,((NNI,NSHA),),((RNI,RSHA),(RNI,RSHA)),((RNI,RSHA),(NNI,None)),((RNI,RSHA),(NNI,NSHA),(NNI,NSHA))])
def test_trace_shape_rejects_before_API(pins):
    class NoAPI:
        def __getattr__(self,n):return forbidden
    policy=t.CompilerTracePolicy(((T/'cl.exe','a'*64),),Path(r'C:\Windows'),native_image_pins=pins)
    with pytest.raises(t.CompilerTraceError):t._LockedPolicy(policy,NoAPI())

@pytest.mark.parametrize('name',[RNI.name,NNI.name])
def test_reserved_NI_basename_cannot_be_tool_pin_route(name,monkeypatch):
    class API:
        def GetWindowsDirectoryW(self,b,n):b.value=r'C:\Windows';return len(b.value)
        def __getattr__(self,n):return forbidden
    monkeypatch.setattr(t,'_ordinary',lambda *a,**k:None)
    with pytest.raises(t.CompilerTraceError,match='separate pins'):t._LockedPolicy(t.CompilerTracePolicy(((T/name,'a'*64),),Path(r'C:\Windows')),API())

@pytest.mark.parametrize('name',[None,True,[],NIL.name,'telemetry.ni.dll','NEWTONSOFT.JSON.NI.DLL'])
def test_private_pair_selector_is_closed_typed_format_only(name):
    with pytest.raises(t.CompilerTraceError):t._native_image_il_name(name)


def raw():
    b=bytearray(1536);b[:2]=b'MZ';struct.pack_into('<I',b,60,128);b[128:132]=b'PE\0\0';struct.pack_into('<HHIIIHH',b,132,0x8664,1,0,0,0,240,0x2022);o=152
    struct.pack_into('<H',b,o,0x20b);struct.pack_into('<II',b,o+32,4096,512);struct.pack_into('<II',b,o+56,8192,512);struct.pack_into('<I',b,o+108,16);struct.pack_into('<II',b,o+112+14*8,4096,72)
    struct.pack_into('<8sIIIIIIHHI',b,o+240,b'.text',1024,4096,1024,512,0,0,0,0,0x60000020);struct.pack_into('<IHHIIII',b,512,72,2,5,4352,32,4,0);struct.pack_into('<II',b,576,4416,168);b[768:772]=b'BSJB';b[832:836]=b'NGE\0';struct.pack_into('<HH',b,836,1,0);return bytes(b)

def model(which):
    b=raw();p=object.__new__(t._LockedPolicy);p.k=None;p.windows=Path(r'C:\Windows');p.allowed=(T/'vctip.exe',);p.handles=[];p.support={};p.rows={'cl.exe':[{'path':T/'cl.exe'}]};p.native_images={};modules=[];active={}
    for idx,(ni,il,sha) in enumerate(((RNI,RIL,RISHA),(NNI,NIL,NISHA))):
        p.rows[il.name.casefold()]=[{'path':il,'sha256':sha,'identity':(7,idx+10)}]
        info={'volume':7,'index':idx+20,'size':len(b),'links':1,'attributes':32,'write':99}
        p.native_images[ni.name.casefold()]={'path':ni,'sha256':hashlib.sha256(b).hexdigest(),'identity':(7,idx+20),'info':info,'handle':400+idx}
        base=4096*(idx+1);active[base]=idx;modules.append({'pid':42,'base':base,'event_index':100+idx,'path':str(il),'sha256':sha,'volume':7,'index':idx+10,'classification':'pinned_anycpu_il_tool_dll','image_admission':'approved','unload_event_index':None})
    ni=(RNI,NNI)[which];pin=p.native_images[ni.name.casefold()];row={**pin['info'],'path':str(ni),'sha256':pin['sha256'],'machine':'AMD64','image_size':8192,'_native_raw':b}
    return p,ni,row,(42,140,active,modules)

@pytest.mark.parametrize('which',[0,1])
def test_both_synthetic_NI_families_bind_their_own_current_IL(which,monkeypatch):
    p,path,row,ctx=model(which);monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)))
    _,out=p.classify(123,managed_tool_root=T,_active_images=ctx)
    need(out['classification']=='pinned_vctip_tool_native_image' and out['active_pinned_IL_binding']['path']==str((RIL,NIL)[which]))
    need(all(out[k] is False for k in ('NI_compilation_authenticity_proven','IL_native_semantic_equivalence_proven','NGEN_dependency_closure_proven','JIT_closure_proven')))

@pytest.mark.parametrize('which',[0,1])
@pytest.mark.parametrize('kind',['wrong-pair','unloaded','crosspid','wrong-IL-hash','wrong-IL-id','future','rejected','no-role','wrong-root','wrong-NI-hash','wrong-NI-id','missing-NI-pin','notactive','duplicateactive','malformedcontext','foreignbase','wrong-path'])
def test_pair_role_pin_and_current_active_context_fail_closed(which,kind,monkeypatch):
    p,path,row,ctx=model(which);context=T;base=4096*(which+1);il=ctx[3][which]
    if kind=='wrong-pair':ctx[2].pop(base)
    elif kind=='unloaded':il['unload_event_index']=139
    elif kind=='crosspid':il['pid']=43
    elif kind=='wrong-IL-hash':il['sha256']='0'*64
    elif kind=='wrong-IL-id':il['index']=999
    elif kind=='future':il['event_index']=140
    elif kind=='rejected':il['image_admission']='pending'
    elif kind=='no-role':context=None
    elif kind=='wrong-root':context=T.parent
    elif kind=='wrong-NI-hash':row['sha256']='0'*64
    elif kind=='wrong-NI-id':row['index']=999
    elif kind=='missing-NI-pin':p.native_images.pop(path.name.casefold())
    elif kind=='notactive':ctx[2].clear()
    elif kind=='duplicateactive':ctx[3].append(dict(il,base=16384));ctx[2][16384]=2
    elif kind=='malformedcontext':ctx=True
    elif kind=='foreignbase':ctx[2][0]=which
    elif kind=='wrong-path':path=Path(r'C:\Windows\System32')/path.name
    monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)))
    with pytest.raises(t.CompilerTraceError):p.classify(123,managed_tool_root=context,_active_images=ctx)


def test_unrelated_unloaded_Remote_IL_does_not_replace_active_Newton_IL(monkeypatch):
    p,path,row,ctx=model(1);ctx[2].pop(4096);ctx[3][0]['unload_event_index']=126
    monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)))
    _,out=p.classify(123,managed_tool_root=T,_active_images=ctx);need(out['active_pinned_IL_binding']['event_index']==101)

@pytest.mark.parametrize('which',[0,1])
def test_both_NI_paths_are_hash_bound_on_recheck(which,monkeypatch):
    p,path,row,ctx=model(which)
    def read(k,handle,**kw):
        idx=handle-400;q=(RNI,NNI)[idx];pin=p.native_images[q.name.casefold()]
        return q,{**pin['info'],'path':str(q),'sha256':pin['sha256'] if idx!=which else '0'*64,'machine':'AMD64','_native_raw':raw()}
    monkeypatch.setattr(t,'_read_image',read);monkeypatch.setattr(t,'_ordinary_native_image',lambda *a:None)
    with pytest.raises(t.CompilerTraceError,match='drift'):p.recheck()

@pytest.mark.parametrize('failure_index',[0,1])
def test_both_NIs_locked_before_capsule_and_preflight_failure_closes_prior(failure_index,tmp_path,monkeypatch):
    v=replace(inputs(),capsule=tmp_path/'absent');calls=[];closed=[]
    monkeypatch.setattr(r,'_ordinary',lambda *a,**k:None);monkeypatch.setattr(r,'_tool_inventory',lambda p:{pin.path for pin in v.tool_files});monkeypatch.setattr(r.source_link_build,'_source_tree_hashes',lambda *a,**k:{})
    def lock(self,path,digest=None,**kw):
        need(not v.capsule.exists() and kw=={'native_image':True});calls.append(path)
        if len(calls)-1==failure_index:raise r.RuntimeCompileError('modeled locked NI failure')
        self.stack.callback(closed.append,path)
    monkeypatch.setattr(r._State,'_lock',lock)
    with pytest.raises(r.RuntimeCompileError):
        with r.runtime_compile_session(v):forbidden()
    need(calls==[RNI,NNI][:failure_index+1] and closed==[RNI,NNI][:failure_index] and not v.capsule.exists())


def test_state_deepcopies_both_NI_records():
    v=inputs();state=r._State(v)
    for pin in v.native_image_pins:pin.__dict__['sha256']='0'*64
    v.__dict__['native_image_pins']=()
    need(tuple(pin.sha256 for pin in state.inputs.native_image_pins)==(RSHA,NSHA))


def modeled_proof(value,monkeypatch):
    s=r._State(value);s.built=True;objects={name+'.obj':b'modeled-'+name.encode() for name,_ in r._ROLES};g=tuple(Path(r'D:\a\NJmodel_export')/n for n in objects)+tuple(Path(r'D:\a\NJmodel_export')/('extra'+str(i)+'.obj') for i in range(3));s.exports={r._key(p):r._sha(objects[p.name]) for p in g if p.name in objects};s.source_pins={'stub/src/model.c':'a'*64};s._lock=lambda p,*a,**k:objects[p.name];s.compile=lambda:(objects,{},[{}]*8);s.recheck=lambda:None
    monkeypatch.setattr(r,'_session_state',lambda h:s);monkeypatch.setattr(r,'_ordinary',lambda *a,**k:None)
    return r.prove_runtime_coff_compilation(object(),g,Path(r'D:\a\NJmodel_capture'))


def test_V4_proof_digest_binds_both_NI_and_both_IL_not_semantic_auth(monkeypatch):
    out=modeled_proof(inputs(),monkeypatch);ni={str(RNI):RSHA,str(NNI):NSHA};il={str(RIL):RISHA,str(NIL):NISHA}
    payload={'profile':V4,'allowed_role':'direct_child_vctip_LOAD_DLL_with_active_exact_pinned_IL','native_image_pins':ni,'required_IL_tool_pin':il}
    need(out['profile']==V4 and out['native_image_sha256']==ni and out['native_image_profile_sha256']==r._sha(json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')))
    need(all(out[k] is False for k in ('NI_compilation_authenticity_proven','IL_native_semantic_equivalence_proven','NGEN_dependency_closure_proven','JIT_closure_proven')))
    v=inputs();changed=replace(v,native_image_pins=(v.native_image_pins[0],r.RuntimeFilePin(NNI,'0'*64)))
    need(modeled_proof(changed,monkeypatch)['native_image_profile_sha256']!=out['native_image_profile_sha256'])
    changed=replace(v,tool_files=tuple(r.RuntimeFilePin(p.path,'0'*64) if p.path==NIL else p for p in v.tool_files))
    need(modeled_proof(changed,monkeypatch)['native_image_profile_sha256']!=out['native_image_profile_sha256'])

@pytest.mark.parametrize('kind',['closed','failed','copied','forged'])
def test_V4_stale_session_never_authorizes_replay(kind,monkeypatch):
    s=r._State(inputs());h=r._RuntimeCompileSession();r._ACTIVE[id(h)]=(h,s);monkeypatch.setattr(r,'_ordinary',forbidden)
    try:
        if kind=='closed':s.closed=True
        elif kind=='failed':s.failed=True
        elif kind=='copied':h=copy.copy(h)
        else:h=r._RuntimeCompileSession()
        with pytest.raises(r.RuntimeCompileError):r.validate_runtime_compile_session(h)
    finally:
        for key,pair in list(r._ACTIVE.items()):
            if pair[1] is s:r._ACTIVE.pop(key)


def _installed_probe():
    flag=os.environ.get('LETHE_RUNTIME_NEWTON_NI_READONLY_PROBE')
    pin=os.environ.get('LETHE_RUNTIME_NEWTON_NI_READONLY_PIN_SHA256')
    if flag is None and pin is None:pytest.skip('explicit installed Newton NI readonly probe not requested')
    need(flag=='1' and pin==NSHA,'invalid independent installed Newton probe pin/flag')


def _bounded_installed_image(path,expected=None):
    # Static bytes only. Check cap before reading and hold the same file against
    # writes/deletes through hashing/envelope parse. No LoadLibrary or process.
    k,_=t._api();t._ordinary(path)
    handle=k.CreateFileW(str(path),0x80000000,1,None,3,0x80,None)
    need(handle not in (None,0,t._INVALID),'installed read lock unavailable')
    try:
        before=t._file_info(k,handle)
        need(before['links']==1 and 512<=before['size']<=16*1024*1024,'installed size/link cap')
        actual,row=t._read_image(k,handle,allow_managed_read=True,retain_native_raw=True)
        data=row.pop('_native_raw',row.pop('_managed_raw',None))
        need(actual==path and type(data) is bytes and len(data)==before['size'],'installed same-handle path/size')
        need(expected is None or row['sha256']==expected,'independent installed pin differs')
        need(t._file_info(k,handle)==before,'installed same-handle identity drift')
        return data,row
    finally:need(k.CloseHandle(handle),'installed CloseHandle failed')


def test_installed_Newton_NI_existing_envelope_unchanged_optin():
    _installed_probe();data,row=_bounded_installed_image(NNI,NSHA);need(len(data)==3884544)
    out=t._recognize_native_tool_image(data);need(out['format_is_admission_authority'] is False and out['NI_compilation_authenticity_proven'] is False)


def test_installed_both_NI_hFiles_with_modeled_current_pair_context_optin():
    _installed_probe();files=(T/'cl.exe',T/'vctip.exe',RIL,NIL)
    pins=tuple((p,_bounded_installed_image(p,expected)[1]['sha256']) for p,expected in zip(files,(None,None,RISHA,NISHA)))
    need(pins[-1][1]==NISHA and pins[-2][1]==RISHA)
    k,_=t._api();p=t._LockedPolicy(t.CompilerTracePolicy(pins,Path(r'C:\Windows'),(T/'vctip.exe',),native_image_pins=((RNI,RSHA),(NNI,NSHA))),k)
    try:
        modules=[];active={}
        for idx,(il,sha) in enumerate(((RIL,RISHA),(NIL,NISHA))):
            pin=p.rows[il.name.casefold()][0];base=4096*(idx+1);active[base]=idx;modules.append({'pid':42,'base':base,'event_index':123+idx,'path':str(il),'sha256':sha,'volume':pin['identity'][0],'index':pin['identity'][1],'classification':'pinned_anycpu_il_tool_dll','image_admission':'approved','unload_event_index':None})
        for ni,il in ((RNI,RIL),(NNI,NIL)):
            handle=k.CreateFileW(str(ni),0x80000000,1,None,3,0x80,None);need(handle not in (None,0,t._INVALID))
            try:
                _,out=p.classify(handle,managed_tool_root=T,_active_images=(42,140,active,modules));need(out['active_pinned_IL_binding']['path']==str(il))
            finally:need(k.CloseHandle(handle))
        p.recheck()
    finally:p.close()


@pytest.mark.parametrize('pins',[(),(r.RuntimeFilePin(RNI,RSHA),)*2])
def test_V3_pin_count_keeps_exact_legacy_diagnostic(pins):
    with pytest.raises(r.RuntimeCompileError,match='^v3 requires one explicit native-image pin$'):r.validate_runtime_compile_inputs(replace(inputs(),profile=V3,native_image_pins=pins))


def test_V3_old_Windows_before_tool_validation_precedence():
    class NoAPI:
        def __getattr__(self,n):return forbidden
    policy=t.CompilerTracePolicy((('bad-tool-path','a'*64),),Path('relative-root'),native_image_pins=((RNI,RSHA),))
    with pytest.raises(t.CompilerTraceError,match='^noncanonical policy path$'):t._LockedPolicy(policy,NoAPI())

@pytest.mark.parametrize('kind',['missingRemoteIL','missingNewtonIL','malformedILsha','nohelper','wronghelper','twohelpers','nonechild','boolchild','stringchild'])
def test_V4_only_early_tool_IL_helper_preflight_before_API(kind):
    class NoAPI:
        def __getattr__(self,n):return forbidden
    pins=((T/'cl.exe','a'*64),(T/'vctip.exe','b'*64),(RIL,RISHA),(NIL,NISHA));children=(T/'vctip.exe',)
    if kind=='missingRemoteIL':pins=tuple(p for p in pins if p[0]!=RIL)
    elif kind=='missingNewtonIL':pins=tuple(p for p in pins if p[0]!=NIL)
    elif kind=='malformedILsha':pins=pins[:-1]+((NIL,None),)
    elif kind=='nohelper':children=()
    elif kind=='wronghelper':children=(T/'other.exe',)
    elif kind=='twohelpers':children=(T/'vctip.exe',T.parent/'vctip.exe')
    else:children=(T/'vctip.exe',{'nonechild':None,'boolchild':True,'stringchild':str(T/'vctip.exe')}[kind])
    with pytest.raises(t.CompilerTraceError):t._LockedPolicy(t.CompilerTracePolicy(pins,Path(r'C:\Windows'),children,native_image_pins=((RNI,RSHA),(NNI,NSHA))),NoAPI())


@pytest.mark.parametrize('flag,pin',[(None,None),(None,NSHA),('1',None),('0',NSHA),('',NSHA),('1','0'*64),('1',NSHA.upper()),('true',NSHA),('1',NSHA)])
def test_installed_probe_optin_and_independent_pin_before_IO(flag,pin,monkeypatch):
    for name,value in (('LETHE_RUNTIME_NEWTON_NI_READONLY_PROBE',flag),('LETHE_RUNTIME_NEWTON_NI_READONLY_PIN_SHA256',pin)):
        if value is None:monkeypatch.delenv(name,raising=False)
        else:monkeypatch.setenv(name,value)
    monkeypatch.setattr(t,'_api',forbidden);monkeypatch.setattr(t,'_ordinary',forbidden)
    monkeypatch.setattr(Path,'read_bytes',forbidden)
    if flag=='1' and pin==NSHA:_installed_probe();return
    expected=pytest.skip.Exception if flag is None and pin is None else AssertionError
    with pytest.raises(expected):_installed_probe()
    for probe in (test_installed_Newton_NI_existing_envelope_unchanged_optin,test_installed_both_NI_hFiles_with_modeled_current_pair_context_optin):
        with pytest.raises(expected):probe()
