"""V3 NI pin/active-event contracts; all compilation and debugger launches are forbidden."""
from dataclasses import replace, FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
import copy
import hashlib
import json
import os
import struct

import pytest
from lifter import runtime_coff_compile as r
from lifter import runtime_compiler_trace as t

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='closed Win64 path profile')
T=Path(r'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64')
SDK=Path(r'C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0')
NI=Path(r'C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.V8f370856#\c4c9d7fd5bf04be34be80f649b419ccd\Microsoft.VisualStudio.RemoteControl.ni.dll')
IL=T/'Microsoft.VisualStudio.RemoteControl.dll'
NSHA='6bd9b8b7fc3ba9e0f3efee4532aa9f8fa6d32f25bbaca0fd8db2b640d19ecd2d'
ISHA='cc52e19735d6152702672feb5911c8ba77f60fdc73df5ed0d601b37415f3a7ed'
V3='msvc-14.44.35207-sdk-10.0.26100.0-raw-v3'

def need(v,m='contract failed'):
    if not v:raise AssertionError(m)

def inputs():
    h=SDK/'ucrt/stdio.h'
    return r.RuntimeCompileInputs(Path(r'D:\a\NI_model_capsule'),T,
        (T.parents[2]/'include',*(SDK/n for n in ('ucrt','shared','um','winrt','cppwinrt'))),
        tuple(r.RuntimeFilePin(T/n,'a'*64) for n in ('cl.exe','ml64.exe','vctip.exe'))+(r.RuntimeFilePin(IL,ISHA),),
        (r.RuntimeFilePin(h,'b'*64),),tuple((role,(str(h),)) for role,_ in r._ROLES[:4]),V3,
        (r.RuntimeFilePin(r._SETUP_SUPPORT,'c'*64),),(r.RuntimeFilePin(NI,NSHA),))

def no_effect(*a,**k):raise AssertionError('unexpected I/O/compile/process effect')

def test_v3_shape_and_legacy_default_are_explicit(monkeypatch):
    monkeypatch.setattr(r,'_ordinary',no_effect)
    r.validate_runtime_compile_inputs(inputs())
    legacy=replace(inputs(),profile=r._PROFILE,native_image_pins=())
    r.validate_runtime_compile_inputs(legacy)
    need(r.RuntimeCompileInputs.__dataclass_fields__['native_image_pins'].default==())
    need(t.CompilerTracePolicy.__dataclass_fields__['native_image_pins'].default==())
    with pytest.raises(FrozenInstanceError):inputs().native_image_pins=()

@pytest.mark.parametrize('bad',[None,[],{},True,(),(None,),((NI,NSHA),),(r.RuntimeFilePin(str(NI),NSHA),),
    (r.RuntimeFilePin(NI,None),),(r.RuntimeFilePin(NI,NSHA.upper()),),(r.RuntimeFilePin(NI,'a'*63),),
    (r.RuntimeFilePin(NI,NSHA),)*2])
def test_malformed_native_pins_reject_before_effects(bad,monkeypatch):
    monkeypatch.setattr(r,'_ordinary',no_effect)
    value=replace(inputs(),native_image_pins=bad)
    with pytest.raises(r.RuntimeCompileError):r.validate_runtime_compile_inputs(value)
    with pytest.raises(r.RuntimeCompileError):
        with r.runtime_compile_session(value):no_effect()

@pytest.mark.parametrize('text',[
    str(NI).replace('C:\\Windows','c:\\Windows'),str(NI).replace('Windows','WINDOWS'),
    str(NI).replace('Microsoft.V8f370856#','Microsoft.Other#'),str(NI).replace('c4c9d7fd','C4c9d7fd'),
    str(NI).replace('c4c9d7fd5bf04be34be80f649b419ccd','c4c9d7fd5bf04be34be80f649b419cc'),
    str(NI).replace('.ni.dll','.dll'),str(NI).replace('.ni.dll','.ni.exe'),str(NI)+':data',
    str(NI).replace('assembly\\','assembly\\..\\assembly\\'),
    str(NI).replace('Microsoft.V8f370856#','Microsoft.V8f370856# '),'relative.ni.dll'])
def test_strict_NI_path_is_not_generic_path_expansion(text,monkeypatch):
    monkeypatch.setattr(r,'_ordinary',no_effect)
    with pytest.raises(r.RuntimeCompileError):r.validate_runtime_compile_inputs(replace(inputs(),native_image_pins=(r.RuntimeFilePin(Path(text),NSHA),)))
    # Slash spelling is normalized by Path itself; raw string input is never accepted.


def test_legacy_profile_rejects_optin_and_v3_requires_IL(monkeypatch):
    monkeypatch.setattr(r,'_ordinary',no_effect)
    with pytest.raises(r.RuntimeCompileError,match='v2'):r.validate_runtime_compile_inputs(replace(inputs(),profile=r._PROFILE))
    with pytest.raises(r.RuntimeCompileError,match='IL tool pin'):r.validate_runtime_compile_inputs(replace(inputs(),tool_files=inputs().tool_files[:-1]))
    with pytest.raises(r.RuntimeCompileError):r._path(NI,'generic')
    with pytest.raises(r.RuntimeCompileError):r.validate_runtime_compile_inputs(replace(inputs(),profile=True))


def test_deepcopy_native_pin_authority():
    value=inputs();pin=value.native_image_pins[0];s=r._State(value)
    pin.__dict__['sha256']='0'*64;pin.__dict__['path']=NI.parent/'other.ni.dll';value.__dict__['native_image_pins']=()
    need(s.inputs.native_image_pins[0].path==NI and s.inputs.native_image_pins[0].sha256==NSHA)
    need(s.inputs.native_image_pins[0] is not pin and s.inputs.profile==V3)

@pytest.mark.parametrize('bad',[None,[],True,((NI,),),((str(NI),NSHA),),((NI,None),),((NI,'F'*64),),((NI,NSHA),)*2])
def test_trace_pin_shape_before_API(bad):
    class NoAPI:
        def __getattr__(self,n):return no_effect
    with pytest.raises(t.CompilerTraceError):t._LockedPolicy(t.CompilerTracePolicy(((T/'cl.exe','a'*64),),Path(r'C:\Windows'),native_image_pins=bad),NoAPI())


def native_raw():
    # A synthetic structurally bounded envelope, not Windows/CLR-loadable code.
    raw=bytearray(1536);raw[:2]=b'MZ';struct.pack_into('<I',raw,60,128);raw[128:132]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',raw,132,0x8664,1,0,0,0,240,0x2022)
    o=152;struct.pack_into('<H',raw,o,0x20b);struct.pack_into('<II',raw,o+32,4096,512)
    struct.pack_into('<II',raw,o+56,8192,512);struct.pack_into('<I',raw,o+108,16)
    struct.pack_into('<II',raw,o+112+14*8,4096,72)
    struct.pack_into('<8sIIIIIIHHI',raw,o+240,b'.text',1024,4096,1024,512,0,0,0,0,0x60000020)
    struct.pack_into('<IHHIIII',raw,512,72,2,5,4352,32,4,0)
    struct.pack_into('<II',raw,512+64,4416,168);raw[768:772]=b'BSJB';raw[832:836]=b'NGE\0';struct.pack_into('<HH',raw,836,1,0)
    return bytes(raw)


def model():
    raw=native_raw();p=object.__new__(t._LockedPolicy);p.k=None;p.handles=[];p.windows=Path(r'C:\Windows');p.allowed=(T/'vctip.exe',);p.support={}
    p.rows={'cl.exe':[{'path':T/'cl.exe'}],t._REMOTE_IL_NAME:[{'path':IL,'sha256':ISHA,'identity':(1,10)}]}
    info={'volume':1,'index':20,'size':len(raw),'links':1,'attributes':32,'write':99};sha=hashlib.sha256(raw).hexdigest()
    p.native_images={t._NATIVE_IMAGE_NAME:{'path':NI,'sha256':sha,'identity':(1,20),'info':info.copy(),'handle':789}}
    row={**info,'path':str(NI),'sha256':sha,'machine':'AMD64','image_size':8192,'_native_raw':raw}
    il={'pid':42,'base':4096,'event_index':12,'path':str(IL),'sha256':ISHA,'volume':1,'index':10,'classification':'pinned_anycpu_il_tool_dll','image_admission':'approved','unload_event_index':None}
    return p,NI,row,(42,13,{4096:0},[il])


def test_NI_model_consumer_requires_current_active_pinned_IL(monkeypatch):
    p,path,row,ctx=model();monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)))
    _,out=p.classify(123,managed_tool_root=T,_active_images=ctx)
    need(out['classification']=='pinned_vctip_tool_native_image' and out['active_pinned_IL_binding']['event_index']==12)
    need(out['NI_compilation_authenticity_proven'] is False and out['NGEN_dependency_closure_proven'] is False)
    need('_native_raw' not in out)

@pytest.mark.parametrize('kind',['no-role','wrong-root','missingpin','wrongpath','wronghash','wrongid','size','links','write','attrs','PE32','unboundroot',
    'nonecontext','badcontext','crosspid','unloaded','notactive','rejected','future','wrongILpath','wrongILhash','wrongILid','wrongclass','ambiguous','badbase','badindex'])
def test_NI_consumer_rejects_role_pin_active_event_failures(kind,monkeypatch):
    p,path,row,ctx=model();context=T;pid,event,active,modules=ctx
    if kind=='no-role':context=None
    elif kind=='wrong-root':context=T.parent
    elif kind=='missingpin':p.native_images={}
    elif kind=='wrongpath':path=NI.parent/'Other.ni.dll'
    elif kind=='wronghash':row['sha256']='0'*64
    elif kind=='wrongid':row['index']=21
    elif kind=='size':row['size']+=1
    elif kind=='links':row['links']=2
    elif kind=='write':row['write']+=1
    elif kind=='attrs':row['attributes']=0x400
    elif kind=='PE32':row['machine']='I386';row['_managed_raw']=row.pop('_native_raw')
    elif kind=='unboundroot':p.allowed=()
    elif kind=='nonecontext':ctx=None
    elif kind=='badcontext':ctx=True
    elif kind=='crosspid':modules[0]['pid']=43
    elif kind=='unloaded':modules[0]['unload_event_index']=13
    elif kind=='notactive':active.clear()
    elif kind=='rejected':modules[0]['image_admission']='pending'
    elif kind=='future':modules[0]['event_index']=13
    elif kind=='wrongILpath':modules[0]['path']=str(T.parent/IL.name)
    elif kind=='wrongILhash':modules[0]['sha256']='0'*64
    elif kind=='wrongILid':modules[0]['index']=11
    elif kind=='wrongclass':modules[0]['classification']='pinned_compiler_module'
    elif kind=='ambiguous':modules.append(dict(modules[0],base=8192));active[8192]=1
    elif kind=='badbase':active[0]=0
    elif kind=='badindex':active[4096]=1
    monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)))
    with pytest.raises(t.CompilerTraceError):p.classify(123,managed_tool_root=context,_active_images=ctx)

@pytest.mark.parametrize('code,pid,rootpid,path,pinned,parent',[(3,42,7,str(T/'vctip.exe'),True,7),(6,7,7,str(T/'vctip.exe'),True,7),(6,42,7,str(T/'other.exe'),True,7),(6,42,7,str(T/'vctip.exe'),False,7),(6,42,7,str(T/'vctip.exe'),True,99)])
def test_existing_role_derivation_cannot_optin_NI(code,pid,rootpid,path,pinned,parent):
    need(not t._managed_tool_load_role(code,pid,rootpid,path,pinned,parent,T/'cl.exe'))

@pytest.mark.parametrize('at,fmt,value',[(132,'H',0x14c),(152,'H',0x10b),(150,'H',0x22),(150,'H',0x2122),(134,'H',0),(260,'I',15),
    (184,'I',511),(188,'I',1024),(212,'I',1024),(392+12,'I',0),(392+36,'I',0xe0000020),
    (512,'I',71),(516,'H',1),(528,'I',1),(532,'I',1),(512+64,'I',8190),(512+68,'I',167),(768,'I',0),(832,'I',0),(836,'H',2),
    (264+9*8,'I',4096),(264+9*8+4,'I',4)])
def test_NI_structural_envelope_negatives(at,fmt,value):
    raw=bytearray(native_raw());struct.pack_into('<'+fmt,raw,at,value)
    with pytest.raises(t.CompilerTraceError):t._recognize_native_tool_image(bytes(raw))



def _require_real_NI_probe():
    # Both machine-private read-only controls are explicit opt-in. This is not
    # the mandatory future native2 proof and grants no image admission.
    flag=os.environ.get('LETHE_RUNTIME_NI_READONLY_PROBE')
    if flag is None:pytest.skip('explicit private NI read-only probe not requested')
    need(flag=='1','invalid NI read-only probe flag')
    need(os.environ.get('LETHE_RUNTIME_NI_READONLY_PIN_SHA256')==NSHA,
         'independent expected NI probe pin differs/missing')

def test_real_NI_readonly_envelope_is_not_authentication():
    _require_real_NI_probe()
    raw=NI.read_bytes();need(hashlib.sha256(raw).hexdigest()==NSHA)
    out=t._recognize_native_tool_image(raw);need(out['format_is_admission_authority'] is False and out['IL_native_semantic_equivalence_proven'] is False)


def test_NI_held_lock_and_identity_hash_recheck_only(tmp_path,monkeypatch):
    path=tmp_path/'ownedNI.bin';path.write_bytes(b'whole raw NI bytes');value=inputs();s=r._State(value)
    monkeypatch.setattr(r,'_native_image_path',lambda p:p)
    s.inputs=replace(value,native_image_pins=(r.RuntimeFilePin(path,r._sha(path.read_bytes())),))
    s._lock(path,s.inputs.native_image_pins[0].sha256,native_image=True)
    try:
        s._check_native_images()
        with pytest.raises(OSError):path.write_bytes(b'changed')
        with pytest.raises(OSError):path.unlink()
        old=s.native_locks[path];s.native_locks[path]=(old[0],old[1],'0'*64)
        with pytest.raises(r.RuntimeCompileError):s._check_native_images()
        s.native_locks[path]=old
        # Identity mutation rejected independently of bytes. No Windows file altered.
        identity=list(old[1]);identity[1]+=1;s.native_locks[path]=(old[0],tuple(identity),old[2])
        with pytest.raises(r.RuntimeCompileError):s._check_native_images()
    finally:s.stack.close()


def test_modeled_public_proof_digest_consumes_actual_V3_pins(monkeypatch):
    value=inputs();s=r._State(value);s.built=True
    raw={name+'.obj':b'object-'+name.encode() for name,_ in r._ROLES}
    generated=tuple(Path(r'D:\a\model_export')/n for n in raw)+tuple(Path(r'D:\a\model_export')/('extra'+str(i)+'.obj') for i in range(3))
    s.exports={r._key(p):r._sha(raw[p.name]) for p in generated if p.name in raw};s.source_pins={'stub/src/model.c':'a'*64}
    s._lock=lambda p,*a,**k:raw[p.name];s.compile=lambda:(raw,{},[{}]*8);s.recheck=lambda:None
    monkeypatch.setattr(r,'_session_state',lambda h:s);monkeypatch.setattr(r,'_ordinary',lambda *a,**k:None)
    result=r.prove_runtime_coff_compilation(object(),generated,Path(r'D:\a\model_capture'))
    payload={'profile':V3,'allowed_role':'direct_child_vctip_LOAD_DLL_with_active_exact_pinned_IL','native_image_pins':{str(NI):NSHA},'required_IL_tool_pin':{str(IL):ISHA}}
    need(result['profile']==V3 and result['native_image_sha256']=={str(NI):NSHA})
    need(result['native_image_profile_sha256']==r._sha(json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')))
    need(all(result[k] is False for k in ('NI_compilation_authenticity_proven','IL_native_semantic_equivalence_proven','NGEN_dependency_closure_proven','JIT_closure_proven')))
    # This mocked test is contract evidence, not a real compilation success.

@pytest.mark.parametrize('kind',['closed','failed','forged','copied'])
def test_stale_or_replayed_session_not_NI_authority(kind,monkeypatch):
    s=r._State(inputs());h=r._RuntimeCompileSession();r._ACTIVE[id(h)]=(h,s)
    monkeypatch.setattr(r,'_ordinary',no_effect)
    try:
        if kind=='closed':s.closed=True
        elif kind=='failed':s.failed=True
        elif kind=='forged':h=r._RuntimeCompileSession()
        else:h=copy.copy(h)
        with pytest.raises(r.RuntimeCompileError):r.validate_runtime_compile_session(h)
    finally:
        for key,pair in list(r._ACTIVE.items()):
            if pair[1] is s:r._ACTIVE.pop(key)


@pytest.mark.parametrize('failure',['missing','hash','identity'])
def test_NI_lock_failure_precedes_capsule_creation(failure,tmp_path,monkeypatch):
    value=replace(inputs(),capsule=tmp_path/'absentCapsule');s=r._State(value)
    monkeypatch.setattr(r,'_ordinary',lambda *a,**k:None)
    monkeypatch.setattr(r,'_tool_inventory',lambda p:{pin.path for pin in value.tool_files})
    monkeypatch.setattr(r.source_link_build,'_source_tree_hashes',lambda *a,**k:{})
    seen=[]
    def lock(path,*a,**kw):
        need(path==NI and kw=={'native_image':True})
        need(not value.capsule.exists())
        seen.append(path)
        raise r.RuntimeCompileError('modeled native-image '+failure)
    s._lock=lock
    with pytest.raises(r.RuntimeCompileError,match='modeled native-image'):s.prepare()
    need(seen==[NI] and not value.capsule.exists())



def test_readonly_actual_NI_hFile_pin_and_modeled_active_IL_context():
    _require_real_NI_probe()
    # Real image reads/locks, modeled event role; no debugger/compiler/assembly launch.
    paths=(T/'cl.exe',T/'vctip.exe',IL)
    pins=tuple((p,hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths)
    need(pins[-1][1]==ISHA)
    k,_=t._api();policy=t._LockedPolicy(t.CompilerTracePolicy(pins,Path(r'C:\Windows'),(T/'vctip.exe',),native_image_pins=((NI,NSHA),)),k)
    handle=k.CreateFileW(str(NI),0x80000000,1,None,3,0x80,None)
    need(handle not in (None,0,t._INVALID))
    try:
        pin=policy.rows[t._REMOTE_IL_NAME][0]
        il={'pid':42,'base':4096,'event_index':12,'path':str(IL),'sha256':ISHA,'volume':pin['identity'][0],'index':pin['identity'][1],'classification':'pinned_anycpu_il_tool_dll','image_admission':'approved','unload_event_index':None}
        ctx=(42,13,{4096:0},[il])
        with pytest.raises(t.CompilerTraceError):policy.classify(handle)
        _,out=policy.classify(handle,managed_tool_root=T,_active_images=ctx)
        need(out['sha256']==NSHA and out['classification']=='pinned_vctip_tool_native_image')
        ctx[2].clear()
        with pytest.raises(t.CompilerTraceError):policy.classify(handle,managed_tool_root=T,_active_images=ctx)
        policy.recheck()
    finally:
        need(k.CloseHandle(handle));policy.close()


@pytest.mark.parametrize('flag,pin',[(None,None),(None,NSHA),('',NSHA),('0',NSHA),('true',NSHA),('1',None),('1','0'*64),('1',NSHA.upper()),('1',NSHA)])
def test_private_probe_optin_and_independent_pin_precede_file_IO(flag,pin,monkeypatch):
    monkeypatch.delenv('LETHE_RUNTIME_NI_READONLY_PROBE',raising=False)
    monkeypatch.delenv('LETHE_RUNTIME_NI_READONLY_PIN_SHA256',raising=False)
    if flag is not None:monkeypatch.setenv('LETHE_RUNTIME_NI_READONLY_PROBE',flag)
    if pin is not None:monkeypatch.setenv('LETHE_RUNTIME_NI_READONLY_PIN_SHA256',pin)
    monkeypatch.setattr(Path,'read_bytes',no_effect)
    monkeypatch.setattr(t,'_api',no_effect)
    if flag is None:
        with pytest.raises(pytest.skip.Exception):_require_real_NI_probe()
    elif flag=='1' and pin==NSHA:_require_real_NI_probe()
    else:
        with pytest.raises(AssertionError):_require_real_NI_probe()
