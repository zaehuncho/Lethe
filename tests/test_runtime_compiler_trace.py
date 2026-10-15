"""Structural envelope/role tests; no compiler or traced process is launched."""
from pathlib import Path
import copy,ctypes,hashlib,json,os,struct,subprocess,sys
import pytest
from lifter import runtime_compiler_trace as t

TOOL=Path(r'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64')
TELEMETRY_SHA='c6b09bdb01fb84406fb95f77befd68b4f8f0b5d715bb00df817b5e691501c50d'
def require(v,m='contract failed'):
    if not v:raise AssertionError(m)
def put(raw,at,fmt,*values):struct.pack_into(fmt,raw,at,*values)

def envelope():
    """Bounded synthetic PE envelope, not a CLR-loadable/semantic assembly."""
    raw=bytearray(1536);raw[:2]=b'MZ';put(raw,60,'<I',128);raw[128:132]=b'PE\0\0';put(raw,132,'<HHIIIHH',0x14c,2,0,0,0,224,0x2022);o=152
    put(raw,o,'<H',0x10b);put(raw,o+4,'<III',512,512,0);put(raw,o+16,'<III',0x21b0,0x2000,0x4000);put(raw,o+28,'<III',0x10000000,8192,512);put(raw,o+56,'<II',0x6000,512);put(raw,o+92,'<I',16)
    for i,r,s in ((1,0x2160,79),(5,0x4000,12),(12,0x2000,8),(14,0x2008,72)):put(raw,o+96+i*8,'<II',r,s)
    for i,n,vs,va,rp,flags in ((0,b'.text',512,0x2000,512,0x60000020),(1,b'.reloc',12,0x4000,1024,0x42000040)):
        at=o+224+i*40;put(raw,at,'<8sIIIIIIHHI',n,vs,va,512,rp,0,0,0,0,flags)
    pos=lambda r:512+r-0x2000
    put(raw,pos(0x2000),'<II',0x2190,0);put(raw,pos(0x2008),'<IHHIIII',72,2,5,0x2080,200,1,0)
    meta=pos(0x2080);raw[meta:meta+4]=b'BSJB';put(raw,meta+4,'<HHII',1,1,0,12);raw[meta+16:meta+28]=b'v4.0.30319\0\0';put(raw,meta+28,'<HH',0,5)
    streams=((b'#~',108,64),(b'#Strings',172,4),(b'#US',176,4),(b'#GUID',180,16),(b'#Blob',196,4));at=meta+32
    for name,off,size in streams:
        put(raw,at,'<II',off,size);at+=8;raw[at:at+len(name)+1]=name+b'\0';at=(at+len(name)+4)&~3
    table=meta+108;put(raw,table,'<IBBBBQQII',0,2,0,0,1,(1<<0)|(1<<32),0,1,1);put(raw,table+32,'<HHHHH',0,1,1,0,0);put(raw,table+42,'<IHHHHIHHH',0x8004,1,0,0,0,0,0,1,0)
    raw[meta+172:meta+176]=b'\0A\0\0';raw[meta+180:meta+196]=b'0123456789abcdef'
    put(raw,pos(0x2160),'<IIIII',0x2188,0,0,0x219e,0x2000);put(raw,pos(0x2188),'<II',0x2190,0);raw[pos(0x2190):pos(0x2190)+14]=b'\0\0_CorDllMain\0';raw[pos(0x219e):pos(0x219e)+12]=b'mscoree.dll\0'
    raw[pos(0x21b0):pos(0x21b0)+6]=b'\xff\x25'+struct.pack('<I',0x10002000);put(raw,1024,'<IIHH',0x2000,12,0x31b2,0)
    return bytes(raw)

def guid_boundary_envelope(guid_size,wide):
    base=envelope();table=bytearray(base[748:780]);table[6]=2 if wide else 0
    table.extend(struct.pack('<HHIII' if wide else '<HHHHH',0,1,1,0,0));table.extend(base[790:812]);table.extend(b'\0'*((-len(table))%4))
    sizes=(len(table),4,4,guid_size,4);offsets=[];offset=108
    for size in sizes:offsets.append(offset);offset+=size
    meta_size=offset;irva=0x2080+meta_size+24;entry=irva+80;text_size=(entry+6-0x2000+511)&~511;relva=(0x2000+text_size+8191)&~8191;relpos=512+text_size
    raw=bytearray(relpos+512);raw[:512]=base[:512];o=152
    put(raw,o+4,'<I',text_size);put(raw,o+16,'<I',entry);put(raw,o+24,'<I',relva);put(raw,o+56,'<I',relva+8192);put(raw,o+96+8,'<II',irva,79);put(raw,o+96+5*8,'<II',relva,12)
    put(raw,376+8,'<I',text_size);put(raw,376+16,'<I',text_size);put(raw,416+12,'<I',relva);put(raw,416+20,'<I',relpos)
    pos=lambda r:512+r-0x2000
    put(raw,pos(0x2000),'<II',irva+48,0);raw[520:592]=base[520:592];put(raw,532,'<I',meta_size)
    raw[640:748]=base[640:748]
    for at,off,size in zip((672,684,704,716,732),offsets,sizes):put(raw,at,'<II',off,size)
    content=(bytes(table),b'\0A\0\0',b'\0'*4,b'G'*guid_size,b'\0'*4)
    for off,value in zip(offsets,content):raw[640+off:640+off+len(value)]=value
    put(raw,pos(irva),'<IIIII',irva+40,0,0,irva+62,0x2000);put(raw,pos(irva+40),'<II',irva+48,0);raw[pos(irva+48):pos(irva+48)+14]=b'\0\0_CorDllMain\0';raw[pos(irva+62):pos(irva+62)+12]=b'mscoree.dll\0';raw[pos(entry):pos(entry)+6]=b'\xff\x25'+struct.pack('<I',0x10002000)
    put(raw,relpos,'<IIHH',(entry+2)&~0xfff,12,0x3000|((entry+2)&0xfff),0)
    return bytes(raw)

@pytest.mark.parametrize('size,wide,accepted',[(65520,False,True),(65536,True,True),(65536,False,False)])
def test_GUID_heap_actual_65536_byte_boundary(size,wide,accepted):
    raw=guid_boundary_envelope(size,wide)
    if accepted:require(t._recognize_anycpu_tool_dll(raw)['metadata_streams']['#GUID']['size']==size)
    else:
        with pytest.raises(t.CompilerTraceError,match='heap index width profile'):t._recognize_anycpu_tool_dll(raw)

def low_alignment_header_envelope(overlap):
    base=envelope();textva=512 if overlap else 1024;relva=textva+1536;raw=bytearray(3072);raw[:376]=base[:376];o=152
    put(raw,134,'<H',4);put(raw,o+8,'<I',1536);put(raw,o+16,'<III',textva+432,textva,textva+512);put(raw,o+32,'<I',512);put(raw,o+56,'<II',relva+512,1024)
    for i,r,s in ((1,textva+352,79),(5,relva,12),(12,textva,8),(14,textva+8,72)):put(raw,o+96+i*8,'<II',r,s)
    for i,name,vs,flags in ((0,b'.text',512,0x60000020),(1,b'.rdata',512,0x40000040),(2,b'.extra',512,0x40000040),(3,b'.reloc',12,0x42000040)):
        put(raw,376+i*40,'<8sIIIIIIHHI',name,vs,textva+i*512,512,1024+i*512,0,0,0,0,flags)
    raw[1024:1536]=base[512:1024];pos=lambda r:1024+r-textva
    put(raw,1024,'<II',textva+400,0);put(raw,1040,'<I',textva+128);put(raw,1376,'<IIIII',textva+392,0,0,textva+414,textva);put(raw,1416,'<II',textva+400,0);put(raw,1458,'<I',0x10000000+textva)
    put(raw,2560,'<IIHH',((textva+434)&~0xfff),12,0x3000|((textva+434)&0xfff),0)
    return bytes(raw)

@pytest.mark.parametrize('overlap',[False,True])
def test_low_alignment_sections_stay_outside_mapped_headers(overlap):
    raw=low_alignment_header_envelope(overlap)
    if not overlap:require(t._recognize_anycpu_tool_dll(raw)['image_size']==3072)
    else:
        with pytest.raises(t.CompilerTraceError,match='section virtual extent'):t._recognize_anycpu_tool_dll(raw)

def test_structural_synthetic_envelope_positive():
    r=t._recognize_anycpu_tool_dll(envelope());require(r['envelope']=='AnyCPU_ILONLY_compiler_tool_DLL');require(r['metadata_table_record_bounds_proven']);require(not r['native_x86_admission'] and not r['managed_assembly_verification_proven'])

@pytest.mark.parametrize('at,fmt,values',[
    (132,'<H',(0x8664,)),(152,'<H',(0x20b,)),(150,'<H',(0x2023,)),(150,'<H',(0x22,)),(150,'<H',(0x2122,)),(148,'<H',(223,)),(134,'<H',(97,)),(244,'<I',(15,)),
    (188,'<I',(511,)),(208,'<I',(0x6001,)),(212,'<I',(1024,)),(376+12,'<I',(0,)),(376+36,'<I',(0x70000020,)),(376+36,'<I',(0x20000020,)),(376+36,'<I',(0x20,)),(376+36,'<I',(0xe0000020,)),(416+12,'<I',(0x2000,)),(416+20,'<I',(512,)),
    (536,'<I',(0,)),(536,'<I',(2,)),(536,'<I',(0x20001,)),(536,'<I',(0x11,)),(536,'<I',(0x21,)),(524,'<H',(4,)),(520,'<I',(71,)),(540,'<I',(0x06000001,)),(560,'<II',(0x2100,8)),(568,'<II',(0x2100,8)),(576,'<II',(0x2100,8)),(584,'<II',(0x2100,8)),
    (528,'<I',(0x21ff,)),(532,'<I',(201,)),(640,'<I',(0,)),(644,'<H',(2,)),(648,'<I',(1,)),(652,'<I',(4096,)),(668,'<H',(1,)),(670,'<H',(6,)),(672,'<I',(0,)),(676,'<I',(0xffffffff,)),(724,'<I',(111,)),(748,'<I',(1,)),(752,'<B',(1,)),
    (768,'<Q',(0,)),(772,'<I',(1000001,)),(720,'<I',(15,)),(864,'<I',(0x80002190,)),(868,'<I',(1,)),(880,'<I',(0x80002190,)),(884,'<I',(1,)),(888,'<H',(1,)),(946,'<I',(0x10002004,)),(1032,'<H',(0x31b3,)),(1034,'<H',(0x31b2,)),
])
def test_mutated_envelope_rejects(at,fmt,values):
    raw=bytearray(envelope());put(raw,at,fmt,*values)
    with pytest.raises(t.CompilerTraceError):t._recognize_anycpu_tool_dll(bytes(raw))

@pytest.mark.parametrize('directory',[0,3,7,8,9,10,11,13,15])
def test_unknown_native_directories_reject(directory):
    raw=bytearray(envelope());put(raw,152+96+directory*8,'<II',0x2100,8)
    with pytest.raises(t.CompilerTraceError):t._recognize_anycpu_tool_dll(bytes(raw))

@pytest.mark.parametrize('kind',['extra-import','wrong-dll','wrong-function','entry-opcode','stream-duplicate','stream-padding','table-tail','truncated','overlay'])
def test_named_envelope_mutations_reject(kind):
    raw=bytearray(envelope())
    if kind=='extra-import':put(raw,884-8,'<I',1) # second descriptor's first field
    elif kind=='wrong-dll':raw[927]=ord('x')
    elif kind=='wrong-function':raw[892]=ord('x')
    elif kind=='entry-opcode':raw[944]=0xe9
    elif kind=='stream-duplicate':raw[704:713]=b'#~\0\0\0\0\0\0\0'
    elif kind=='stream-padding':raw[683]=1
    elif kind=='table-tail':put(raw,676,'<I',63)
    elif kind=='truncated':del raw[-1]
    elif kind=='overlay':raw.extend(b'OPAQUE')
    with pytest.raises(t.CompilerTraceError):t._recognize_anycpu_tool_dll(bytes(raw))

@pytest.mark.parametrize('change',[{}, {'event_code':3},{'pid':1},{'parent_pid':3},{'parent_pid':True},{'approved_image_pinned':False},{'approved_image_path':str(TOOL/'other.exe')},{'root_image':TOOL/'other.exe'},{'pid':0},{'event_code':True}])
def test_managed_role_requires_direct_verified_vctip_child(change):
    args=dict(event_code=6,pid=2,root_pid=1,approved_image_path=str(TOOL/'vctip.exe'),approved_image_pinned=True,parent_pid=1,root_image=TOOL/'cl.exe');args.update(change)
    require(t._managed_tool_load_role(**args)==(not change))

def locked_model(path=None,raw=None):
    path=path or TOOL/'Managed.dll';raw=raw or envelope();policy=t._LockedPolicy.__new__(t._LockedPolicy);policy.k=None;policy.windows=Path(r'C:\Windows');policy.allowed=(TOOL/'vctip.exe',)
    digest=hashlib.sha256(raw).hexdigest();policy.rows={path.name.casefold():[{'path':path,'sha256':digest,'identity':(1,2),'handle':123}], 'cl.exe':[{'path':TOOL/'cl.exe'}]}
    row={'path':str(path),'volume':1,'index':2,'sha256':digest,'machine':'I386_PE32_unvalidated','_managed_raw':raw}
    return policy,path,row

def test_exact_pin_precedes_IL_recognizer(monkeypatch):
    policy,path,row=locked_model();row['sha256']='0'*64;calls=[]
    monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)))
    monkeypatch.setattr(t,'_recognize_anycpu_tool_dll',lambda *a:calls.append(1))
    with pytest.raises(t.CompilerTraceError):policy.classify(123,managed_tool_root=TOOL)
    require(calls==[])

@pytest.mark.parametrize('kind',['no-role','unknown-file','wrong-path','wrong-identity','wrong-hash','wrong-suffix','nested-tool','no-vctip','other-parent'])
def test_managed_classification_fails_closed(monkeypatch,kind):
    policy,path,row=locked_model();flag=True
    if kind=='no-role':flag=False
    elif kind=='unknown-file':policy.rows.pop(path.name.casefold())
    elif kind=='wrong-path':path=Path(r'C:\Windows\System32\Managed.dll');row['path']=str(path)
    elif kind=='wrong-identity':row['index']=3
    elif kind=='wrong-hash':row['sha256']='0'*64
    elif kind=='wrong-suffix':
        policy,path,row=locked_model(TOOL/'Managed.exe')
    elif kind=='nested-tool':policy,path,row=locked_model(TOOL/'1033/Managed.dll')
    elif kind=='no-vctip':policy.allowed=()
    elif kind=='other-parent':policy.allowed=(TOOL.parent/'elsewhere/vctip.exe',)
    monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)))
    with pytest.raises(t.CompilerTraceError):policy.classify(123,managed_tool_root=TOOL if flag else None)

def test_pinned_managed_envelope_classification_and_scope(monkeypatch):
    policy,path,row=locked_model();monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)))
    _,result=policy.classify(123,managed_tool_root=TOOL);require(result['classification']=='pinned_anycpu_il_tool_dll' and result['native_image'] is False and '_managed_raw' not in result)
    record=t.CompilerTraceResult(0,b'',b'','exited',(),(result,),(),{}).to_record();require(record['observed_native_image_provenance_only'] is False and record['managed_assembly_closure_proven'] is False and record['runtime_source_compile_binding_proven'] is False)

def test_managed_scope_is_current_child_root_not_any_allowed_root(monkeypatch):
    second=TOOL.parent/'other-version';policy,path,row=locked_model(second/'Managed.dll')
    policy.allowed=(TOOL/'vctip.exe',second/'vctip.exe');policy.rows['cl.exe'].append({'path':second/'cl.exe'})
    monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)))
    with pytest.raises(t.CompilerTraceError):policy.classify(123,managed_tool_root=TOOL)

@pytest.mark.parametrize('bad',[True,'directory',42])
def test_managed_context_requires_exact_path_type(bad):
    policy,_,_=locked_model()
    with pytest.raises(t.CompilerTraceError):policy.classify(123,managed_tool_root=bad)

def test_native_first_classification_unchanged(monkeypatch):
    policy,path,row=locked_model();row.pop('_managed_raw');row.update(machine='AMD64',image_size=0x6000);seen=[]
    def read(*args,**kwargs):seen.append(kwargs);return path,copy.deepcopy(row)
    monkeypatch.setattr(t,'_read_image',read);_,result=policy.classify(123);require(seen==[{}] and result['classification']=='pinned_compiler_module' and result['machine']=='AMD64')
    record=t.CompilerTraceResult(0,b'',b'','exited',(),(result,),(),{}).to_record();require(record['observed_native_image_provenance_only'] is True)

@pytest.mark.skipif(os.name!='nt' or not (TOOL/'Microsoft.VisualStudio.Telemetry.dll').is_file(),reason='exact reviewed Windows14.44 tool fixture absent')
def test_actual_hash_bound_telemetry_envelope():
    raw=(TOOL/'Microsoft.VisualStudio.Telemetry.dll').read_bytes();require(hashlib.sha256(raw).hexdigest()==TELEMETRY_SHA,'reviewed tool fixture changed')
    result=t._recognize_anycpu_tool_dll(raw);require(result['CLI_flags']==9 and result['metadata_table_record_bounds_proven'] and not result['managed_assembly_verification_proven'])

@pytest.mark.skipif(os.name!='nt' or not (TOOL/'Microsoft.VisualStudio.Telemetry.dll').is_file(),reason='exact reviewed Windows14.44 tool fixture absent')
def test_actual_image_handle_stays_native_by_default_then_pin_bound_IL():
    paths=(TOOL/'cl.exe',TOOL/'vctip.exe',TOOL/'Microsoft.VisualStudio.Telemetry.dll');pins=tuple((p,hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths)
    require(pins[2][1]==TELEMETRY_SHA,'reviewed tool fixture changed');k,nt=t._api();policy=t._LockedPolicy(t.CompilerTracePolicy(pins,Path(r'C:\Windows'),(paths[1],)),k)
    handle=k.CreateFileW(str(paths[2]),0x80000000,1,None,3,0x80,None)
    require(handle not in (None,t._INVALID),'test read handle failed')
    try:
        with pytest.raises(t.CompilerTraceError):policy.classify(handle)
        _,row=policy.classify(handle,managed_tool_root=TOOL);require(row['sha256']==TELEMETRY_SHA and row['classification']=='pinned_anycpu_il_tool_dll')
    finally:require(k.CloseHandle(handle),'test own image handle close failed');policy.close()

def test_optimized_envelope_guards_are_not_assert_based(tmp_path):
    fixture=tmp_path/'envelope.bin';fixture.write_bytes(envelope());module=Path(t.__file__)
    code="""import importlib.util,sys,pathlib;spec=importlib.util.spec_from_file_location('guarded',sys.argv[1]);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);raw=pathlib.Path(sys.argv[2]).read_bytes();m._recognize_anycpu_tool_dll(raw);count=0
for value in (b'',raw[:-1],raw+b'UNKNOWN'):
 try:m._recognize_anycpu_tool_dll(value)
 except m.CompilerTraceError:count+=1
if count!=3 or sys.flags.optimize!=2:raise RuntimeError('optimized guards missing')
print('OO_ENVELOPE_GUARDS optimize=2 rejected=3')
"""
    p=subprocess.run([sys.executable,'-I','-OO','-B','-c',code,str(module),str(fixture)],capture_output=True,timeout=20)
    require(p.returncode==0 and p.stdout.splitlines()==[b'OO_ENVELOPE_GUARDS optimize=2 rejected=3'] and not p.stderr,(p.returncode,p.stdout,p.stderr))


# Exact external Setup support tests. These open read-only handles or model the
# private role context; no compiler/debugger process or DLL export is executed.
SETUP=Path(r'C:\ProgramData\Microsoft\VisualStudio\Setup\x64\Microsoft.VisualStudio.Setup.Configuration.Native.dll')
SETUP_SHA='2d64e8f75e487211367ce99d49171695d9cdd47d855f27b920fcffde422f3a58'

def native_support_envelope():
    """Structural native PE envelope, not a Windows-loadable behavior fixture."""
    raw=bytearray(1024);raw[:2]=b'MZ';put(raw,60,'<I',128);raw[128:132]=b'PE\0\0';put(raw,132,'<HHIIIHH',0x8664,1,0,0,0,240,0x2022)
    put(raw,152,'<H',0x20b);put(raw,168,'<I',4096);put(raw,176,'<Q',0x180000000);put(raw,184,'<II',4096,512);put(raw,208,'<II',8192,512);put(raw,260,'<I',16)
    put(raw,392,'<8sIIIIIIHHI',b'.text',512,4096,512,512,0,0,0,0,0x60000020);raw[512]=0xc3;return bytes(raw)

def support_model(raw=None):
    raw=native_support_envelope() if raw is None else raw;policy=t._LockedPolicy.__new__(t._LockedPolicy);policy.k=object();policy.windows=Path(r'C:\Windows');policy.handles=[];policy.allowed=(TOOL/'vctip.exe',);policy.rows={'cl.exe':[{'path':TOOL/'cl.exe'}]}
    info={'volume':1,'index':2,'size':len(raw),'links':1,'attributes':32,'write':5};digest=hashlib.sha256(raw).hexdigest()
    policy.support={SETUP.name.casefold():{'path':SETUP,'sha256':digest,'identity':(1,2),'handle':123,'info':info.copy()}}
    return policy,SETUP,{**info,'path':str(SETUP),'sha256':digest,'machine':'AMD64','image_size':8192,'_native_raw':raw}

def test_support_policy_append_is_immutable_and_default_empty():
    from dataclasses import FrozenInstanceError
    p=t.CompilerTracePolicy(((TOOL/'cl.exe','0'*64),),Path(r'C:\Windows'))
    require(p.support_pins==())
    with pytest.raises(FrozenInstanceError):p.support_pins=((SETUP,SETUP_SHA),)

def test_native_support_structural_envelope_positive():
    r=t._recognize_setup_support_dll(native_support_envelope());require(r['machine']=='AMD64' and r['sections']==1 and r['signature_verified'] is False and r['unwind_semantics_verified'] is False)

@pytest.mark.parametrize('at,fmt,values',[
    (132,'<H',(0x14c,)),(152,'<H',(0x10b,)),(150,'<H',(0x22,)),(150,'<H',(0x2023,)),(148,'<H',(224,)),(134,'<H',(0,)),(134,'<H',(97,)),(140,'<I',(1,)),(144,'<I',(1,)),
    (184,'<I',(511,)),(188,'<I',(511,)),(208,'<I',(8193,)),(212,'<I',(1024,)),(260,'<I',(15,)),(168,'<I',(0,)),(168,'<I',(8191,)),
    (392+12,'<I',(0,)),(392+16,'<I',(1024,)),(392+20,'<I',(0,)),(392+36,'<I',(0x70000020,)),(392+36,'<I',(0xe0000020,)),(392+36,'<I',(0x20000020,)),
    (264+14*8,'<II',(4096,72)),(264+8,'<II',(4096,0)),(264+8,'<II',(4607,2)),(264+4*8,'<II',(1023,1)),
])
def test_native_support_mutations_fail_typed(at,fmt,values):
    raw=bytearray(native_support_envelope());put(raw,at,fmt,*values)
    with pytest.raises(t.CompilerTraceError):t._recognize_setup_support_dll(bytes(raw))

@pytest.mark.parametrize('bad',[None,[],(SETUP,),((SETUP,),),((str(SETUP),SETUP_SHA),),((SETUP,1),),((SETUP,'A'*64),),((SETUP.parent/'other.dll',SETUP_SHA),),((SETUP,SETUP_SHA),(SETUP,SETUP_SHA))])
def test_support_shape_preflight_before_any_API(bad):
    class NoAPI:
        def __getattr__(self,name):raise AssertionError('unexpected API '+name)
    policy=t.CompilerTracePolicy(((TOOL/'cl.exe','0'*64),),Path(r'C:\Windows'),support_pins=bad)
    with pytest.raises(t.CompilerTraceError):t._LockedPolicy(policy,NoAPI())

@pytest.mark.parametrize('kind',['no-role','no-pin','wrong-path','wrong-sha','wrong-id','wrong-size','wrong-write','wrong-links','wrong-attrs','no-vctip','other-root','unbound-root','PE32','non-DLL'])
def test_support_current_child_and_exact_pin_fail_closed(monkeypatch,kind):
    policy,path,row=support_model();context=TOOL
    if kind=='no-role':context=None
    elif kind=='no-pin':policy.support={}
    elif kind=='wrong-path':path=Path(r'C:\Windows\System32')/SETUP.name;row['path']=str(path)
    elif kind=='wrong-sha':row['sha256']='0'*64
    elif kind=='wrong-id':row['index']=3
    elif kind=='wrong-size':row['size']+=1
    elif kind=='wrong-write':row['write']+=1
    elif kind=='wrong-links':row['links']=2
    elif kind=='wrong-attrs':row['attributes']|=0x400
    elif kind=='no-vctip':policy.allowed=()
    elif kind=='other-root':context=TOOL.parent/'other';policy.allowed+=(context/'vctip.exe',)
    elif kind=='unbound-root':policy.rows={}
    elif kind=='PE32':row.pop('_native_raw');row['_managed_raw']=envelope();row['machine']='I386_PE32_unvalidated'
    elif kind=='non-DLL':
        raw=bytearray(row['_native_raw']);put(raw,150,'<H',0x22);policy,path,row=support_model(bytes(raw))
    monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)))
    monkeypatch.setattr(t,'_platform_domain',lambda *a:(_ for _ in ()).throw(AssertionError('support used OS fallback')))
    with pytest.raises(t.CompilerTraceError):policy.classify(456,managed_tool_root=context)

def test_support_positive_is_private_pin_bound_and_scoped(monkeypatch):
    policy,path,row=support_model();monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)))
    _,out=policy.classify(456,managed_tool_root=TOOL)
    require(out['classification']=='pinned_vctip_setup_support_native_image' and out['support_child_tool_root']==str(TOOL) and '_native_raw' not in out)
    require(out['support_native_envelope']['import_or_dynamic_dependency_closure_proven'] is False)
    rec=t.CompilerTraceResult(0,b'',b'','exited',(),(out,),(),{}).to_record();require(rec['runtime_source_compile_binding_proven'] is False)

@pytest.mark.parametrize('code,pid,parent,pinned,path',[(3,2,1,True,str(TOOL/'vctip.exe')),(6,1,1,True,str(TOOL/'vctip.exe')),(6,2,3,True,str(TOOL/'vctip.exe')),(6,2,1,False,str(TOOL/'vctip.exe')),(6,2,1,True,str(TOOL/'other.exe'))])
def test_support_service_role_never_root_CREATE_or_other_child(code,pid,parent,pinned,path):
    require(t._managed_tool_load_role(code,pid,1,path,pinned,parent,TOOL/'cl.exe') is False)

@pytest.mark.skipif(os.name!='nt' or not SETUP.is_file(),reason='exact reviewed Setup DLL absent')
def test_actual_setup_bytes_only_native_envelope():
    raw=SETUP.read_bytes();require(hashlib.sha256(raw).hexdigest()==SETUP_SHA,'reviewed Setup fixture changed')
    r=t._recognize_setup_support_dll(raw);require(r['sections']==8 and not r['signature_verified'] and not r['unwind_semantics_verified'])

@pytest.mark.skipif(os.name!='nt' or not SETUP.is_file(),reason='exact reviewed Setup DLL absent')
def test_actual_setup_read_handle_pin_role_and_recheck():
    paths=(TOOL/'cl.exe',TOOL/'vctip.exe');pins=tuple((p,hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths)
    k,_=t._api();policy=t._LockedPolicy(t.CompilerTracePolicy(pins,Path(r'C:\Windows'),(paths[1],),((SETUP,SETUP_SHA),)),k)
    handle=k.CreateFileW(str(SETUP),0x80000000,1,None,3,0x80,None);require(handle not in (None,t._INVALID),'support test handle missing')
    try:
        with pytest.raises(t.CompilerTraceError,match='verified current VCTIP'):policy.classify(handle)
        _,out=policy.classify(handle,managed_tool_root=TOOL);require(out['sha256']==SETUP_SHA and out['classification']=='pinned_vctip_setup_support_native_image')
        policy.recheck()
    finally:require(k.CloseHandle(handle),'support test handle close failed');policy.close()

@pytest.mark.skipif(os.name!='nt' or not SETUP.is_file(),reason='exact reviewed Setup DLL absent')
@pytest.mark.parametrize('kind',['bad-sha','tool-route'])
def test_actual_support_preflight_rejects_hash_and_tool_route(kind):
    paths=(TOOL/'cl.exe',TOOL/'vctip.exe');pins=tuple((p,hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths)
    if kind=='tool-route':pins+=((SETUP,SETUP_SHA),);support=()
    else:support=((SETUP,'0'*64),)
    k,_=t._api()
    with pytest.raises(t.CompilerTraceError):t._LockedPolicy(t.CompilerTracePolicy(pins,Path(r'C:\Windows'),(paths[1],),support),k)

@pytest.mark.parametrize('flags',[0x2022,0x2422,0x2822,0x2c22])
def test_support_documented_swap_copy_characteristics(flags):
    raw=bytearray(native_support_envelope());put(raw,150,'<H',flags);require(t._recognize_setup_support_dll(bytes(raw))['machine']=='AMD64')


# Windows-GAC facade diagnostics: hash-bound read-only bytes/handles and models.
# No compiler/debugger or assembly load/export invocation occurs.
FACADE=Path(r'C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Runtime\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Runtime.dll')
FACADE_SHA='cb4a18c5c5f4f11d24633ed0ffc4df8b2acd00b96d8b628c72846e61dee1a232'
FACADE_ID=('System.Runtime','b03f5f7f11d50a3a')

@pytest.fixture
def facade_raw():
    if os.name!='nt' or not FACADE.is_file():pytest.skip('reviewed Windows framework facade absent')
    raw=FACADE.read_bytes();require(hashlib.sha256(raw).hexdigest()==FACADE_SHA,'reviewed facade fixture changed');return raw

def facade_layout(raw):
    # Geometry for this actual hash-bound small-index fixture only.
    env=t._recognize_anycpu_tool_dll(bytes(raw));pe=struct.unpack_from('<I',raw,60)[0];opt=pe+24;n=struct.unpack_from('<H',raw,pe+6)[0];size=struct.unpack_from('<H',raw,pe+20)[0]
    sections=[struct.unpack_from('<IIII',raw,opt+size+i*40+8) for i in range(n)]
    def pos(rva):return next(rp+rva-va for vs,va,rs,rp in sections if va<=rva<va+min(vs,rs))
    clr=pos(struct.unpack_from('<I',raw,opt+96+14*8)[0]);meta=pos(struct.unpack_from('<I',raw,clr+8)[0]);table=meta+env['metadata_streams']['#~']['offset'];rows=env['table_rows'];cursor=table+24+4*len(rows);widths={0:10,1:6,2:14,10:6,12:6,32:22,35:20,39:14};offsets={}
    require(raw[table+6]==0 and set(rows)==set(widths),'exact fixture table profile changed')
    for i in sorted(rows):offsets[i]=cursor;cursor+=rows[i]*widths[i]
    return meta,env['metadata_streams'],rows,offsets,widths

def facade_model(raw):
    policy,path,row=locked_model();policy.rows.pop(path.name.casefold());policy.support={};path=FACADE
    row.update(path=str(path),sha256=hashlib.sha256(raw).hexdigest(),_managed_raw=raw,size=len(raw),links=4,attributes=32,write=5)
    return policy,path,row

def test_actual_facade_identity_nested_forwarders_and_scope(facade_raw):
    r=t._recognize_anycpu_tool_dll(facade_raw,_facade_identity=FACADE_ID);f=r['facade_identity']
    require(r['envelope']=='Windows_GAC_MSIL_framework_pure_facade' and f['MethodDef_count']==0 and f['Field_count']==0 and f['TypeDef_count']==1)
    require(f['ExportedType_count']==279 and f['nested_ExportedType_count']==6 and f['terminal_forwarder_counts']=={'mscorlib':250,'System.Core':18,'System':10,'System.ComponentModel.Composition':1})
    require(f['public_key_derived_token']==FACADE_ID[1] and not f['public_key_token_is_authenticity'] and not f['strong_name_signature_verified'] and not f['managed_dependency_closure_proven'])

@pytest.mark.parametrize('identity',[None,(),[],('System.Runtime',),('System.Runtime','bad'),('System.Evil',FACADE_ID[1]),('System.Runtime','b77a5c561934e089'),('System..Runtime',FACADE_ID[1]),(1,FACADE_ID[1])])
def test_facade_identity_mode_fails_closed(facade_raw,identity):
    if identity is None:
        r=t._recognize_anycpu_tool_dll(facade_raw);require('facade_identity' not in r);return
    with pytest.raises(t.CompilerTraceError):t._recognize_anycpu_tool_dll(facade_raw,_facade_identity=identity)

@pytest.mark.parametrize('path',[
    r'C:\Windows\Microsoft.NET\assembly\GAC_64\System.Runtime\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Runtime.dll',
    r'C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Runtime\v2.0_4.0.0.0__b03f5f7f11d50a3a\System.Runtime.dll',
    r'C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Runtime\v4.0_4.0.0.1__b03f5f7f11d50a3a\System.Runtime.dll',
    r'C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Runtime\v4.0_4.0.0.0__31bf3856ad364e35\System.Runtime.dll',
    r'C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Runtime\v4.0_4.0.0.0__b03f5f7f11d50a3a\other.dll',
    r'C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Evil\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Runtime.dll',
    r'C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Runtime\v4.0_4.0.0.0__b03f5f7f11d50a3a\nested\System.Runtime.dll',
    r'C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System..Runtime\v4.0_4.0.0.0__b03f5f7f11d50a3a\System..Runtime.dll',
    r'C:\Windows\Temp\System.Runtime\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Runtime.dll',
    r'C:\user\Microsoft.NET\assembly\GAC_MSIL\System.Runtime\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Runtime.dll',
])
def test_facade_path_domain_rejects(path):require(t._facade_domain(Path(path),Path(r'C:\Windows')) is None)

@pytest.mark.parametrize('token',['b03f5f7f11d50a3a','b77a5c561934e089'])
def test_facade_exact_ASCII_path_domain(token):
    p=FACADE.parent.parent/('v4.0_4.0.0.0__'+token)/FACADE.name
    require(t._facade_domain(p,Path(r'C:\Windows'))==('System.Runtime',token))

@pytest.mark.parametrize('kind',['assembly-version','assembly-name','assembly-culture','assembly-key','assembly-flags','Module-name','Module-MVID','TypeDef-name','TypeDef-flags','TypeDef-extends','TypeDef-field','TypeDef-method','TypeRef-Module-scope','TypeRef-bad-ref','TypeRef-cycle','TypeRef-name','TypeRef-nonascii','ref-version','ref-self','ref-key','ref-culture','ref-flags','ref-hash','member-parent','member-name','member-signature','attribute-parent','attribute-type','attribute-value','export-flags','export-TypeDefId','export-File','export-bad-ref','export-nested-cycle','export-duplicate'])
def test_facade_metadata_mutations_fail_typed(facade_raw,kind):
    raw=bytearray(facade_raw);meta,streams,rows,at,w=facade_layout(raw);a=at[32];td=at[2];tr=at[1];ref=at[35];member=at[10];attr=at[12];exp=at[39]
    if kind=='assembly-version':put(raw,a+4,'<H',5)
    elif kind=='assembly-name':put(raw,a+18,'<H',0)
    elif kind=='assembly-culture':put(raw,a+20,'<H',1)
    elif kind=='assembly-key':put(raw,a+16,'<H',0)
    elif kind=='assembly-flags':put(raw,a+12,'<I',0)
    elif kind=='Module-name':put(raw,at[0]+2,'<H',0)
    elif kind=='Module-MVID':put(raw,at[0]+4,'<H',2)
    elif kind=='TypeDef-name':put(raw,td+4,'<H',0)
    elif kind=='TypeDef-flags':put(raw,td,'<I',1)
    elif kind=='TypeDef-extends':put(raw,td+8,'<H',4)
    elif kind=='TypeDef-field':put(raw,td+10,'<H',2)
    elif kind=='TypeDef-method':put(raw,td+12,'<H',2)
    elif kind=='TypeRef-Module-scope':put(raw,tr,'<H',4)
    elif kind=='TypeRef-bad-ref':put(raw,tr,'<H',(999<<2)|2)
    elif kind=='TypeRef-cycle':put(raw,tr,'<H',7);put(raw,tr+4,'<H',0)
    elif kind=='TypeRef-name':put(raw,tr+2,'<H',0)
    elif kind=='TypeRef-nonascii':raw[meta+streams['#Strings']['offset']+struct.unpack_from('<H',raw,tr+2)[0]]=255
    elif kind=='ref-version':put(raw,ref,'<H',5)
    elif kind=='ref-self':put(raw,ref+14,'<H',struct.unpack_from('<H',raw,a+18)[0])
    elif kind=='ref-key':put(raw,ref+12,'<H',0)
    elif kind=='ref-culture':put(raw,ref+16,'<H',1)
    elif kind=='ref-flags':put(raw,ref+8,'<I',1)
    elif kind=='ref-hash':put(raw,ref+18,'<H',1)
    elif kind=='member-parent':put(raw,member,'<H',8)
    elif kind=='member-name':put(raw,member+2,'<H',0)
    elif kind=='member-signature':put(raw,member+4,'<H',0)
    elif kind=='attribute-parent':put(raw,attr,'<H',35)
    elif kind=='attribute-type':put(raw,attr+2,'<H',(999<<3)|3)
    elif kind=='attribute-value':put(raw,attr+4,'<H',0)
    elif kind=='export-flags':put(raw,exp,'<I',0)
    elif kind=='export-TypeDefId':put(raw,exp+4,'<I',1)
    elif kind=='export-File':put(raw,exp+12,'<H',4)
    elif kind=='export-bad-ref':put(raw,exp+12,'<H',(999<<2)|1)
    elif kind=='export-nested-cycle':put(raw,exp+73*w[39]+12,'<H',(74<<2)|2)
    elif kind=='export-duplicate':raw[exp+w[39]+8:exp+w[39]+12]=raw[exp+8:exp+12];put(raw,exp+w[39]+12,'<H',9)
    with pytest.raises(t.CompilerTraceError):t._recognize_anycpu_tool_dll(bytes(raw),_facade_identity=FACADE_ID)

@pytest.mark.parametrize('kind',['no-role','no-vctip','other-root','unbound-root','outside-path','wrong-name','wrong-token','native-not-IL'])
def test_facade_classification_context_fails_closed(monkeypatch,facade_raw,kind):
    policy,path,row=facade_model(facade_raw);context=TOOL
    if kind=='no-role':context=None
    elif kind=='no-vctip':policy.allowed=()
    elif kind=='other-root':context=TOOL.parent/'other';policy.allowed+=(context/'vctip.exe',)
    elif kind=='unbound-root':policy.rows={}
    elif kind=='outside-path':path=Path(r'C:\Windows\Temp')/FACADE.name
    elif kind=='wrong-name':path=FACADE.parent.parent.parent/'System.Evil'/FACADE.parent.name/'System.Evil.dll'
    elif kind=='wrong-token':path=FACADE.parent.parent/'v4.0_4.0.0.0__b77a5c561934e089'/FACADE.name
    elif kind=='native-not-IL':row.pop('_managed_raw');row.update(machine='AMD64',image_size=40960)
    row['path']=str(path);monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)))
    with pytest.raises(t.CompilerTraceError):policy.classify(456,managed_tool_root=context)

def test_facade_model_separates_OS_trust_from_pinned_tool_and_native(monkeypatch,facade_raw):
    policy,path,row=facade_model(facade_raw);monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)));_,out=policy.classify(456,managed_tool_root=TOOL)
    require(out['classification']=='operator_trusted_Windows_GAC_pure_facade' and out['native_image'] is False and out['links']==4 and '_managed_raw' not in out)
    rec=t.CompilerTraceResult(0,b'',b'','exited',(),(out,),(),{}).to_record()
    require(not rec['observed_native_image_provenance_only'] and not rec['observed_native_and_pinned_IL_image_provenance_only'] and rec['operator_trusted_OS_facade_observed'] and not rec['runtime_source_compile_binding_proven'] and not rec['managed_assembly_closure_proven'])

def test_actual_facade_handle_acceptance_requires_private_role_and_no_pin(facade_raw):
    paths=(TOOL/'cl.exe',TOOL/'vctip.exe');pins=tuple((p,hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths);k,_=t._api();policy=t._LockedPolicy(t.CompilerTracePolicy(pins,Path(r'C:\Windows'),(paths[1],)),k)
    handle=k.CreateFileW(str(FACADE),0x80000000,1,None,3,0x80,None);require(handle not in (None,t._INVALID),'facade read handle failed')
    try:
        with pytest.raises(t.CompilerTraceError):policy.classify(handle)
        _,out=policy.classify(handle,managed_tool_root=TOOL);require(out['sha256']==FACADE_SHA and out['classification']=='operator_trusted_Windows_GAC_pure_facade' and out['links']==4)
        policy.recheck()
    finally:require(k.CloseHandle(handle),'facade own handle close failed');policy.close()


@pytest.mark.parametrize('forbidden_table',[4,6,26,28,29,38])
def test_facade_closed_inventory_rejects_own_code_PInvoke_and_multimodule_before_record_access(facade_raw,forbidden_table):
    # Lower metadata-inventory contract; whole-image bounds are separately
    # consumed by every real positive/public classifier path above.
    meta,streams,rows,offsets,widths=facade_layout(facade_raw);bad=dict(rows);bad[forbidden_table]=1
    with pytest.raises(t.CompilerTraceError,match='closed table inventory'):
        t._facade_metadata(facade_raw,meta,streams,bad,offsets,widths,None,None,FACADE_ID)


# Exact table tail profiles. No compiler/debugger/assembly invocation.
REFLECTION=Path(r'C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Reflection\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Reflection.dll')
REFLECTION_SHA='2d8cf3808e89b9ecb3c9be2e8cab38747b314b115e48aeade2dd0cb299b56fdd'

@pytest.mark.parametrize('origin',[0,1,3,17])
@pytest.mark.parametrize('residue',range(4))
@pytest.mark.parametrize('tail',range(8))
def test_exact_relative_table_tail_origin_residue_0_to_7(origin,residue,tail):
    length=64+residue;rows_end=origin+length;stream_end=rows_end+tail;raw=b'P'*origin+b'R'*length+b'\0'*tail+b'OUTSIDE'
    expected=length+tail in (((length+3)&~3),((length+4)&~3))
    if expected:
        result=t._validate_metadata_table_tail(raw,origin,rows_end,stream_end);require(result in ('legacy_aligned_zero','terminated_aligned_zero'))
    else:
        with pytest.raises(t.CompilerTraceError,match='metadata table record bounds/tail'):t._validate_metadata_table_tail(raw,origin,rows_end,stream_end)

@pytest.mark.parametrize('length,tail,position',[(64,4,p) for p in range(4)]+[(65,3,p) for p in range(3)]+[(66,2,p) for p in range(2)]+[(67,1,0)])
def test_tail_every_nonzero_byte_rejects(length,tail,position):
    raw=bytearray(b'R'*length+b'\0'*tail);raw[length+position]=1
    with pytest.raises(t.CompilerTraceError):t._validate_metadata_table_tail(bytes(raw),0,length,len(raw))

@pytest.mark.parametrize('kind',['truncated','negative-origin','negative-row','end-before-rows','row-before-table','end-outside','too-small-header','bool-origin','float-end','wrong-bytes-type'])
def test_table_tail_bounds_fail_typed(kind):
    raw=b'R'*64+b'\0'*4;origin,rows,end=0,64,68
    if kind=='truncated':raw=raw[:-1]
    elif kind=='negative-origin':origin=-1
    elif kind=='negative-row':rows=-1
    elif kind=='end-before-rows':end=63
    elif kind=='row-before-table':origin=65
    elif kind=='end-outside':end=72
    elif kind=='too-small-header':rows=20;end=20
    elif kind=='bool-origin':origin=False
    elif kind=='float-end':end=68.0
    elif kind=='wrong-bytes-type':raw=bytearray(raw)
    with pytest.raises(t.CompilerTraceError):t._validate_metadata_table_tail(raw,origin,rows,end)

@pytest.fixture
def reflection_raw():
    if os.name!='nt' or not REFLECTION.is_file():pytest.skip('reviewed Windows Reflection facade absent')
    raw=REFLECTION.read_bytes();require(hashlib.sha256(raw).hexdigest()==REFLECTION_SHA,'reviewed Reflection fixture changed');return raw

def test_actual_reflection_canonical_four_zero_tail_and_facade(reflection_raw):
    require(reflection_raw[1460:1464]==b'\0'*4)
    require(t._validate_metadata_table_tail(reflection_raw,700,1460,1464)=='terminated_aligned_zero')
    r=t._recognize_anycpu_tool_dll(reflection_raw,_facade_identity=('System.Reflection',FACADE_ID[1]));f=r['facade_identity']
    require(f['assembly_name']=='System.Reflection' and f['MethodDef_count']==0 and f['ExportedType_count']==34 and f['framework_AssemblyRefs']==['mscorlib'] and not f['managed_dependency_closure_proven'])

@pytest.mark.parametrize('position',range(4))
def test_actual_reflection_nonzero_tail_rejects_before_admission(reflection_raw,position):
    raw=bytearray(reflection_raw);raw[1460+position]=1
    with pytest.raises(t.CompilerTraceError,match='metadata table record bounds/tail'):t._recognize_anycpu_tool_dll(bytes(raw),_facade_identity=('System.Reflection',FACADE_ID[1]))

def test_actual_reflection_declared_extra_tail_rejects(reflection_raw):
    raw=bytearray(reflection_raw);put(raw,628,'<I',768) # exact #~ descriptor size is at metadata592+32+4
    with pytest.raises(t.CompilerTraceError):t._recognize_anycpu_tool_dll(bytes(raw),_facade_identity=('System.Reflection',FACADE_ID[1]))

def test_actual_reflection_handle_remains_VCTIP_only(reflection_raw):
    paths=(TOOL/'cl.exe',TOOL/'vctip.exe');pins=tuple((p,hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths);k,_=t._api();policy=t._LockedPolicy(t.CompilerTracePolicy(pins,Path(r'C:\Windows'),(paths[1],)),k)
    handle=k.CreateFileW(str(REFLECTION),0x80000000,1,None,3,0x80,None);require(handle not in (None,t._INVALID),'Reflection read handle failed')
    try:
        with pytest.raises(t.CompilerTraceError):policy.classify(handle)
        _,row=policy.classify(handle,managed_tool_root=TOOL);require(row['sha256']==REFLECTION_SHA and row['classification']=='operator_trusted_Windows_GAC_pure_facade')
        policy.recheck()
    finally:require(k.CloseHandle(handle),'Reflection handle close failed');policy.close()


# Exact legacy COFF format controls. No compiler/debugger or assembly invocation.
UNSAFE=TOOL/'System.Runtime.CompilerServices.Unsafe.dll'
UNSAFE_SHA='3cadcb6b8a7335141c7c357a1d77af1ff49b59b872df494f5025580191d1c0d5'

@pytest.fixture
def unsafe_raw():
    if os.name!='nt' or not UNSAFE.is_file():pytest.skip('reviewed compiler Unsafe DLL absent')
    raw=UNSAFE.read_bytes();require(hashlib.sha256(raw).hexdigest()==UNSAFE_SHA,'reviewed Unsafe tool changed');return raw

def unsafe_positions(raw):
    pe=struct.unpack_from('<I',raw,60)[0];opt=pe+24;n=struct.unpack_from('<H',raw,pe+6)[0];size=struct.unpack_from('<H',raw,pe+20)[0]
    sections=[struct.unpack_from('<IIII',raw,opt+size+i*40+8) for i in range(n)]
    def pos(rva):return next(rp+rva-va for vs,va,rs,rp in sections if va<=rva<va+min(vs,rs))
    return pe,opt,pos(struct.unpack_from('<I',raw,opt+96+14*8)[0]),pos(struct.unpack_from('<I',raw,opt+16)[0])

def test_actual_Unsafe_default_negative_and_private_format_positive(unsafe_raw):
    with pytest.raises(t.CompilerTraceError,match='file characteristics'):t._recognize_anycpu_tool_dll(unsafe_raw)
    r=t._recognize_anycpu_tool_dll(unsafe_raw,_legacy_tool_coff=True)
    require(r['COFF_characteristics']==0x2102 and r['COFF_format_profile']=='legacy_tool_ILONLY_2102' and r['COFF_profile_is_admission_authority'] is False)
    require(r['CLI_flags']==9 and r['table_rows'][6]==40 and r['metadata_table_record_bounds_proven'] and r['canonical_CorDllMain_bootstrap'])
    require(not r['native_x86_admission'] and not r['managed_assembly_verification_proven'] and not r['managed_dependency_closure_proven'] and not r['authenticode_signature_verified'])
    require(all(k not in r for k in ('admitted','tool_pin_proven','fresh_role_proven','runtime_source_compile_binding_proven')),'format result exposed admission authority')

@pytest.mark.parametrize('selector',[None,0,1,1.0,'true',[],{},TOOL])
def test_legacy_format_selector_requires_exact_bool(unsafe_raw,selector):
    with pytest.raises(t.CompilerTraceError,match='selector must be bool'):t._recognize_anycpu_tool_dll(unsafe_raw,_legacy_tool_coff=selector)

def test_legacy_format_selector_is_mutually_exclusive_with_OS_facade(unsafe_raw):
    with pytest.raises(t.CompilerTraceError,match='not a Windows facade profile'):
        t._recognize_anycpu_tool_dll(unsafe_raw,_legacy_tool_coff=True,_facade_identity=('System.Runtime',FACADE_ID[1]))

@pytest.mark.parametrize('flags',[0,2,0x100,0x102,0x2000,0x2100,0x2103,0x2122,0x3102,0x6102,0x8102])
def test_legacy_format_all_other_COFF_bits_stay_rejected(unsafe_raw,flags):
    raw=bytearray(unsafe_raw);pe,_,_,_=unsafe_positions(raw);put(raw,pe+22,'<H',flags)
    with pytest.raises(t.CompilerTraceError,match='file characteristics'):t._recognize_anycpu_tool_dll(bytes(raw),_legacy_tool_coff=True)

@pytest.mark.parametrize('flags',[0,2,3,11,0x20009,0x19,0x29,0x80000009])
def test_legacy_tool_CLI32_required_preferred_native_and_unknown_reject(unsafe_raw,flags):
    raw=bytearray(unsafe_raw);_,_,cli,_=unsafe_positions(raw);put(raw,cli+16,'<I',flags)
    with pytest.raises(t.CompilerTraceError):t._recognize_anycpu_tool_dll(bytes(raw),_legacy_tool_coff=True)

@pytest.mark.parametrize('offset',[40,48,56,64])
def test_legacy_tool_mixed_native_directories_stay_rejected(unsafe_raw,offset):
    raw=bytearray(unsafe_raw);_,_,cli,_=unsafe_positions(raw);put(raw,cli+offset,'<II',0x2100,8)
    with pytest.raises(t.CompilerTraceError):t._recognize_anycpu_tool_dll(bytes(raw),_legacy_tool_coff=True)

@pytest.mark.parametrize('kind',['machine','optional','entry-token','bootstrap','IAT-target','metadata-signature','native-method','OPTIL-method','unmanaged-method'])
def test_legacy_format_does_not_skip_existing_envelope_guards(unsafe_raw,kind):
    raw=bytearray(unsafe_raw);pe,opt,cli,entry=unsafe_positions(raw)
    if kind=='machine':put(raw,pe+4,'<H',0x8664)
    elif kind=='optional':put(raw,opt,'<H',0x20b)
    elif kind=='entry-token':put(raw,cli+20,'<I',0x06000001)
    elif kind=='bootstrap':raw[entry]=0x90
    elif kind=='IAT-target':put(raw,entry+2,'<I',struct.unpack_from('<I',raw,entry+2)[0]+4)
    elif kind=='metadata-signature':
        require(raw[1552:1556]==b'BSJB','exact Unsafe metadata fixture changed');raw[1552]=0
    else:
        require(struct.unpack_from('<H',raw,1914)[0]==0x100,'exact Unsafe MethodDef geometry changed')
        put(raw,1914,'<H',0x100|{'native-method':1,'OPTIL-method':2,'unmanaged-method':4}[kind])
    with pytest.raises(t.CompilerTraceError):t._recognize_anycpu_tool_dll(bytes(raw),_legacy_tool_coff=True)

@pytest.mark.parametrize('kind',['wrong-hash','wrong-identity','wrong-path','unknown-tool','no-role','no-vctip','other-root','unknown-root'])
def test_legacy_classifier_requires_pin_and_current_VCTIP_before_parser(monkeypatch,unsafe_raw,kind):
    policy,path,row=locked_model(UNSAFE,unsafe_raw);context=TOOL;calls=[]
    if kind=='wrong-hash':row['sha256']='0'*64
    elif kind=='wrong-identity':row['index']=3
    elif kind=='wrong-path':path=Path(r'C:\Windows\System32')/UNSAFE.name;row['path']=str(path)
    elif kind=='unknown-tool':policy.rows.pop(UNSAFE.name.casefold())
    elif kind=='no-role':context=None
    elif kind=='no-vctip':policy.allowed=()
    elif kind=='other-root':context=TOOL.parent/'other';policy.allowed+=(context/'vctip.exe',)
    elif kind=='unknown-root':policy.rows.pop('cl.exe')
    monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)))
    monkeypatch.setattr(t,'_recognize_anycpu_tool_dll',lambda *a,**k:calls.append(k))
    with pytest.raises(t.CompilerTraceError):policy.classify(123,managed_tool_root=context)
    require(calls==[],'unconsumed pin/role reached format parser')

def test_legacy_classifier_enables_format_only_after_consumed_pin_role(monkeypatch,unsafe_raw):
    policy,path,row=locked_model(UNSAFE,unsafe_raw);calls=[];real=t._recognize_anycpu_tool_dll
    def parse(raw,**kwargs):calls.append(kwargs);return real(raw,**kwargs)
    monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)));monkeypatch.setattr(t,'_recognize_anycpu_tool_dll',parse)
    _,out=policy.classify(123,managed_tool_root=TOOL)
    require(calls==[{'_legacy_tool_coff':True}] and out['classification']=='pinned_anycpu_il_tool_dll')
    require(out['IL_only_envelope']['COFF_profile_is_admission_authority'] is False)
    rec=t.CompilerTraceResult(0,b'',b'','exited',(),(out,),(),{}).to_record();require(rec['runtime_source_compile_binding_proven'] is False)

def test_legacy_profile_has_no_public_policy_or_runner_authority_switch():
    import inspect
    require(set(t.CompilerTracePolicy.__dataclass_fields__)=={'tool_pins','windows_root','allowed_child_images','support_pins','native_image_pins','framework_native_image_pins'})
    require('_legacy_tool_coff' not in inspect.signature(t.run_traced_compiler).parameters)
    with pytest.raises(TypeError):t.CompilerTracePolicy(((TOOL/'cl.exe','0'*64),),Path(r'C:\Windows'),legacy_tool_coff=True)

def test_OS_facade_route_cannot_consume_legacy_tool_format(monkeypatch,unsafe_raw):
    policy,path,row=locked_model(UNSAFE,unsafe_raw);policy.rows.pop(UNSAFE.name.casefold());path=Path(r'C:\Windows\Microsoft.NET\assembly\GAC_MSIL')/'System.Runtime.CompilerServices.Unsafe'/'v4.0_4.0.0.0__b03f5f7f11d50a3a'/UNSAFE.name;row['path']=str(path);seen=[];real=t._recognize_anycpu_tool_dll
    def parse(raw,**kwargs):seen.append(kwargs);return real(raw,**kwargs)
    monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)));monkeypatch.setattr(t,'_recognize_anycpu_tool_dll',parse)
    with pytest.raises(t.CompilerTraceError,match='file characteristics'):policy.classify(123,managed_tool_root=TOOL)
    require(seen==[{'_facade_identity':('System.Runtime.CompilerServices.Unsafe',FACADE_ID[1])}])

def test_actual_Unsafe_read_handle_requires_private_current_child_context(unsafe_raw):
    paths=(TOOL/'cl.exe',TOOL/'vctip.exe',UNSAFE);pins=tuple((p,hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths);k,_=t._api();policy=t._LockedPolicy(t.CompilerTracePolicy(pins,Path(r'C:\Windows'),(paths[1],)),k)
    handle=k.CreateFileW(str(UNSAFE),0x80000000,1,None,3,0x80,None);require(handle not in (None,t._INVALID),'Unsafe own read handle failed')
    try:
        with pytest.raises(t.CompilerTraceError):policy.classify(handle)
        _,row=policy.classify(handle,managed_tool_root=TOOL);require(row['sha256']==UNSAFE_SHA and row['classification']=='pinned_anycpu_il_tool_dll' and row['IL_only_envelope']['COFF_format_profile']=='legacy_tool_ILONLY_2102')
        policy.recheck()
    finally:require(k.CloseHandle(handle),'Unsafe own read handle close failed');policy.close()


# Marked resource file-tail controls use exact copied bytes, never DLL execution.
REMOTE_CONTROL=TOOL/'Microsoft.VisualStudio.RemoteControl.dll'
REMOTE_CONTROL_SHA='cc52e19735d6152702672feb5911c8ba77f60fdc73df5ed0d601b37415f3a7ed'
REMOTE_TAIL_SHA='f9f51191f6cfceb83e3d2eb2ab7377307604bb3f7fa8a990350fe3ff7f924795'

@pytest.fixture
def remotecontrol_raw(tmp_path):
    if os.name!='nt' or not REMOTE_CONTROL.is_file():pytest.skip('reviewed compiler RemoteControl DLL absent')
    raw=REMOTE_CONTROL.read_bytes();require(hashlib.sha256(raw).hexdigest()==REMOTE_CONTROL_SHA,'reviewed RemoteControl tool changed')
    target=tmp_path/'RemoteControl.original.bin';target.write_bytes(raw)
    copied=target.read_bytes();require(copied==raw,'exact static copy differs');return copied


def test_actual_RemoteControl_default_negative_private_resource_profile_positive(remotecontrol_raw):
    for options in ({},{'_legacy_tool_coff':True}):
        with pytest.raises(t.CompilerTraceError,match='nonzero file alignment padding'):t._recognize_anycpu_tool_dll(remotecontrol_raw,**options)
    result=t._recognize_anycpu_tool_dll(remotecontrol_raw,_tool_resource_tail=True)
    row=result['marked_resource_file_tail']
    require(row['profile']=='phase0_marked_readonly_rsrc_file_tail' and row['file_offset']==0x9090 and row['size']==368 and row['sha256']==REMOTE_TAIL_SHA)
    require(row['resource_directories']==5 and row['resource_entries']==6 and row['resource_leaves']==2 and row['logical_resource_bounds_proven'] and row['raw_bytes_preserved'])
    require(all(row[f] is False for f in ('mapped_inaccessibility_proven','writer_authenticity_proven','resource_tail_profile_is_admission_authority')))
    require(result['COFF_format_profile']=='default_ILONLY' and result['table_rows'][6]==97 and result['table_rows'][28]==2 and result['metadata_table_record_bounds_proven'])
    require(not result['managed_assembly_verification_proven'] and not result['managed_dependency_closure_proven'] and not result['authenticode_signature_verified'])
    require(all(k not in result for k in ('admitted','tool_pin_proven','fresh_role_proven','runtime_source_compile_binding_proven')),'format exposed authority')
    require(hashlib.sha256(remotecontrol_raw).hexdigest()==REMOTE_CONTROL_SHA,'parser mutated input')

@pytest.mark.parametrize('selector',[None,0,1,1.0,'true',[],{},TOOL])
def test_resource_tail_selector_requires_exact_bool(remotecontrol_raw,selector):
    with pytest.raises(t.CompilerTraceError,match='selector must be bool'):t._recognize_anycpu_tool_dll(remotecontrol_raw,_tool_resource_tail=selector)


def test_resource_tail_selector_cannot_enable_OS_facade(remotecontrol_raw):
    with pytest.raises(t.CompilerTraceError,match='not a Windows facade profile'):
        t._recognize_anycpu_tool_dll(remotecontrol_raw,_tool_resource_tail=True,_facade_identity=('System.Runtime',FACADE_ID[1]))

@pytest.mark.parametrize('offset',range(16))
def test_resource_tail_every_literal_marker_byte_must_match(remotecontrol_raw,offset):
    raw=bytearray(remotecontrol_raw);raw[0x9090+offset]^=1
    with pytest.raises(t.CompilerTraceError,match='phase/content profile'):t._recognize_anycpu_tool_dll(bytes(raw),_tool_resource_tail=True)

@pytest.mark.parametrize('phase',range(1,16))
def test_resource_tail_all_nonzero_marker_phases_reject(remotecontrol_raw,phase):
    raw=bytearray(remotecontrol_raw);pattern=b'PADDINGXXPADDING';raw[0x9090:0x9200]=(pattern[phase:]+pattern[:phase])*23
    with pytest.raises(t.CompilerTraceError,match='phase/content profile'):t._recognize_anycpu_tool_dll(bytes(raw),_tool_resource_tail=True)

@pytest.mark.parametrize('kind',['renamed','executable','writable','shared','discardable','uninitialized','extra-flags','text-tail','reloc-tail'])
def test_marked_resource_section_profile_does_not_expand_other_data(remotecontrol_raw,kind):
    raw=bytearray(remotecontrol_raw);rsrc=416
    if kind=='renamed':raw[rsrc:rsrc+8]=b'.rdata\0\0'
    elif kind in ('executable','writable','shared','discardable','uninitialized','extra-flags'):
        flags={'executable':0x60000040,'writable':0xc0000040,'shared':0x50000040,'discardable':0x42000040,'uninitialized':0x40000080,'extra-flags':0x40000060}[kind];put(raw,rsrc+36,'<I',flags)
    elif kind=='text-tail':raw[0x8294]=0x50
    elif kind=='reloc-tail':raw[0x920c]=0x50
    with pytest.raises(t.CompilerTraceError):t._recognize_anycpu_tool_dll(bytes(raw),_tool_resource_tail=True)

@pytest.mark.parametrize('kind',['VS-minus1','VS-plus1','VS-plus8','VS-plus16','VS-minus16','raw-plus-align','raw-minus-align','short-file','extra-file'])
def test_resource_tail_lengths_and_extents_stay_closed(remotecontrol_raw,kind):
    raw=bytearray(remotecontrol_raw)
    if kind.startswith('VS-'):
        delta={'VS-minus1':-1,'VS-plus1':1,'VS-plus8':8,'VS-plus16':16,'VS-minus16':-16}[kind]
        put(raw,416+8,'<I',0xc90+delta);put(raw,152+96+2*8+4,'<I',0xc90+delta)
    elif kind=='raw-plus-align':put(raw,416+16,'<I',0x1000)
    elif kind=='raw-minus-align':put(raw,416+16,'<I',0xc00)
    elif kind=='short-file':raw.pop()
    else:raw.extend(b'X')
    with pytest.raises(t.CompilerTraceError):t._recognize_anycpu_tool_dll(bytes(raw),_tool_resource_tail=True)

@pytest.mark.parametrize('directory',[1,2,5,6,12,14])
def test_no_loader_directory_can_point_into_marked_raw_tail(remotecontrol_raw,directory):
    raw=bytearray(remotecontrol_raw);put(raw,152+96+8*directory,'<II',0xcc90,8 if directory!=14 else 72)
    with pytest.raises(t.CompilerTraceError):t._recognize_anycpu_tool_dll(bytes(raw),_tool_resource_tail=True)

@pytest.mark.parametrize('kind',['pointer-tail','RVA-tail','both-tail','payload-cross-tail','empty-address','unaligned-table-size'])
def test_debug_payload_file_pointer_and_RVA_cannot_hide_tail_reference(remotecontrol_raw,kind):
    raw=bytearray(remotecontrol_raw);debug=0x8138
    if kind=='pointer-tail':put(raw,debug+24,'<I',0x9090)
    elif kind=='RVA-tail':put(raw,debug+20,'<I',0xcc90)
    elif kind=='both-tail':put(raw,debug+20,'<II',0xcc90,0x9090)
    elif kind=='payload-cross-tail':put(raw,debug+16,'<III',4,0xcc8e,0x908e)
    elif kind=='empty-address':put(raw,debug+16,'<I',0)
    else:put(raw,152+96+6*8+4,'<I',83)
    with pytest.raises(t.CompilerTraceError):t._recognize_anycpu_tool_dll(bytes(raw),_tool_resource_tail=True)

@pytest.mark.parametrize('kind',['root-cycle','shared-directory','branch-too-deep','leaf-too-early','directory-in-tail','name-in-tail','name-cross-tail','name-invalid-UTF16','name-null','wrong-name-order','numeric-reserved','directory-count','reserved-header','duplicate-key','data-entry-in-tail','data-entry-overlap','leaf-in-tail','leaf-cross-tail','leaf-overlap','leaf-reserved','leaf-zero','logical-gap-change','logical-tail-change'])
def test_marked_resource_tree_is_bounded_nonoverlapping_and_owned(remotecontrol_raw,kind):
    raw=bytearray(remotecontrol_raw);rb=0x8400
    if kind=='root-cycle':put(raw,rb+20,'<I',0x80000000)
    elif kind=='shared-directory':put(raw,rb+28,'<I',0x80000020)
    elif kind=='branch-too-deep':put(raw,rb+0x64,'<I',0x80000020)
    elif kind=='leaf-too-early':put(raw,rb+20,'<I',0x80)
    elif kind=='directory-in-tail':put(raw,rb+20,'<I',0x80000c90)
    elif kind=='name-in-tail':put(raw,rb+16,'<I',0x80000c90)
    elif kind=='name-cross-tail':put(raw,rb+16,'<I',0x80000c8e);put(raw,rb+0xc8e,'<H',4)
    elif kind=='name-invalid-UTF16':put(raw,rb+0xa2,'<H',0xd800)
    elif kind=='name-null':put(raw,rb+0xa2,'<H',0)
    elif kind=='wrong-name-order':put(raw,rb+12,'<HH',0,2)
    elif kind=='numeric-reserved':put(raw,rb+24,'<I',0x10010)
    elif kind=='directory-count':put(raw,rb+12,'<HH',257,0)
    elif kind=='reserved-header':put(raw,rb,'<I',1)
    elif kind=='duplicate-key':put(raw,rb+12,'<HH',2,0);put(raw,rb+24,'<I',0x800000a0)
    elif kind=='data-entry-in-tail':put(raw,rb+0x64,'<I',0xc90)
    elif kind=='data-entry-overlap':put(raw,rb+0x64,'<I',0x20)
    elif kind=='leaf-in-tail':put(raw,rb+0x80,'<II',0xcc90,4)
    elif kind=='leaf-cross-tail':put(raw,rb+0x80,'<II',0xcc8e,4)
    elif kind=='leaf-overlap':put(raw,rb+0x90,'<II',0xc0c4,4)
    elif kind=='leaf-reserved':put(raw,rb+0x80+12,'<I',1)
    elif kind=='leaf-zero':put(raw,rb+0x80+4,'<I',0)
    elif kind=='logical-gap-change':raw[0x8be9]=0x51
    elif kind=='logical-tail-change':raw[0x908e]=0x51
    with pytest.raises(t.CompilerTraceError):t._recognize_anycpu_tool_dll(bytes(raw),_tool_resource_tail=True)

@pytest.mark.parametrize('kind',['wrong-hash','wrong-identity','wrong-path','unknown-tool','no-role','no-vctip','other-root','unknown-root'])
def test_resource_classifier_consumes_pin_and_current_role_before_parser(monkeypatch,remotecontrol_raw,kind):
    policy,path,row=locked_model(REMOTE_CONTROL,remotecontrol_raw);context=TOOL;calls=[]
    if kind=='wrong-hash':row['sha256']='0'*64
    elif kind=='wrong-identity':row['index']=3
    elif kind=='wrong-path':path=Path(r'C:\Windows\System32')/REMOTE_CONTROL.name;row['path']=str(path)
    elif kind=='unknown-tool':policy.rows.pop(REMOTE_CONTROL.name.casefold())
    elif kind=='no-role':context=None
    elif kind=='no-vctip':policy.allowed=()
    elif kind=='other-root':context=TOOL.parent/'other';policy.allowed+=(context/'vctip.exe',)
    elif kind=='unknown-root':policy.rows.pop('cl.exe')
    monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)))
    monkeypatch.setattr(t,'_recognize_anycpu_tool_dll',lambda *a,**k:calls.append(k))
    with pytest.raises(t.CompilerTraceError):policy.classify(123,managed_tool_root=context)
    require(calls==[],'unconsumed pin/current role reached format parser')


def test_resource_classifier_enables_separate_format_after_consumed_exact_pin_role(monkeypatch,remotecontrol_raw):
    policy,path,row=locked_model(REMOTE_CONTROL,remotecontrol_raw);calls=[];real=t._recognize_anycpu_tool_dll
    def parse(raw,**kwargs):calls.append(kwargs);return real(raw,**kwargs)
    monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)));monkeypatch.setattr(t,'_recognize_anycpu_tool_dll',parse)
    _,out=policy.classify(123,managed_tool_root=TOOL)
    require(calls==[{'_legacy_tool_coff':True,'_tool_resource_tail':True}] and out['classification']=='pinned_anycpu_il_tool_dll')
    require(out['sha256']==REMOTE_CONTROL_SHA and out['IL_only_envelope']['marked_resource_file_tail']['resource_tail_profile_is_admission_authority'] is False)
    require(t.CompilerTraceResult(0,b'',b'','exited',(),(out,),(),{}).to_record()['runtime_source_compile_binding_proven'] is False)


def test_resource_classifier_same_bytes_under_other_tool_name_do_not_get_profile(monkeypatch,remotecontrol_raw):
    path=TOOL/'Other.dll';policy,path,row=locked_model(path,remotecontrol_raw);calls=[];real=t._recognize_anycpu_tool_dll
    def parse(raw,**kwargs):calls.append(kwargs);return real(raw,**kwargs)
    monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)));monkeypatch.setattr(t,'_recognize_anycpu_tool_dll',parse)
    with pytest.raises(t.CompilerTraceError,match='nonzero file alignment padding'):policy.classify(123,managed_tool_root=TOOL)
    require(calls==[{'_legacy_tool_coff':True}])


def test_OS_facade_route_never_receives_tool_resource_tail_selector(monkeypatch,remotecontrol_raw):
    policy,path,row=locked_model(REMOTE_CONTROL,remotecontrol_raw);policy.rows.pop(REMOTE_CONTROL.name.casefold());path=Path(r'C:\Windows\Microsoft.NET\assembly\GAC_MSIL')/'System.Runtime'/'v4.0_4.0.0.0__b03f5f7f11d50a3a'/'System.Runtime.dll';row['path']=str(path);seen=[];real=t._recognize_anycpu_tool_dll
    def parse(raw,**kwargs):seen.append(kwargs);return real(raw,**kwargs)
    monkeypatch.setattr(t,'_read_image',lambda *a,**k:(path,copy.deepcopy(row)));monkeypatch.setattr(t,'_recognize_anycpu_tool_dll',parse)
    with pytest.raises(t.CompilerTraceError,match='nonzero file alignment padding'):policy.classify(123,managed_tool_root=TOOL)
    require(seen==[{'_facade_identity':('System.Runtime',FACADE_ID[1])}])


def test_resource_profile_has_no_public_policy_or_runner_authority_switch():
    import inspect
    require(set(t.CompilerTracePolicy.__dataclass_fields__)=={'tool_pins','windows_root','allowed_child_images','support_pins','native_image_pins','framework_native_image_pins'})
    require('_tool_resource_tail' not in inspect.signature(t.run_traced_compiler).parameters)
    with pytest.raises(TypeError):t.CompilerTracePolicy(((TOOL/'cl.exe','0'*64),),Path(r'C:\Windows'),tool_resource_tail=True)


def test_actual_RemoteControl_read_handle_still_requires_private_current_context(remotecontrol_raw):
    paths=(TOOL/'cl.exe',TOOL/'vctip.exe',REMOTE_CONTROL);pins=tuple((p,hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths);k,_=t._api();policy=t._LockedPolicy(t.CompilerTracePolicy(pins,Path(r'C:\Windows'),(paths[1],)),k)
    handle=k.CreateFileW(str(REMOTE_CONTROL),0x80000000,1,None,3,0x80,None);require(handle not in (None,t._INVALID),'RemoteControl own read handle failed')
    try:
        with pytest.raises(t.CompilerTraceError):policy.classify(handle)
        _,row=policy.classify(handle,managed_tool_root=TOOL);require(row['sha256']==REMOTE_CONTROL_SHA and row['classification']=='pinned_anycpu_il_tool_dll' and row['IL_only_envelope']['marked_resource_file_tail']['sha256']==REMOTE_TAIL_SHA)
        policy.recheck()
    finally:require(k.CloseHandle(handle),'RemoteControl own read handle close failed');policy.close()


def test_resource_profile_preserves_old_zero_only_synthetic_behavior():
    raw=envelope();result=t._recognize_anycpu_tool_dll(raw,_tool_resource_tail=True)
    require('marked_resource_file_tail' not in result and result['canonical_CorDllMain_bootstrap'])
