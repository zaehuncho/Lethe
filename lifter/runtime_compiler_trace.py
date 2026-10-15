"""Finite Win64 compiler-tree image trace under an explicitly trusted Windows OS.

The caller owns the tool digest policy. This module freshly observes file handles
and executable modules; it is not OS authenticity or loaded-memory attestation.
OS CLR/GAC/config/JIT semantics are trusted platform behavior. Native debug-image
observation does not attest all managed assemblies or arbitrary OS dependencies.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import ctypes
from ctypes import wintypes as w
import hashlib,os,re,struct,subprocess,time

DBG_CONTINUE=0x10002
DBG_EXCEPTION_NOT_HANDLED=0x80010001
_INVALID=ctypes.c_void_p(-1).value
_SETUP_SUPPORT_PATH=Path(r'C:\ProgramData\Microsoft\VisualStudio\Setup\x64\Microsoft.VisualStudio.Setup.Configuration.Native.dll')
_SETUP_SUPPORT_NAME=_SETUP_SUPPORT_PATH.name.casefold()
_SETUP_SUPPORT_CAP=8*1024*1024
_NATIVE_IMAGE_NAME='microsoft.visualstudio.remotecontrol.ni.dll'
_REMOTE_IL_NAME='microsoft.visualstudio.remotecontrol.dll'
_NEWTON_IMAGE_NAME='newtonsoft.json.ni.dll'
_NEWTON_IL_NAME='newtonsoft.json.dll'
_FRAMEWORK_NATIVE_IMAGE_NAME='system.runtime.serialization.ni.dll'
_FRAMEWORK_NATIVE_IMAGE_CAP=16*1024*1024
_FRAMEWORK_NATIVE_IMAGE_PATH=re.compile(r'C:\\Windows\\assembly\\NativeImages_v4\.0\.30319_64\\System\.Runteb92aa12#\\[0-9a-f]{32}\\System\.Runtime\.Serialization\.ni\.dll\Z')
_NATIVE_IMAGE_CAP=16*1024*1024
_NATIVE_IMAGE_PATH=re.compile(r'C:\\Windows\\assembly\\NativeImages_v4\.0\.30319_64\\Microsoft\.V8f370856#\\[0-9a-f]{32}\\Microsoft\.VisualStudio\.RemoteControl\.ni\.dll\Z')
_NEWTON_IMAGE_PATH=re.compile(r'C:\\Windows\\assembly\\NativeImages_v4\.0\.30319_64\\Newtonsoft\.Json\\[0-9a-f]{32}\\Newtonsoft\.Json\.ni\.dll\Z')

def _native_image_il_name(name):
    # Closed format/role relation, not a name/MVID or publisher authority.
    _need(type(name) is str and name in (_NATIVE_IMAGE_NAME,_NEWTON_IMAGE_NAME),'unsupported native-image family')
    return 'Microsoft.VisualStudio.RemoteControl.dll' if name==_NATIVE_IMAGE_NAME else 'Newtonsoft.Json.dll'

def _native_image_pin_shape(pins):
    _need(type(pins) is tuple and len(pins)<=2,'invalid native-image pin types/count')
    families=set()
    for pair in pins:
        _need(type(pair) is tuple and len(pair)==2,'invalid native-image pin record')
        path,digest=pair;_native_image_path(path)
        _need(type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest) is not None,'invalid native-image pin digest')
        family=path.name.casefold()
        _need(family not in families,'duplicate/ambiguous native-image family');families.add(family)
    _need(not families or families=={_NATIVE_IMAGE_NAME} or families=={_NATIVE_IMAGE_NAME,_NEWTON_IMAGE_NAME},'unsupported native-image family set')
    return families

def _native_image_path(path):
    # Dedicated closed grammar; '#' never enters the generic path policy.
    _need(type(path) is type(Path()) and path.is_absolute() and len(str(path))<=240 and (_NATIVE_IMAGE_PATH.fullmatch(str(path)) is not None or _NEWTON_IMAGE_PATH.fullmatch(str(path)) is not None),'noncanonical explicit native-image pin path')
    return path

def _ordinary_native_image(path):
    _native_image_path(path);_ordinary(path)

def _framework_native_image_path(path):
    _need(type(path) is type(Path()) and path.is_absolute() and len(str(path))<=240 and
          _FRAMEWORK_NATIVE_IMAGE_PATH.fullmatch(str(path)) is not None,
          'noncanonical explicit framework native-image pin path')
    return path

def _ordinary_framework_native_image(path):
    _framework_native_image_path(path);_ordinary(path)

def _framework_native_image_pin_shape(pins):
    _need(type(pins) is tuple and len(pins)<=1,'invalid framework native-image pin types/count')
    paths=set()
    for pair in pins:
        _need(type(pair) is tuple and len(pair)==2,'invalid framework native-image pin record')
        path,digest=pair;_framework_native_image_path(path)
        _need(type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest) is not None,
              'invalid framework native-image pin digest')
        _need(path not in paths,'duplicate framework native-image pin');paths.add(path)
    return bool(paths)


class CompilerTraceError(RuntimeError):
    def __init__(self,message,partial_evidence=None,*,stdout=b'',stderr=b''):
        super().__init__(message);self.partial_evidence=partial_evidence or {};self.evidence=self.partial_evidence
        self.stdout=stdout;self.stderr=stderr

def _need(value,message):
    if not value:raise CompilerTraceError(message)

@dataclass(frozen=True)
class CompilerTracePolicy:
    tool_pins:tuple[tuple[Path,str],...]
    windows_root:Path
    allowed_child_images:tuple[Path,...]=()
    support_pins:tuple[tuple[Path,str],...]=()
    native_image_pins:tuple[tuple[Path,str],...]=()
    framework_native_image_pins:tuple[tuple[Path,str],...]=()

@dataclass(frozen=True)
class CompilerTraceResult:
    exit_code:int
    stdout:bytes
    stderr:bytes
    status:str
    trace_events:tuple[dict,...]
    loaded_modules:tuple[dict,...]
    processes:tuple[dict,...]
    cleanup:dict
    def to_record(self):
        managed=any(row.get('classification')=='pinned_anycpu_il_tool_dll' for row in self.loaded_modules)
        os_facade=any(row.get('classification')=='operator_trusted_Windows_GAC_pure_facade' for row in self.loaded_modules)
        pinned_ni=any(row.get('classification') in ('pinned_vctip_tool_native_image','pinned_vctip_framework_native_image') for row in self.loaded_modules)
        return {'exit_code':self.exit_code,'stdout_sha256':hashlib.sha256(self.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(self.stderr).hexdigest(),'literal_stdout':self.stdout.decode('utf8',errors='replace'),'literal_stderr':self.stderr.decode('utf8',errors='replace'),'status':self.status,'trace_events':list(self.trace_events),'loaded_modules':list(self.loaded_modules),'processes':list(self.processes),'cleanup':self.cleanup,'observed_native_image_provenance_only':not(managed or os_facade),'observed_native_and_pinned_IL_image_provenance_only':not os_facade,'observed_native_pinned_tool_IL_and_operator_trusted_OS_facades_only':True,'operator_trusted_OS_facade_observed':os_facade,'operator_pinned_NGEN_image_observed':pinned_ni,'NI_compilation_authenticity_proven':False,'IL_native_semantic_equivalence_proven':False,'NGEN_dependency_closure_proven':False,'JIT_closure_proven':False,'OS_CLR_GAC_config_JIT_operator_trusted':True,'managed_assembly_closure_proven':False,'OS_loader_dynamic_dependencies_complete':False,'runtime_source_compile_binding_proven':False}

class _FT(ctypes.Structure):_fields_=[('lo',w.DWORD),('hi',w.DWORD)]
class _FileInfo(ctypes.Structure):
    _fields_=[('attributes',w.DWORD),('creation',_FT),('access',_FT),('write',_FT),('volume',w.DWORD),('sizehi',w.DWORD),('sizelo',w.DWORD),('links',w.DWORD),('indexhi',w.DWORD),('indexlo',w.DWORD)]
class _PBI(ctypes.Structure):
    _fields_=[('exit',w.LONG),('peb',ctypes.c_void_p),('affinity',ctypes.c_size_t),('priority',w.LONG),('pid',ctypes.c_size_t),('parent',ctypes.c_size_t)]
class _Create(ctypes.Structure):
    _fields_=[('file',w.HANDLE),('process',w.HANDLE),('thread',w.HANDLE),('base',ctypes.c_void_p),('debugoffset',w.DWORD),('debugsize',w.DWORD),('tls',ctypes.c_void_p),('start',ctypes.c_void_p),('name',ctypes.c_void_p),('unicode',w.WORD)]
class _Load(ctypes.Structure):
    _fields_=[('file',w.HANDLE),('base',ctypes.c_void_p),('debugoffset',w.DWORD),('debugsize',w.DWORD),('name',ctypes.c_void_p),('unicode',w.WORD)]
class _Thread(ctypes.Structure):_fields_=[('thread',w.HANDLE),('tls',ctypes.c_void_p),('start',ctypes.c_void_p)]
class _Payload(ctypes.Union):
    _fields_=[('raw',ctypes.c_ubyte*160),('create',_Create),('load',_Load),('thread',_Thread),('ptr',ctypes.c_void_p)]
class _Event(ctypes.Structure):
    _fields_=[('code',w.DWORD),('pid',w.DWORD),('tid',w.DWORD),('data',_Payload)]
class _JobBasic(ctypes.Structure):
    _fields_=[('process_time',ctypes.c_longlong),('job_time',ctypes.c_longlong),('flags',w.DWORD),('min_working',ctypes.c_size_t),('max_working',ctypes.c_size_t),('active_limit',w.DWORD),('affinity',ctypes.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]
class _IO(ctypes.Structure):_fields_=[(n,ctypes.c_ulonglong) for n in ('readops','writeops','otherops','readbytes','writebytes','otherbytes')]
class _JobLimits(ctypes.Structure):
    _fields_=[('basic',_JobBasic),('io',_IO),('process_memory',ctypes.c_size_t),('job_memory',ctypes.c_size_t),('peak_process',ctypes.c_size_t),('peak_job',ctypes.c_size_t)]
class _JobAccount(ctypes.Structure):
    _fields_=[('user',ctypes.c_longlong),('kernel',ctypes.c_longlong),('perioduser',ctypes.c_longlong),('periodkernel',ctypes.c_longlong),('faults',w.DWORD),('total',w.DWORD),('active',w.DWORD),('terminated',w.DWORD)]

def _api():
    def dll(name):
        try:return ctypes.WinDLL(name,use_last_error=True)
        except (OSError,AttributeError) as exc:raise CompilerTraceError('required Win32 provider unavailable',{'provider':name,'error':str(exc)}) from exc
    def bind(provider,name,restype,argtypes):
        try:f=getattr(provider,name);f.restype=restype;f.argtypes=argtypes;return f
        except (OSError,AttributeError) as exc:raise CompilerTraceError('required Win32 export unavailable',{'provider':provider._name,'export':name,'error':str(exc)}) from exc
    k=dll('kernel32')
    # CompareObjectHandles is documented in KernelBase, not Kernel32.
    kb=dll('kernelbase');k._compiler_kernelbase=kb
    signatures={
      'CreateFileW':(w.HANDLE,(w.LPCWSTR,w.DWORD,w.DWORD,ctypes.c_void_p,w.DWORD,w.DWORD,w.HANDLE)),
      'CloseHandle':(w.BOOL,(w.HANDLE,)),
      'GetFileInformationByHandle':(w.BOOL,(w.HANDLE,ctypes.POINTER(_FileInfo))),
      'GetFinalPathNameByHandleW':(w.DWORD,(w.HANDLE,w.LPWSTR,w.DWORD,w.DWORD)),
      'SetFilePointerEx':(w.BOOL,(w.HANDLE,ctypes.c_longlong,ctypes.POINTER(ctypes.c_longlong),w.DWORD)),
      'ReadFile':(w.BOOL,(w.HANDLE,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD),ctypes.c_void_p)),
      'PeekNamedPipe':(w.BOOL,(w.HANDLE,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD),ctypes.POINTER(w.DWORD),ctypes.POINTER(w.DWORD))),
      'CreateJobObjectW':(w.HANDLE,(ctypes.c_void_p,w.LPCWSTR)),
      'SetInformationJobObject':(w.BOOL,(w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD)),
      'QueryInformationJobObject':(w.BOOL,(w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD))),
      'AssignProcessToJobObject':(w.BOOL,(w.HANDLE,w.HANDLE)),
      'IsProcessInJob':(w.BOOL,(w.HANDLE,w.HANDLE,ctypes.POINTER(w.BOOL))),
      'TerminateJobObject':(w.BOOL,(w.HANDLE,w.UINT)),
      'GetCurrentProcess':(w.HANDLE,()),
      'GetCurrentThreadId':(w.DWORD,()),
      'GetProcessId':(w.DWORD,(w.HANDLE,)),
      'GetThreadId':(w.DWORD,(w.HANDLE,)),
      'GetProcessIdOfThread':(w.DWORD,(w.HANDLE,)),
      'DuplicateHandle':(w.BOOL,(w.HANDLE,w.HANDLE,w.HANDLE,ctypes.POINTER(w.HANDLE),w.DWORD,w.BOOL,w.DWORD)),
      'OpenProcess':(w.HANDLE,(w.DWORD,w.BOOL,w.DWORD)),
      'OpenThread':(w.HANDLE,(w.DWORD,w.BOOL,w.DWORD)),
      'CompareObjectHandles':(w.BOOL,(w.HANDLE,w.HANDLE)),
      'TerminateProcess':(w.BOOL,(w.HANDLE,w.UINT)),
      'WaitForSingleObject':(w.DWORD,(w.HANDLE,w.DWORD)),
      'GetExitCodeProcess':(w.BOOL,(w.HANDLE,ctypes.POINTER(w.DWORD))),
      'WaitForDebugEvent':(w.BOOL,(ctypes.POINTER(_Event),w.DWORD)),
      'ContinueDebugEvent':(w.BOOL,(w.DWORD,w.DWORD,w.DWORD)),
      'DebugActiveProcessStop':(w.BOOL,(w.DWORD,)),
      'GetWindowsDirectoryW':(w.UINT,(w.LPWSTR,w.UINT)),
    }
    for name,(restype,argtypes) in signatures.items():
        f=bind(kb if name=='CompareObjectHandles' else k,name,restype,argtypes)
        if name=='CompareObjectHandles':k.CompareObjectHandles=f
    nt=dll('ntdll')
    bind(nt,'NtResumeProcess',w.LONG,(w.HANDLE,))
    bind(nt,'NtQueryInformationProcess',w.LONG,(w.HANDLE,w.ULONG,ctypes.c_void_p,w.ULONG,ctypes.POINTER(w.ULONG)))
    return k,nt

def _ordinary(path:Path,*,directory=False):
    _need(type(path) is type(Path()) and path.is_absolute() and path.resolve()==path,'noncanonical policy path')
    _need(path.is_dir() if directory else path.is_file(),'missing/wrong policy path')
    for item in (path,*path.parents):_need(not item.lstat().st_file_attributes&0x400,'reparse policy component')

def _file_info(k,handle):
    info=_FileInfo();_need(k.GetFileInformationByHandle(handle,ctypes.byref(info)),'image file identity unreadable')
    return {'volume':int(info.volume),'index':(int(info.indexhi)<<32)|int(info.indexlo),'size':(int(info.sizehi)<<32)|int(info.sizelo),'links':int(info.links),'attributes':int(info.attributes),'write':(int(info.write.hi)<<32)|int(info.write.lo)}

def _read_image(k,handle,*,allow_managed_read=False,retain_native_raw=False):
    before=_file_info(k,handle);_need(not before['attributes']&0x400 and 1<=before['size']<=128*1024*1024,'unsupported image size/reparse')
    buf=ctypes.create_unicode_buffer(4097);n=k.GetFinalPathNameByHandleW(handle,buf,4097,0)
    _need(0<n<4097,'image handle final path unavailable/over cap')
    text=buf.value
    if text.startswith('\\\\?\\'):text=text[4:]
    _need(re.match(r'^[A-Za-z]:\\',text) is not None and '/' not in text,'non-DOS image path')
    path=Path(text);_ordinary(path)
    _need(k.SetFilePointerEx(handle,0,None,0),'image seek failed')
    data=bytearray();block=ctypes.create_string_buffer(1024*1024);got=w.DWORD()
    while len(data)<before['size']:
        want=min(len(block),before['size']-len(data))
        _need(k.ReadFile(handle,block,want,ctypes.byref(got),None) and 0<got.value<=want,'image read failed/truncated')
        data.extend(block.raw[:got.value])
    _need(_file_info(k,handle)==before,'image handle changed while hashed')
    raw=bytes(data);observed={**before,'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}
    if not (len(raw)>=64 and raw[:2]==b'MZ'):raise CompilerTraceError('loaded file is not PE',{'rejected_image':observed})
    pe=struct.unpack_from('<I',raw,60)[0]
    observed['pe_offset']=pe
    valid_header=pe>=64 and pe+88<=len(raw) and raw[pe:pe+4]==b'PE\0\0'
    if valid_header:observed.update(machine_value=struct.unpack_from('<H',raw,pe+4)[0],optional_magic=struct.unpack_from('<H',raw,pe+24)[0])
    if not (valid_header and observed['machine_value']==0x8664 and observed['optional_magic']==0x20b):
        # This is only a private bounded read, not image admission. The caller
        # must check its verified child role and exact file pin before parsing.
        if allow_managed_read and valid_header and observed['machine_value']==0x14c and observed['optional_magic']==0x10b:
            return path,{**observed,'machine':'I386_PE32_unvalidated','_managed_raw':raw}
        raise CompilerTraceError('loaded file is not bounded AMD64 PE32+',{'rejected_image':observed})
    image_size=struct.unpack_from('<I',raw,pe+24+56)[0];_need(0<image_size<=1024*1024*1024,'loaded image virtual bounds')
    return path,{**before,'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'machine':'AMD64','image_size':image_size,**({'_native_raw':raw} if retain_native_raw else {})}

def _recognize_setup_support_dll(raw:bytes):
    """Bounded native PE envelope only; no signature/unwind/import closure claim.

    This parser does not authorize a module. Exact locked pin and private current
    VCTIP LOAD_DLL context are mandatory at its consumer.
    """
    def need(v,m):_need(v,'Setup support DLL: '+m)
    need(type(raw) is bytes and 512<=len(raw)<=_SETUP_SUPPORT_CAP,'raw type/size')
    def u16(at):
        need(type(at) is int and 0<=at<=len(raw)-2,'word bounds');return struct.unpack_from('<H',raw,at)[0]
    def u32(at):
        need(type(at) is int and 0<=at<=len(raw)-4,'dword bounds');return struct.unpack_from('<I',raw,at)[0]
    def pow2(v):return v>0 and not v&(v-1)
    def align(v,a):return (v+a-1)&~(a-1)
    need(raw[:2]==b'MZ','DOS signature');pe=u32(60)
    need(pe>=64 and pe%4==0 and pe+24<=len(raw) and raw[pe:pe+4]==b'PE\0\0','PE signature/bounds')
    n=u16(pe+6);opt=pe+24;size=u16(pe+20);flags=u16(pe+22)
    need(u16(pe+4)==0x8664 and size==240 and u16(opt)==0x20b,'AMD64 PE32+ required')
    # The exact reviewed image also declares removable/network swap-copy flags.
    need(flags in (0x2022,0x2422,0x2822,0x2c22),'unsupported/non-DLL characteristics')
    need(1<=n<=96 and opt+size+n*40<=len(raw) and u32(pe+12)==u32(pe+16)==0,'section/symbol bounds')
    sa=u32(opt+32);fa=u32(opt+36);headers=u32(opt+60);image=u32(opt+56)
    need(pow2(fa) and 512<=fa<=65536 and pow2(sa) and fa<=sa<=1024*1024,'alignment profile')
    need(headers==align(opt+size+n*40,fa) and headers<=len(raw),'file-backed headers')
    need(0<image<=1024*1024*1024 and image%sa==0 and u32(opt+108)==16,'image/directory bounds')
    sections=[];vspans=[];rspans=[]
    for i in range(n):
        at=opt+size+i*40;vs,va,rs,rp=struct.unpack_from('<IIII',raw,at+8);ch=u32(at+36)
        need(vs>0 and va>=align(headers,sa) and va%sa==0 and va+max(vs,rs)<=image,'section virtual bounds')
        need(rs>0 and rs%fa==0 and rp>=headers and rp%fa==0 and rp+rs<=len(raw),'section raw bounds')
        need(bool(ch&0x40000000) and not ch&0x10000000 and not(ch&0x20000000 and ch&0x80000000),'section permission profile')
        vspans.append((va,va+max(vs,rs)));rspans.append((rp,rp+rs));sections.append((va,vs,rp,rs,ch))
    for spans in (vspans,rspans):
        ordered=sorted(spans);need(all(a[1]<=b[0] for a,b in zip(ordered,ordered[1:])),'overlapping sections')
    def backed(rva,length,executable=False):
        return length>0 and sum(va<=rva and rva+length<=va+min(vs,rs) and (not executable or bool(ch&0x20000000)) for va,vs,rp,rs,ch in sections)==1
    need(backed(u32(opt+16),1,True),'entry is not retained file-backed executable')
    for i in range(16):
        rva,length=u32(opt+112+i*8),u32(opt+116+i*8)
        need((rva==0)==(length==0),'partial directory bounds')
        if not length:continue
        if i==4:need(rva%8==0 and rva>=max(end for start,end in rspans) and rva+length<=len(raw),'certificate file bounds')
        else:need(backed(rva,length),'directory is not unique file-backed span')
        need(i!=14,'managed support image refused')
    return {'envelope':'pinned_Setup_native_AMD64_PE32plus_DLL','machine':'AMD64','optional_magic':'PE32+','image_size':image,'sections':n,'signature_verified':False,'unwind_semantics_verified':False,'import_or_dynamic_dependency_closure_proven':False}

def _recognize_native_tool_image(raw:bytes):
    """Closed AMD64 NGEN file envelope; whole bytes remain operator trust.

    Neither this format result nor association to an active IL file establishes
    compilation authenticity, method equivalence, unwind or dependency closure.
    """
    def need(v,m):_need(v,'Pinned native tool image: '+m)
    need(type(raw) is bytes and 512<=len(raw)<=_NATIVE_IMAGE_CAP,'raw type/size')
    def u16(at):
        need(type(at) is int and 0<=at<=len(raw)-2,'word bounds');return struct.unpack_from('<H',raw,at)[0]
    def u32(at):
        need(type(at) is int and 0<=at<=len(raw)-4,'dword bounds');return struct.unpack_from('<I',raw,at)[0]
    def align(v,a):return (v+a-1)&~(a-1)
    def pow2(v):return v>0 and not v&(v-1)
    need(raw[:2]==b'MZ','DOS signature');pe=u32(60)
    need(pe>=64 and pe%4==0 and pe+24<=len(raw) and raw[pe:pe+4]==b'PE\0\0','PE signature/bounds')
    n=u16(pe+6);opt=pe+24;size=u16(pe+20)
    need(u16(pe+4)==0x8664 and size==240 and u16(opt)==0x20b and u16(pe+22)==0x2022,'native AMD64 PE32+ DLL required')
    need(1<=n<=32 and opt+size+n*40<=len(raw) and u32(pe+12)==u32(pe+16)==0,'section/symbol bounds')
    sa=u32(opt+32);fa=u32(opt+36);headers=u32(opt+60);image=u32(opt+56)
    need(pow2(fa) and 512<=fa<=65536 and pow2(sa) and fa<=sa<=1024*1024,'alignment profile')
    need(headers==align(opt+size+n*40,fa) and headers<=len(raw),'file-backed headers')
    need(0<image<=1024*1024*1024 and image%sa==0 and u32(opt+108)==16,'image/directory bounds')
    sections=[];vspans=[];rspans=[]
    for i in range(n):
        at=opt+size+i*40;vs,va,rs,rp=struct.unpack_from('<IIII',raw,at+8);ch=u32(at+36)
        need(vs>0 and va>=align(headers,sa) and va%sa==0 and va+max(vs,rs)<=image,'section virtual bounds')
        need(rs>0 and rs%fa==0 and rp>=headers and rp%fa==0 and rp+rs<=len(raw),'section raw bounds')
        need(bool(ch&0x40000000) and not ch&0x10000000 and not(ch&0x20000000 and ch&0x80000000),'section permissions')
        sections.append((va,vs,rp,rs,ch));vspans.append((va,va+max(vs,rs)));rspans.append((rp,rp+rs))
    for spans in (vspans,rspans):
        ordered=sorted(spans);need(all(a[1]<=b[0] for a,b in zip(ordered,ordered[1:])),'overlapping sections')
    need(max(b for a,b in rspans)==len(raw),'unclassified file overlay')
    def backed(rva,length,execute=False):
        hits=[rp+rva-va for va,vs,rp,rs,ch in sections if length>0 and va<=rva and rva+length<=va+min(vs,rs) and(not execute or ch&0x20000000)]
        need(len(hits)==1,'unique file-backed RVA span required');return hits[0]
    entry=u32(opt+16)
    if entry:backed(entry,1,True)
    directories={}
    for i in range(16):
        rva,length=u32(opt+112+i*8),u32(opt+116+i*8)
        need((rva==0)==(length==0),'partial directory')
        if length:
            need(i in (2,3,5,6,14),'unsupported native image directory')
            directories[i]=(rva,length,backed(rva,length))
    need(14 in directories,'CLI native image header missing')
    cli_rva,cli_len,cli=directories[14]
    need(cli_len==72 and u32(cli)==72 and (u16(cli+4),u16(cli+6))==(2,5),'CLI header/version')
    need(u32(cli+16)==4 and u32(cli+20)==0,'native image CLI flags/entry')
    spans=[(cli_rva,cli_rva+72)]
    for offset in (8,24,32,40,48,56,64):
        rva,length=u32(cli+offset),u32(cli+offset+4)
        need((rva==0)==(length==0),'partial CLI span')
        if length:
            off=backed(rva,length);spans.append((rva,rva+length))
            if offset==8:need(length>=20 and raw[off:off+4]==b'BSJB','metadata root bounds/signature')
            elif offset==64:need(length==168 and raw[off:off+4]==b'NGE\0' and(u16(off+4),u16(off+6))==(1,0),'NGEN header shape/version')
            elif offset!=32:need(False,'unsupported CLI auxiliary span')
        elif offset in (8,64):need(False,'required CLI span missing')
    ordered=sorted(spans);need(all(a[1]<=b[0] for a,b in zip(ordered,ordered[1:])),'overlapping CLI spans')
    return {'envelope':'operator_pinned_AMD64_NGEN_PE32plus_DLL','image_size':image,'sections':n,'format_is_admission_authority':False,'NI_compilation_authenticity_proven':False,'IL_native_semantic_equivalence_proven':False,'NGEN_dependency_closure_proven':False,'signature_verified':False,'unwind_semantics_verified':False,'JIT_closure_proven':False}


def _recognize_framework_native_image(raw:bytes):
    """Closed AMD64 NGEN envelope with one bounded opaque CLI Resources span.

    Resources are not parsed and no resource-reference closure is claimed.
    Whole bytes remain operator trust; no IL binding or semantic authority.
    """
    def need(v,m):_need(v,'Pinned native tool image: '+m)
    need(type(raw) is bytes and 512<=len(raw)<=_FRAMEWORK_NATIVE_IMAGE_CAP,'raw type/size')
    def u16(at):
        need(type(at) is int and 0<=at<=len(raw)-2,'word bounds');return struct.unpack_from('<H',raw,at)[0]
    def u32(at):
        need(type(at) is int and 0<=at<=len(raw)-4,'dword bounds');return struct.unpack_from('<I',raw,at)[0]
    def align(v,a):return (v+a-1)&~(a-1)
    def pow2(v):return v>0 and not v&(v-1)
    need(raw[:2]==b'MZ','DOS signature');pe=u32(60)
    need(pe>=64 and pe%4==0 and pe+24<=len(raw) and raw[pe:pe+4]==b'PE\0\0','PE signature/bounds')
    n=u16(pe+6);opt=pe+24;size=u16(pe+20)
    need(u16(pe+4)==0x8664 and size==240 and u16(opt)==0x20b and u16(pe+22)==0x2022,'native AMD64 PE32+ DLL required')
    need(1<=n<=32 and opt+size+n*40<=len(raw) and u32(pe+12)==u32(pe+16)==0,'section/symbol bounds')
    sa=u32(opt+32);fa=u32(opt+36);headers=u32(opt+60);image=u32(opt+56)
    need(pow2(fa) and 512<=fa<=65536 and pow2(sa) and fa<=sa<=1024*1024,'alignment profile')
    need(headers==align(opt+size+n*40,fa) and headers<=len(raw),'file-backed headers')
    need(0<image<=1024*1024*1024 and image%sa==0 and u32(opt+108)==16,'image/directory bounds')
    sections=[];vspans=[];rspans=[]
    for i in range(n):
        at=opt+size+i*40;vs,va,rs,rp=struct.unpack_from('<IIII',raw,at+8);ch=u32(at+36)
        need(vs>0 and va>=align(headers,sa) and va%sa==0 and va+max(vs,rs)<=image,'section virtual bounds')
        need(rs>0 and rs%fa==0 and rp>=headers and rp%fa==0 and rp+rs<=len(raw),'section raw bounds')
        need(bool(ch&0x40000000) and not ch&0x10000000 and not(ch&0x20000000 and ch&0x80000000),'section permissions')
        sections.append((va,vs,rp,rs,ch));vspans.append((va,va+max(vs,rs)));rspans.append((rp,rp+rs))
    for spans in (vspans,rspans):
        ordered=sorted(spans);need(all(a[1]<=b[0] for a,b in zip(ordered,ordered[1:])),'overlapping sections')
    need(max(b for a,b in rspans)==len(raw),'unclassified file overlay')
    def backed(rva,length,execute=False):
        hits=[rp+rva-va for va,vs,rp,rs,ch in sections if length>0 and va<=rva and rva+length<=va+min(vs,rs) and(not execute or ch&0x20000000)]
        need(len(hits)==1,'unique file-backed RVA span required');return hits[0]
    entry=u32(opt+16)
    if entry:backed(entry,1,True)
    directories={}
    loader_directory_spans=[]
    for i in range(16):
        rva,length=u32(opt+112+i*8),u32(opt+116+i*8)
        need((rva==0)==(length==0),'partial directory')
        if length:
            need(i in (2,3,5,6,14),'unsupported native image directory')
            directories[i]=(rva,length,backed(rva,length))
            if i!=14:loader_directory_spans.append((rva,rva+length))
    need(14 in directories,'CLI native image header missing')
    cli_rva,cli_len,cli=directories[14]
    need(cli_len==72 and u32(cli)==72 and (u16(cli+4),u16(cli+6))==(2,5),'CLI header/version')
    need(u32(cli+16)==4 and u32(cli+20)==0,'native image CLI flags/entry')
    spans=[(cli_rva,cli_rva+72)]
    framework_resources=None
    for offset in (8,24,32,40,48,56,64):
        rva,length=u32(cli+offset),u32(cli+offset+4)
        need((rva==0)==(length==0),'partial CLI span')
        if length:
            off=backed(rva,length);spans.append((rva,rva+length))
            if offset==8:need(length>=20 and raw[off:off+4]==b'BSJB','metadata root bounds/signature')
            elif offset==24:
                need(length<=1024*1024 and rva%8==0 and length%8==0,
                     'opaque framework CLI resources bounds/alignment')
                framework_resources=(rva,rva+length)
            elif offset==64:need(length==168 and raw[off:off+4]==b'NGE\0' and(u16(off+4),u16(off+6))==(1,0),'NGEN header shape/version')
            elif offset!=32:need(False,'unsupported CLI auxiliary span')
        elif offset==24:need(False,'framework CLI resources span missing')
        elif offset in (8,64):need(False,'required CLI span missing')
    ordered=sorted(spans);need(all(a[1]<=b[0] for a,b in zip(ordered,ordered[1:])),'overlapping CLI spans')
    need(framework_resources is not None,'framework CLI resources span missing')
    rstart,rend=framework_resources
    need(all(rend<=a or b<=rstart for a,b in loader_directory_spans),
         'opaque framework CLI resources overlap loader directory')
    return {'envelope':'operator_pinned_framework_AMD64_NGEN_PE32plus_DLL','image_size':image,'sections':n,'format_is_admission_authority':False,'NI_compilation_authenticity_proven':False,'IL_native_semantic_equivalence_proven':False,'framework_IL_binding_proven':False,'managed_resource_reference_closure_proven':False,'NGEN_dependency_closure_proven':False,'signature_verified':False,'unwind_semantics_verified':False,'JIT_closure_proven':False}


def _validate_metadata_table_tail(raw:bytes,table_start:int,rows_end:int,stream_end:int):
    """Exact relative legacy/canonical zero-tail profiles, not guessed slack.

    The deliberate legacy writer aligns completed records without a terminator.
    The canonical Microsoft writer appends zero then aligns its stream length.
    Absolute PE/file placement is not the table stream's alignment origin.
    """
    message='AnyCPU tool DLL: metadata table record bounds/tail'
    _need(type(raw) is bytes and all(type(v) is int for v in (table_start,rows_end,stream_end)),message)
    _need(0<=table_start<=rows_end<=stream_end<=len(raw) and rows_end-table_start>=24,message)
    length=rows_end-table_start
    legacy=table_start+((length+3)&~3)
    terminated=table_start+((length+4)&~3)
    _need(stream_end in (legacy,terminated) and not any(raw[rows_end:stream_end]),message)
    return 'legacy_aligned_zero' if stream_end==legacy else 'terminated_aligned_zero'

def _recognize_anycpu_tool_dll(raw:bytes,*,_facade_identity=None,_legacy_tool_coff=False,_tool_resource_tail=False):
    """Bounded IL-only PE envelope, not IL/method/PInvoke/JIT verification.

    This helper authenticates nothing. Tool mode first binds the exact opened
    tool pin and freshly verified VCTIP-child LOAD_DLL role. Facade mode instead
    consumes an observed hash under the finite operator-trusted Windows GAC
    profile, the same fresh child role and metadata/path identity consistency;
    that mode does not claim an operator file pin or a verified strong name.
    The private legacy COFF and marked resource-tail bools select envelope
    formats, never authority; no public policy/run toggles exist. Facade mode
    cannot select either extension. Resource file-tail bytes remain hash-bound;
    neither writer authenticity nor mapped inaccessibility is claimed.
    """
    def need(v,m):_need(v,'AnyCPU tool DLL: '+m)
    need(type(_legacy_tool_coff) is bool,'legacy COFF profile selector must be bool')
    need(type(_tool_resource_tail) is bool,'resource-tail profile selector must be bool')
    need(not(_tool_resource_tail and _facade_identity is not None),'resource-tail profile is not a Windows facade profile')
    need(not(_legacy_tool_coff and _facade_identity is not None),'legacy COFF profile is not a Windows facade profile')
    need(type(raw) is bytes and 512<=len(raw)<=128*1024*1024,'raw type/size')
    def u16(at):
        need(type(at) is int and 0<=at<=len(raw)-2,'word bounds');return struct.unpack_from('<H',raw,at)[0]
    def u32(at):
        need(type(at) is int and 0<=at<=len(raw)-4,'dword bounds');return struct.unpack_from('<I',raw,at)[0]
    def pow2(v):return v>0 and v&(v-1)==0
    def aligned(v,a):return (v+a-1)&~(a-1)
    need(raw[:2]==b'MZ','DOS signature');pe=u32(60);need(pe>=64 and pe%4==0 and pe+24<=len(raw) and raw[pe:pe+4]==b'PE\0\0','PE signature/bounds')
    need(u16(pe+4)==0x14c,'not I386 declaration');nsec=u16(pe+6);optsize=u16(pe+20);ch=u16(pe+22);opt=pe+24
    need(1<=nsec<=96 and optsize==224 and opt+optsize+40*nsec<=len(raw),'section/PE32 optional header bounds')
    # Format selector only: it grants no file/role/admission authority. The
    # consumer enables it only after exact tool pin + fresh VCTIP LOAD proof.
    need((ch&0x2002==0x2002 and ch&~0x2022==0) or (_legacy_tool_coff and ch==0x2102),'unsupported/non-DLL file characteristics')
    need(u32(pe+12)==0 and u32(pe+16)==0 and u16(opt)==0x10b,'symbols/non-PE32 header')
    entry=u32(opt+16);base=u32(opt+28);salign=u32(opt+32);falign=u32(opt+36);image_size=u32(opt+56);headers=u32(opt+60)
    need(pow2(falign) and 512<=falign<=65536 and pow2(salign) and falign<=salign<=1024*1024,'alignment profile')
    need(0<base<=0xffffffff and base%65536==0 and 0<image_size<=1024*1024*1024 and image_size%salign==0,'image base/size')
    need(headers==aligned(opt+optsize+40*nsec,falign) and headers<=len(raw) and headers%falign==0,'file-backed header extent')
    need(u32(opt+92)==16,'exact directory count');dirs=tuple((u32(opt+96+i*8),u32(opt+100+i*8)) for i in range(16))
    allowed={1,2,4,5,6,12,14}
    need(all((i in allowed or d==(0,0)) and ((d[0]==0)==(d[1]==0)) for i,d in enumerate(dirs)),'unknown/native callback directory')
    sections=[];rawspans=[];virtualspans=[];marked_resource=None;section_names=[]
    for i in range(nsec):
        at=opt+optsize+40*i;vs,va,rs,rp=struct.unpack_from('<IIII',raw,at+8);flags=u32(at+36)
        need(vs>0 and va>=aligned(headers,salign) and va%salign==0 and va+max(vs,rs)<=image_size,'section virtual extent')
        need(rs>0 and rs%falign==0 and rp>=headers and rp%falign==0 and rp+rs<=len(raw),'section raw extent')
        need(not flags&0x80000000,'writable managed section profile')
        need(not flags&0x10000000 and bool(flags&0x40000000),'shared/non-readable managed section')
        if flags&0x2000000:need(not flags&0x20000000 and (va,vs)==dirs[5],'discardable non-relocation section')
        section_name=raw[at:at+8];section_names.append(section_name)
        tail=raw[rp+vs:rp+rs] if rs>vs else b''
        if any(tail):
            need(_tool_resource_tail,'nonzero file alignment padding')
            need(marked_resource is None and section_name==b'.rsrc\0\0\0' and flags==0x40000040,
                 'marked resource-tail section/permissions profile')
            need(rs==aligned(vs,falign) and 0<len(tail)<falign and vs%16==0 and len(tail)%16==0,
                 'marked resource-tail alignment/length profile')
            need(tail==b'PADDINGXXPADDING'*(len(tail)//16),'marked resource-tail phase/content profile')
            marked_resource=(va,vs,rp,rs)
        sections.append((va,vs,rp,rs,flags));rawspans.append((rp,rp+rs));virtualspans.append((va,va+aligned(max(vs,rs),salign)))
    for spans in (rawspans,virtualspans):
        ordered=sorted(spans);need(all(a[1]<=b[0] for a,b in zip(ordered,ordered[1:])),'overlapping section mapping')
    need(image_size==max(end for _,end in virtualspans),'declared image extent differs')
    def file_span(rva,size,*,executable=None):
        need(type(rva) is int and type(size) is int and rva>0 and size>0 and rva+size<=image_size,'RVA span bounds')
        matches=[s for s in sections if s[0]<=rva and rva+size<=s[0]+min(s[1],s[3])]
        need(len(matches)==1,'RVA not uniquely fully file-backed');va,vs,rp,rs,flags=matches[0]
        if executable is not None:need(bool(flags&0x20000000)==executable,'executable span mismatch')
        return rp+rva-va
    resource_tail_evidence=None
    if marked_resource is not None:
        va,vs,rp,rs=marked_resource
        need(section_names.count(b'.rsrc\0\0\0')==1 and dirs[2]==(va,vs) and vs<=16*1024*1024,
             'marked resource directory must exactly cover unique logical .rsrc')
        need(all(not rva or i in (2,4) or rva+size<=va or va+rs<=rva
                 for i,(rva,size) in enumerate(dirs)),
             'other directory overlaps marked resource section')
        # A closed three-level resource tree is structural evidence only. Names
        # are never interpreted as filesystem paths. Shared/cyclic structures,
        # overlapping payloads and references into file alignment tails reject.
        occupied=[];visited=set();entry_count=0;name_bytes=0;leaf_count=0
        def own(relative,length,label,alignment=1):
            need(type(relative) is int and type(length) is int and relative>=0 and length>0 and
                 relative%alignment==0 and relative+length<=vs,
                 'resource '+label+' lies outside logical VirtualSize')
            need(len(occupied)<8192 and all(relative+length<=a or b<=relative for a,b in occupied),
                 'overlapping/aliased resource structures or payloads')
            occupied.append((relative,relative+length));return rp+relative
        def resource_name(value):
            nonlocal name_bytes
            if not value&0x80000000:
                need(value<=0xffff,'resource integer ID reserved bits');return ('id',value)
            relative=value&0x7fffffff
            need(relative%2==0 and relative+2<=vs,'resource name prefix bounds')
            count=u16(rp+relative);need(0<count<=256,'resource name length')
            at=own(relative,2+2*count,'name',2);name_bytes+=2*count
            need(name_bytes<=65536,'resource name work bound')
            try:name=raw[at+2:at+2+2*count].decode('utf-16le')
            except UnicodeError as exc:raise CompilerTraceError('AnyCPU tool DLL: malformed resource name') from exc
            need('\0' not in name,'embedded null resource name');return ('name',name)
        def resource_directory(relative,depth):
            nonlocal entry_count,leaf_count
            need(depth<3 and relative not in visited and len(visited)<256,'cyclic/aliased/deep resource directory')
            need(relative%4==0 and relative+16<=vs,'resource directory prefix bounds')
            visited.add(relative);named,ids=u16(rp+relative+12),u16(rp+relative+14);count=named+ids
            need(0<count<=256 and entry_count+count<=4096,'resource directory work bound');entry_count+=count
            at=own(relative,16+8*count,'directory',4);need(u32(at)==0,'resource directory reserved characteristics');keys=set()
            for index in range(count):
                value,target=struct.unpack_from('<II',raw,at+16+8*index)
                need(bool(value&0x80000000)==(index<named),'resource named/ID entry order')
                key=resource_name(value);need(key not in keys,'duplicate resource entry key');keys.add(key)
                if target&0x80000000:
                    need(depth<2,'resource branch beyond language level');resource_directory(target&0x7fffffff,depth+1)
                else:
                    need(depth==2,'resource leaf before language level')
                    entry=own(target,16,'data entry',4)
                    data_rva,size,codepage,reserved=struct.unpack_from('<IIII',raw,entry)
                    need(reserved==0 and size>0 and va<=data_rva and data_rva+size<=va+vs,
                         'resource leaf outside logical VirtualSize/reserved')
                    payload=own(data_rva-va,size,'leaf')
                    need(file_span(data_rva,size)==payload,'resource leaf backing differs');leaf_count+=1
        resource_directory(0,0)
        need(leaf_count>0,'marked resource tree has no leaves')
        previous=0
        for start,stop in sorted(occupied):
            need(start>=previous,'overlapping resource ownership union')
            if start>previous:
                gap=raw[rp+previous:rp+start]
                need(start==aligned(previous,4) and len(gap)<=3 and
                     (not any(gap) or gap==b'PADDINGXXPADDING'[:len(gap)]),
                     'unclassified logical resource alignment gap')
            previous=stop
        need(aligned(previous,4)==vs,'resource logical end/alignment differs')
        gap=raw[rp+previous:rp+vs]
        need(len(gap)<=3 and (not any(gap) or gap==b'PADDINGXXPADDING'[:len(gap)]),
             'unclassified terminal resource alignment gap')
        # Debug payloads carry both an RVA and a file pointer. The latter cannot
        # hide a reference into the marked tail while its directory stays valid.
        debug_rva,debug_size=dirs[6]
        if debug_rva:
            need(debug_size%28==0 and debug_size//28<=4096,'marked resource debug table profile')
            debug=file_span(debug_rva,debug_size)
            for index in range(debug_size//28):
                at=debug+28*index;size=u32(at+16);rva=u32(at+20);pointer=u32(at+24)
                if size:
                    need(pointer==file_span(rva,size),'debug file/RVA payload mismatch')
                else:need(rva==pointer==0,'empty debug payload has an address')
        tail=raw[rp+vs:rp+rs]
        resource_tail_evidence={'profile':'phase0_marked_readonly_rsrc_file_tail',
            'file_offset':rp+vs,'size':len(tail),'sha256':hashlib.sha256(tail).hexdigest(),
            'candidate_rva_start':va+vs,'candidate_rva_end':va+rs,
            'resource_directories':len(visited),'resource_entries':entry_count,'resource_leaves':leaf_count,
            'logical_resource_bounds_proven':True,'raw_bytes_preserved':True,
            'mapped_inaccessibility_proven':False,'writer_authenticity_proven':False,
            'resource_tail_profile_is_admission_authority':False}
    # Security directory uses a FILE offset, never an RVA. No opaque overlay.
    last_raw=max(end for _,end in rawspans);cert,cert_size=dirs[4]
    if cert:
        need(cert==aligned(last_raw,8) and cert%8==0 and cert+cert_size==len(raw),'certificate/overlay file bounds')
        pos=cert
        while pos<cert+cert_size:
            length=u32(pos);need(length>=8 and pos+length<=cert+cert_size and u16(pos+4)==0x200 and u16(pos+6)==2,'certificate record bounds/type')
            end=aligned(pos+length,8);need(end<=cert+cert_size and not any(raw[pos+length:end]),'certificate padding');pos=end
        need(pos==cert+cert_size,'certificate table tail')
    else:need(last_raw==len(raw),'unclassified file overlay')
    for i,(rva,size) in enumerate(dirs):
        if rva and i!=4:file_span(rva,size)
    clr_rva,clr_size=dirs[14];need(clr_size==72,'CLI directory absent/size');clr=file_span(clr_rva,72,executable=True)
    need(u32(clr)==72 and (u16(clr+4),u16(clr+6))==(2,5),'CLI header version/size')
    flags=u32(clr+16);need(flags in (1,9),'ILONLY/32bit/native/unknown flags');need(u32(clr+20)==0,'DLL managed entry token')
    meta_rva,meta_size=u32(clr+8),u32(clr+12);need(32<=meta_size<=32*1024*1024,'metadata size');meta=file_span(meta_rva,meta_size,executable=True)
    # All native/mixed-mode directories must be absent, not merely unused.
    need(all(u32(clr+o)==0 and u32(clr+o+4)==0 for o in (40,48,56,64)),'mixed/native CLI directory')
    cli_spans=[(clr_rva,clr_rva+72),(meta_rva,meta_rva+meta_size)]
    for o in (24,32):
        rva,size=u32(clr+o),u32(clr+o+4);need((rva==0)==(size==0),'half CLI resource/signature span')
        if rva:file_span(rva,size);cli_spans.append((rva,rva+size))
    need(bool(flags&8)==bool(u32(clr+36)),'strong-name flag/span mismatch')
    ordered=sorted(cli_spans);need(all(a[1]<=b[0] for a,b in zip(ordered,ordered[1:])),'overlapping CLI/metadata spans')
    other_dirs=[(rva,rva+size) for i,(rva,size) in enumerate(dirs) if rva and i not in (4,14)]
    need(all(b<=c or d<=a for a,b in cli_spans for c,d in other_dirs),'CLI span overlaps other loader directory')
    # One canonical CLR bootstrap import, exactly one IAT entry+terminator.
    irva,isize=dirs[1];need(40<=isize<=512,'import directory profile');imp=file_span(irva,isize,executable=True)
    oft,tstamp,forward,name_rva,first=struct.unpack_from('<IIIII',raw,imp)
    need(tstamp==0 and forward==0 and not any(raw[imp+20:imp+40]) and dirs[12]==(first,8),'import descriptors/IAT shape')
    def cstring(rva,limit):
        start=file_span(rva,1);end=raw.find(b'\0',start,start+limit);need(end>=start,'unterminated bootstrap import');file_span(rva,end-start+1);return raw[start:end]
    need(cstring(name_rva,32).lower()==b'mscoree.dll','unknown bootstrap DLL')
    lookup=file_span(oft,8,executable=True);iat=file_span(first,8,executable=True);hint_rva=u32(lookup)
    need(hint_rva>0 and hint_rva<0x80000000 and u32(lookup+4)==0 and u32(iat)==hint_rva and u32(iat+4)==0,'import lookup/IAT terminators')
    hint=file_span(hint_rva,2);need(u16(hint)==0 and cstring(hint_rva+2,32)==b'_CorDllMain','unknown bootstrap function')
    ep=file_span(entry,6,executable=True);need(raw[ep:ep+2]==b'\xff\x25' and u32(ep+2)==base+first<=0xffffffff,'noncanonical native bootstrap')
    rrva,rsize=dirs[5];need(rsize==12,'relocation directory profile');rel=file_span(rrva,12,executable=False)
    need(u32(rel)==((entry+2)&~0xfff) and u32(rel+4)==12 and u16(rel+8)==0x3000|((entry+2)&0xfff) and u16(rel+10)==0,'noncanonical bootstrap relocation')
    # Bounded ECMA metadata root/stream envelope, not table/method verification.
    end=meta+meta_size;need(raw[meta:meta+4]==b'BSJB' and u16(meta+4)==1 and u16(meta+6)==1 and u32(meta+8)==0,'metadata root signature/version')
    vlen=u32(meta+12);need(4<=vlen<=256 and vlen%4==0 and meta+16+vlen+4<=end,'metadata version bounds')
    version=raw[meta+16:meta+16+vlen];zero=version.find(0);need(zero>0 and not any(version[zero:]) and re.fullmatch(rb'v[0-9]+\.[0-9]+\.[0-9]+',version[:zero]) is not None,'metadata version string')
    pos=meta+16+vlen;need(u16(pos)==0,'metadata flags');count=u16(pos+2);pos+=4;need(count==5,'metadata stream inventory')
    streams={};spans=[]
    for _ in range(count):
        need(pos+8<=end,'stream header bounds');off,size=u32(pos),u32(pos+4);pos+=8
        stop=raw.find(b'\0',pos,min(pos+32,end));need(stop>=pos,'stream name bounds');name=raw[pos:stop]
        need(name in (b'#~',b'#Strings',b'#US',b'#GUID',b'#Blob') and name not in streams,'unknown/duplicate stream')
        padded=aligned(stop+1,4);need(padded<=end and not any(raw[stop:padded]),'stream name padding');pos=padded
        need(off%4==0 and size>0 and off+size<=meta_size,'stream extent');streams[name]=(off,size);spans.append((off,off+size))
    ordered=sorted(spans);need(ordered[0][0]==pos-meta and all(a[1]==b[0] for a,b in zip(ordered,ordered[1:])) and ordered[-1][1]==meta_size,'overlapping/gapped metadata streams')
    for name in (b'#Strings',b'#US',b'#Blob'):need(raw[meta+streams[name][0]]==0,'heap zero entry')
    need(streams[b'#GUID'][1]%16==0,'GUID heap size')
    table_off,table_size=streams[b'#~'];table=meta+table_off;need(table_size>=24 and u32(table)==0 and raw[table+4:table+6]==b'\x02\x00' and raw[table+6]&~7==0 and raw[table+7]==1,'tables header')
    valid,sorted_mask=struct.unpack_from('<QQ',raw,table+8);need(valid>>45==0 and sorted_mask>>45==0 and valid&1 and valid&(1<<32),'tables mask/module/assembly')
    need(not valid&((1<<3)|(1<<5)|(1<<7)|(1<<19)|(1<<22)),'unoptimized pointer tables')
    row_end=table+24+4*valid.bit_count();need(row_end<=table+table_size,'table row count header bounds');cursor=table+24;rows={}
    for i in range(45):
        if valid&(1<<i):
            rows[i]=u32(cursor);cursor+=4;need(0<rows[i]<=1000000,'table row count bound')
    need(rows[0]==1 and rows[32]==1,'module/assembly row count')
    need(not valid&((1<<30)|(1<<31)) and sum(rows.values())<=250000,'delta tables/total row work limit')
    heaps=raw[table+6];hs={'s':4 if heaps&1 else 2,'g':4 if heaps&2 else 2,'b':4 if heaps&4 else 2}
    need(bool(heaps&1)==(streams[b'#Strings'][1]>=65536) and bool(heaps&2)==(streams[b'#GUID'][1]>=65536) and bool(heaps&4)==(streams[b'#Blob'][1]>=65536),'heap index width profile')
    # ECMA II.22 ordinary compressed table row widths. This proves record
    # boundaries only, not every coded token, signature, method or JIT behavior.
    coded={'res':(2,(0,26,35,1)),'tdr':(2,(2,1,27)),'hc':(2,(4,8,23)),'hca':(5,(6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43)),'cat':(3,(6,10)),'hfm':(1,(4,8)),'hds':(2,(2,6,32)),'mrp':(3,(2,1,26,6,27)),'hsem':(1,(20,23)),'mdr':(1,(6,10)),'mf':(1,(4,6)),'impl':(2,(38,35,39)),'tom':(1,(2,6))}
    layouts={0:(2,'s','g','g','g'),1:('res','s','s'),2:(4,'s','s','tdr',('t',4),('t',6)),4:(2,'s','b'),6:(4,2,2,'s','b',('t',8)),8:(2,2,'s'),9:(('t',2),'tdr'),10:('mrp','s','b'),11:(2,'hc','b'),12:('hca','cat','b'),13:('hfm','b'),14:(2,'hds','b'),15:(2,4,('t',2)),16:(4,('t',4)),17:('b',),18:(('t',2),('t',20)),20:(2,'s','tdr'),21:(('t',2),('t',23)),23:(2,'s','b'),24:(2,('t',6),'hsem'),25:(('t',2),'mdr','mdr'),26:('s',),27:('b',),28:(2,'mf','s',('t',26)),29:(4,('t',4)),32:(4,2,2,2,2,4,'b','s','s'),33:(4,),34:(4,4,4),35:(2,2,2,2,4,'b','s','s','b'),36:(4,('t',35)),37:(4,4,4,('t',35)),38:(4,'s','b'),39:(4,4,'s','s','impl'),40:(4,4,'s','impl'),41:(('t',2),('t',2)),42:(2,2,'tom','s'),43:('mdr','b'),44:(('t',42),'tdr')}
    def width(col):
        if type(col) is int:return col
        if type(col) is tuple:return 4 if rows.get(col[1],0)>=65536 else 2
        if col in hs:return hs[col]
        bits,targets=coded[col];return 4 if max(rows.get(t,0) for t in targets)>=(1<<(16-bits)) else 2
    widths={i:sum(width(c) for c in layouts[i]) for i in rows};offsets={};table_cursor=row_end
    for i in sorted(rows):offsets[i]=table_cursor;table_cursor+=rows[i]*widths[i]
    _validate_metadata_table_tail(raw,table,table_cursor,table+table_size)
    for i in range(rows.get(6,0)):
        at=offsets[6]+i*widths[6];impl=u16(at+4)
        need(impl&7 in (0,3),'native/OPTIL/unmanaged method declaration')
    result={'machine':'I386','optional_magic':'PE32','envelope':'AnyCPU_ILONLY_compiler_tool_DLL','image_size':image_size,'CLI_flags':flags,'metadata_version':version[:zero].decode('ascii'),'metadata_size':meta_size,'metadata_streams':{name.decode('ascii'):{'offset':v[0],'size':v[1]} for name,v in streams.items()},'table_rows':rows,'metadata_table_record_bounds_proven':True,'canonical_CorDllMain_bootstrap':True,'managed_assembly_verification_proven':False,'managed_dependency_closure_proven':False,'native_x86_admission':False,'authenticode_signature_verified':False,'COFF_characteristics':ch,'COFF_format_profile':'legacy_tool_ILONLY_2102' if ch==0x2102 else 'default_ILONLY','COFF_profile_is_admission_authority':False}
    if resource_tail_evidence is not None:result['marked_resource_file_tail']=resource_tail_evidence
    if _facade_identity is not None:
        result['facade_identity']=_facade_metadata(raw,meta,streams,rows,offsets,widths,layouts,width,_facade_identity)
        result['envelope']='Windows_GAC_MSIL_framework_pure_facade'
    return result


_FACADE_TOKENS=('b03f5f7f11d50a3a','b77a5c561934e089')
_FACADE_REFERENCES=frozenset(('mscorlib','System','System.Core','System.ComponentModel.Composition','System.Runtime.Serialization','System.ServiceModel','System.Xml','System.Xml.Linq'))

def _facade_domain(path:Path,windows:Path):
    """ASCII exact framework path shape only; no arbitrary GAC/Windows prefix."""
    base=windows/'Microsoft.NET'/'assembly'/'GAC_MSIL'
    if not path.is_relative_to(base):return None
    parts=path.relative_to(base).parts
    if len(parts)!=3:return None
    name,version,filename=parts
    if re.fullmatch(r'System(?:\.[A-Za-z_][A-Za-z0-9_]*)*',name) is None or filename!=name+'.dll':return None
    for token in _FACADE_TOKENS:
        if version=='v4.0_4.0.0.0__'+token:return (name,token)
    return None

def _facade_metadata(raw,meta,streams,rows,offsets,widths,layouts,width,identity):
    """Closed metadata consistency, not strong-name/CLR/method verification.

    Only verified VCTIP LOAD_DLL under actual Windows may consume this result.
    Windows CLR/GAC/config/JIT behavior remains explicitly operator-trusted.
    """
    def need(v,m):_need(v,'Windows facade: '+m)
    need(type(identity) is tuple and len(identity)==2 and all(type(x) is str for x in identity),'identity type')
    name,token=identity;need(re.fullmatch(r'System(?:\.[A-Za-z_][A-Za-z0-9_]*)*',name) is not None and token in _FACADE_TOKENS,'identity profile')
    need(set(rows)<={0,1,2,10,12,32,35,39} and rows.get(2)==1 and 1<=rows.get(39,0)<=10000 and 1<=rows.get(35,0)<=64,'closed table inventory')
    need(rows.get(1,0)<=128 and rows.get(10,0)<=128 and rows.get(12,0)<=256,'metadata work bounds')
    def record(table,rid):
        need(table in rows and type(rid) is int and 1<=rid<=rows[table],'table row reference')
        pos=offsets[table]+(rid-1)*widths[table];values=[]
        for col in layouts[table]:
            size=width(col);values.append(int.from_bytes(raw[pos:pos+size],'little'));pos+=size
        return values
    def string(index,limit=512):
        off,size=streams[b'#Strings'];need(type(index) is int and 0<=index<size,'string index')
        start=meta+off+index;end=raw.find(b'\0',start,min(meta+off+size,start+limit+1));need(end>=start,'string limit/termination')
        text=raw[start:end];need(all(b<128 for b in text),'non-ASCII metadata identity')
        return text.decode('ascii')
    def blob(index):
        off,size=streams[b'#Blob'];need(type(index) is int and 0<=index<size,'blob index');pos=meta+off+index;first=raw[pos]
        if first<128:length=first;head=1
        elif first&0xc0==0x80:
            need(index+2<=size,'blob length2');length=((first&0x3f)<<8)|raw[pos+1];head=2;need(length>=128,'noncanonical blob length2')
        elif first&0xe0==0xc0:
            need(index+4<=size,'blob length4');length=((first&0x1f)<<24)|int.from_bytes(raw[pos+1:pos+4],'big');head=4;need(length>=16384,'noncanonical blob length4')
        else:need(False,'invalid compressed blob')
        need(length<=1024*1024 and index+head+length<=size,'blob body bounds');return raw[pos+head:pos+head+length]
    def type_name(text):return re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:`[1-9][0-9]*)?',text) is not None
    def namespace(text):return text=='' or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*',text) is not None
    a=record(32,1);key=blob(a[6]);derived=hashlib.sha1(key).digest()[-8:][::-1].hex()
    need(a[0]==0x8004 and a[1:5]==[4,0,0,0] and a[5]==1 and 16<=len(key)<=4096,'assembly identity declaration')
    need(string(a[7])==name and string(a[8])=='' and derived==token,'assembly/path name/version/culture/public-key token mismatch')
    m=record(0,1);need(m[0]==0 and string(m[1])==name+'.dll' and m[2:]==[1,0,0],'Module identity declaration')
    module=record(2,1);need(module[0]==0 and string(module[1])=='<Module>' and string(module[2])=='' and module[3:]==[0,1,1],'only Module TypeDef required')
    refs=[]
    for rid in range(1,rows[35]+1):
        r=record(35,rid);ref_name=string(r[6]);ref_token=blob(r[5]);need(r[:4]==[4,0,0,0] and r[4]==0 and ref_name in _FACADE_REFERENCES and ref_name!=name and string(r[7])=='' and ref_token.hex()=='b77a5c561934e089' and blob(r[8])==b'','unreviewed AssemblyRef identity')
        refs.append(ref_name)
    need(len(refs)==len(set(refs)),'duplicate AssemblyRef identity')
    # Every TypeRef resolves to a bounded framework AssemblyRef, possibly through
    # nested TypeRefs. No Module/ModuleRef or local/multi-module escape exists.
    typerefs=[]
    for rid in range(1,rows.get(1,0)+1):
        r=record(1,rid);need(type_name(string(r[1])) and namespace(string(r[2])),'TypeRef name/namespace');typerefs.append(r)
    def typeref_terminal(rid):
        seen=set()
        while True:
            need(1<=rid<=len(typerefs) and rid not in seen and len(seen)<64,'TypeRef bounds/cycle/depth');seen.add(rid);scope=typerefs[rid-1][0];tag,target=scope&3,scope>>2
            if tag==2:need(1<=target<=len(refs),'TypeRef AssemblyRef bounds');return target
            need(tag==3 and string(typerefs[rid-1][2])=='','non-framework TypeRef scope');rid=target
    for rid in range(1,len(typerefs)+1):typeref_terminal(rid)
    for rid in range(1,rows.get(10,0)+1):
        r=record(10,rid);need(r[0]&7==1 and 1<=r[0]>>3<=len(typerefs) and string(r[1])=='.ctor' and len(blob(r[2]))>0,'MemberRef not bounded framework attribute constructor')
    for rid in range(1,rows.get(12,0)+1):
        r=record(12,rid);need(r[0]==(1<<5)|14 and r[1]&7==3 and 1<=r[1]>>3<=rows.get(10,0) and len(blob(r[2]))>0,'CustomAttribute not bounded assembly attribute')
    exported=[];unique=set()
    for rid in range(1,rows[39]+1):
        r=record(39,rid);tn,ns=string(r[2]),string(r[3]);tag,target=r[4]&3,r[4]>>2
        need(r[1]==0 and type_name(tn) and namespace(ns),'ExportedType declaration')
        need((tag==1 and r[0]==0x200000 and 1<=target<=len(refs)) or (tag==2 and r[0]==0 and ns=='' and 1<=target<=rows[39]),'ExportedType implementation/flags')
        key=(ns,tn,tag,target if tag==2 else 0);need(key not in unique,'duplicate ExportedType');unique.add(key);exported.append((tag,target))
    terminal_counts={}
    for start in range(1,len(exported)+1):
        seen=set();rid=start
        while True:
            need(1<=rid<=len(exported) and rid not in seen and len(seen)<64,'ExportedType bounds/cycle/depth');seen.add(rid);tag,target=exported[rid-1]
            if tag==1:terminal_counts[refs[target-1]]=terminal_counts.get(refs[target-1],0)+1;break
            rid=target
    return {'assembly_name':name,'assembly_version':'4.0.0.0','neutral_culture':True,'public_key_derived_token':derived,'public_key_token_is_authenticity':False,'MethodDef_count':0,'Field_count':0,'TypeDef_count':1,'ExportedType_count':len(exported),'nested_ExportedType_count':sum(tag==2 for tag,target in exported),'framework_AssemblyRefs':refs,'terminal_forwarder_counts':terminal_counts,'strong_name_signature_verified':False,'managed_assembly_verification_proven':False,'managed_dependency_closure_proven':False,'OS_CLR_GAC_config_JIT_operator_trusted':True}

def _managed_tool_load_role(event_code,pid,root_pid,approved_image_path,approved_image_pinned,parent_pid,root_image):
    return (type(event_code) is int and event_code==6 and type(pid) is int and type(root_pid) is int and 0<pid!=root_pid and root_pid>0 and type(parent_pid) is int and parent_pid==root_pid and approved_image_pinned is True and type(root_image) is type(Path()) and root_image.name.casefold() in ('cl.exe','ml64.exe') and approved_image_path==str(root_image.parent/'vctip.exe'))

def _platform_domain(path:Path,windows:Path):
    """Finite operator-trusted native loader domains, not all of Windows."""
    if path.parent==windows/'System32':return 'System32_direct'
    if path.parent.parent==windows/'WinSxS' and path.parent.name.casefold().startswith('amd64_'):return 'WinSxS_amd64_direct'
    clr=windows/'Microsoft.NET'/'Framework64'/'v4.0.30319'
    if path.parent==clr and path.suffix.casefold()=='.dll':return 'CLR_Framework64_v4_direct_dll'
    native=windows/'assembly'/'NativeImages_v4.0.30319_64'
    if path.is_relative_to(native):
        parts=path.relative_to(native).parts
        if len(parts)==3 and re.fullmatch(r'(?:mscorlib|System(?:\.[A-Za-z_][A-Za-z0-9_]*)*)',parts[0],re.IGNORECASE) and re.fullmatch(r'[0-9a-f]{32}',parts[1]) and parts[2].casefold()==parts[0].casefold()+'.ni.dll':return 'CLR_standard_NativeImages64'
    return None

class _LockedPolicy:
    def __init__(self,policy,k):
        self.k=k;self.handles=[];self.rows={};self.support={};self.native_images={};self.framework_native_images={};self.windows=None;self.allowed=()
        try:
            _need(type(policy) is CompilerTracePolicy and type(policy.tool_pins) is tuple and 1<=len(policy.tool_pins)<=128 and type(policy.allowed_child_images) is tuple,'invalid trace policy types/count')
            _need(type(policy.support_pins) is tuple and len(policy.support_pins)<=1,'invalid support pin types/count')
            for pair in policy.support_pins:
                _need(type(pair) is tuple and len(pair)==2,'invalid support pin record')
                p,digest=pair
                _need(type(p) is type(Path()) and p==_SETUP_SUPPORT_PATH,'support path is not fixed Setup Configuration DLL')
                _need(type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest) is not None,'invalid support pin digest')
            families=_native_image_pin_shape(policy.native_image_pins)
            framework_pin = _framework_native_image_pin_shape(policy.framework_native_image_pins)
            if framework_pin:
                _need(all(type(pair) is tuple and len(pair)==2 and
                          type(pair[0]) is type(Path()) and type(pair[1]) is str and
                          re.fullmatch('[0-9a-f]{64}',pair[1]) is not None
                          for pair in policy.tool_pins),
                      'invalid tool pin records for framework native-image profile')
                _need(all(type(p) is type(Path()) for p in policy.allowed_child_images),
                      'invalid allowed child elements for framework native-image profile')
                child_roots=[p.parent for p in policy.allowed_child_images if p.name=='vctip.exe']
                _need(len(child_roots)==1 and all(any(pair[0]==child_roots[0]/name
                      for pair in policy.tool_pins)
                      for name in ('cl.exe','ml64.exe','vctip.exe')),
                      'framework native-image role requires exact current compiler/helper pins')
            if _NEWTON_IMAGE_NAME in families:
                # Only V4 opts into the new early shape checks. The V3 singleton
                # retains its previous Windows/tool/lock validation precedence.
                _need(all(type(pair) is tuple and len(pair)==2 and type(pair[0]) is type(Path()) and type(pair[1]) is str and re.fullmatch('[0-9a-f]{64}',pair[1]) is not None for pair in policy.tool_pins),'invalid tool pin records for native-image profile')
                _need(all(type(p) is type(Path()) for p in policy.allowed_child_images),'invalid allowed child elements for v4 native-image profile')
                child_roots=[p.parent for p in policy.allowed_child_images if p.name=='vctip.exe']
                _need(len(child_roots)==1 and all(any(pair[0]==child_roots[0]/_native_image_il_name(name) for pair in policy.tool_pins) for name in families),'native-image profile requires exact current helper/IL tool pins')
            _ordinary(policy.windows_root,directory=True)
            b=ctypes.create_unicode_buffer(4097);n=k.GetWindowsDirectoryW(b,4097)
            _need(0<n<4097 and policy.windows_root==Path(b.value),'policy Windows root is not actual explicit Windows directory')
            self.windows=policy.windows_root
            paths=set();identities=set()
            for pair in policy.tool_pins:
                _need(type(pair) is tuple and len(pair)==2,'invalid tool pin record')
                p,digest=pair;_ordinary(p)
                _need(type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest) is not None,'invalid tool pin digest')
                name=p.name.casefold();_need(name not in (_SETUP_SUPPORT_NAME,_NATIVE_IMAGE_NAME,_NEWTON_IMAGE_NAME,_FRAMEWORK_NATIVE_IMAGE_NAME),'support/native image must use separate pins');_need(p not in paths,'duplicate compiler path');paths.add(p)
                h=k.CreateFileW(str(p),0x80000000,1,None,3,0x80,None);_need(h not in (None,_INVALID),'tool read lock failed');self.handles.append(h)
                info=_file_info(k,h);identity=(info['volume'],info['index']);_need(info['links']==1 and identity not in identities,'tool physical identity alias');identities.add(identity)
                _need(1<=info['size']<=128*1024*1024 and hashlib.sha256(p.read_bytes()).hexdigest()==digest,'tool bytes differ before launch')
                self.rows.setdefault(name,[]).append({'path':p,'sha256':digest,'identity':identity,'handle':h,'info':info})
            for p,digest in policy.support_pins:
                _ordinary(p);h=k.CreateFileW(str(p),0x80000000,1,None,3,0x80,None)
                _need(h not in (None,_INVALID),'support read lock failed');self.handles.append(h)
                info=_file_info(k,h);identity=(info['volume'],info['index'])
                _need(info['links']==1 and identity not in identities,'support physical identity alias')
                _need(1<=info['size']<=_SETUP_SUPPORT_CAP,'support file size cap');identities.add(identity)
                actual,row=_read_image(k,h,retain_native_raw=True);raw=row.pop('_native_raw',None)
                _need(actual==p and row['sha256']==digest,'support bytes/path differ before launch')
                envelope=_recognize_setup_support_dll(raw)
                self.support[p.name.casefold()]={'path':p,'sha256':digest,'identity':identity,'handle':h,'info':info,'envelope':envelope}
            for p,digest in policy.native_image_pins:
                _ordinary_native_image(p);h=k.CreateFileW(str(p),0x80000000,1,None,3,0x80,None)
                _need(h not in (None,_INVALID),'native-image read lock failed');self.handles.append(h)
                info=_file_info(k,h);identity=(info['volume'],info['index'])
                _need(info['links']==1 and identity not in identities,'native-image physical identity alias')
                _need(1<=info['size']<=_NATIVE_IMAGE_CAP,'native-image file size cap');identities.add(identity)
                actual,row=_read_image(k,h,retain_native_raw=True);raw=row.pop('_native_raw',None)
                _need(actual==p and row['sha256']==digest and all(row[key]==info[key] for key in info),'native-image bytes/path differ before launch')
                envelope=_recognize_native_tool_image(raw)
                self.native_images[p.name.casefold()]={'path':p,'sha256':digest,'identity':identity,'handle':h,'info':info,'envelope':envelope}
            for p,digest in policy.framework_native_image_pins:
                _ordinary_framework_native_image(p);h=k.CreateFileW(str(p),0x80000000,1,None,3,0x80,None)
                _need(h not in (None,_INVALID),'framework native-image read lock failed');self.handles.append(h)
                info=_file_info(k,h);identity=(info['volume'],info['index'])
                _need(info['links']==1 and identity not in identities,'framework native-image physical identity alias')
                _need(1<=info['size']<=_FRAMEWORK_NATIVE_IMAGE_CAP,'framework native-image file size cap');identities.add(identity)
                actual,row=_read_image(k,h,retain_native_raw=True);raw=row.pop('_native_raw',None)
                _need(actual==p and row['sha256']==digest and all(row[key]==info[key] for key in info),'framework native-image bytes/path differ before launch')
                _need(row['machine']=='AMD64','framework native image requires AMD64 PE32+')
                envelope=_recognize_framework_native_image(raw)
                self.framework_native_images[p.name.casefold()]={'path':p,'sha256':digest,'identity':identity,'handle':h,'info':info,'envelope':envelope}
            for p in policy.allowed_child_images:
                _ordinary(p);_need(p.name.casefold() in self.rows and any(row['path']==p for row in self.rows[p.name.casefold()]) and p.suffix.casefold()=='.exe','unbound allowed child image')
            _need(len(set(policy.allowed_child_images))==len(policy.allowed_child_images),'duplicate allowed child image')
            self.allowed=policy.allowed_child_images
            if self.native_images:
                roots=[p.parent for p in self.allowed if p.name=='vctip.exe']
                _need(len(roots)==1 and all(any(r['path']==roots[0]/_native_image_il_name(name) for r in self.rows.get(_native_image_il_name(name).casefold(),())) for name in self.native_images),'native-image profile requires exact current helper/IL tool pins')
            if self.framework_native_images:
                roots=[p.parent for p in self.allowed if p.name=='vctip.exe']
                _need(len(roots)==1 and all(any(r['path']==roots[0]/name
                      for r in self.rows.get(name,()))
                      for name in ('cl.exe','ml64.exe','vctip.exe')),
                      'framework native-image profile requires current direct-child VCTIP root')
        except BaseException as primary:
            try:self.close()
            except BaseException as close_error:
                if isinstance(primary,CompilerTraceError):primary.evidence.setdefault('cleanup_errors',[]).append(str(close_error))
                else:raise CompilerTraceError(str(primary),{'preflight_error':repr(primary),'cleanup_errors':[str(close_error)]}) from primary
            raise
    def _active_il_binding(self,tool_root,context,*,native_image_name=_NATIVE_IMAGE_NAME):
        # Context is made inside register_image from THIS trace's mutable active
        # map. It is not a caller receipt, prior-run history or public boolean.
        _need(type(context) is tuple and len(context)==4,'native image requires current active IL context')
        pid,event_index,active,modules=context
        _need(type(pid) is int and pid>0 and type(event_index) is int and event_index>=0 and type(active) is dict and len(active)<=512 and type(modules) is list and len(modules)<=512,'invalid active IL context')
        il_name=_native_image_il_name(native_image_name)
        pins=[r for r in self.rows.get(il_name.casefold(),()) if r['path']==tool_root/il_name]
        _need(len(pins)==1,'active IL tool pin is missing/ambiguous');pin=pins[0];matches=[]
        for base,index in active.items():
            _need(type(base) is int and base>0 and type(index) is int and 0<=index<len(modules),'invalid active module index')
            row=modules[index]
            _need(type(row) is dict,'invalid active module row')
            if row.get('path')!=str(pin['path']):continue
            _need(row.get('pid')==pid and row.get('base')==base and type(row.get('event_index')) is int and 0<=row['event_index']<event_index and row.get('unload_event_index') is None and row.get('image_admission')=='approved' and row.get('classification')=='pinned_anycpu_il_tool_dll' and row.get('sha256')==pin['sha256'] and(row.get('volume'),row.get('index'))==pin['identity'],'active IL row differs from current admitted exact tool pin')
            matches.append(row)
        _need(len(matches)==1,'unique current active admitted IL image required')
        row=matches[0]
        return {key:row[key] for key in ('pid','base','event_index','path','sha256','volume','index')}

    def classify(self,handle,*,managed_tool_root=None,_active_images=None):
        _need(handle not in (None,0,_INVALID),'owned image event has null/invalid hFile')
        _need(managed_tool_root is None or type(managed_tool_root) is type(Path()),'invalid managed tool read context')
        options={}
        if managed_tool_root is not None:options['allow_managed_read']=True
        if (getattr(self,'support',{}) or getattr(self,'native_images',{}) or
                getattr(self,'framework_native_images',{})):options['retain_native_raw']=True
        p,row=_read_image(self.k,handle,**options)
        managed_raw=row.pop('_managed_raw',None);native_raw=row.pop('_native_raw',None);name=p.name.casefold()
        def image_need(value,message):
            if not value:raise CompilerTraceError(message,{'rejected_image':row})
        if name==_FRAMEWORK_NATIVE_IMAGE_NAME:
            want=getattr(self,'framework_native_images',{}).get(name)
            image_need(want is not None,'framework native image is not separately operator-pinned')
            known_root=managed_tool_root is not None and managed_tool_root/'vctip.exe' in self.allowed and any(r['path'].parent==managed_tool_root for n in ('cl.exe','ml64.exe') for r in self.rows.get(n,()))
            image_need(known_root,'framework native image is not a verified current VCTIP LOAD_DLL')
            _framework_native_image_path(p)
            image_need(p==want['path'] and row['sha256']==want['sha256'] and(row['volume'],row['index'])==want['identity'],'framework native image escaped exact pin')
            image_need(all(row[key]==want['info'][key] for key in ('volume','index','size','links','attributes','write')),'framework native image locked identity changed')
            image_need(managed_raw is None and row['machine']=='AMD64','framework native image requires native AMD64')
            try:envelope=_recognize_framework_native_image(native_raw)
            except CompilerTraceError as exc:exc.evidence['rejected_image']=row;raise
            row.update(classification='pinned_vctip_framework_native_image',
                framework_native_image_child_tool_root=str(managed_tool_root),
                framework_native_image_envelope=envelope,framework_IL_binding_proven=False,
                managed_resource_reference_closure_proven=False,
                NI_compilation_authenticity_proven=False,IL_native_semantic_equivalence_proven=False,
                NGEN_dependency_closure_proven=False,JIT_closure_proven=False)
        elif name in (_NATIVE_IMAGE_NAME,_NEWTON_IMAGE_NAME):
            want=getattr(self,'native_images',{}).get(name)
            image_need(want is not None,'native tool image is not separately pinned')
            known_root=managed_tool_root is not None and managed_tool_root/'vctip.exe' in self.allowed and any(r['path'].parent==managed_tool_root for n in ('cl.exe','ml64.exe') for r in self.rows.get(n,()))
            image_need(known_root,'native tool image is not a verified current VCTIP LOAD_DLL')
            _native_image_path(p)
            image_need(p==want['path'] and row['sha256']==want['sha256'] and(row['volume'],row['index'])==want['identity'],'native tool image escaped exact pin')
            image_need(all(row[key]==want['info'][key] for key in ('volume','index','size','links','attributes','write')),'native tool image locked identity changed')
            image_need(managed_raw is None and row['machine']=='AMD64','native tool image requires AMD64 PE32+')
            try:
                binding=self._active_il_binding(managed_tool_root,_active_images,native_image_name=name)
                envelope=_recognize_native_tool_image(native_raw)
            except CompilerTraceError as exc:exc.evidence['rejected_image']=row;raise
            row.update(classification='pinned_vctip_tool_native_image',native_image_child_tool_root=str(managed_tool_root),active_pinned_IL_binding=binding,native_image_envelope=envelope,NI_compilation_authenticity_proven=False,IL_native_semantic_equivalence_proven=False,NGEN_dependency_closure_proven=False,JIT_closure_proven=False)
        elif name==_SETUP_SUPPORT_NAME:
            want=getattr(self,'support',{}).get(name)
            image_need(want is not None,'Setup support image is not separately pinned')
            known_root=managed_tool_root is not None and managed_tool_root/'vctip.exe' in self.allowed and any(r['path'].parent==managed_tool_root for n in ('cl.exe','ml64.exe') for r in self.rows.get(n,()))
            image_need(known_root,'Setup support is not a verified current VCTIP LOAD_DLL')
            image_need(p==want['path'] and p==_SETUP_SUPPORT_PATH and row['sha256']==want['sha256'] and (row['volume'],row['index'])==want['identity'],'Setup support escaped exact file pin')
            image_need(all(row[key]==want['info'][key] for key in ('volume','index','size','links','attributes','write')),'Setup support locked identity changed')
            image_need(managed_raw is None and row['machine']=='AMD64','Setup support requires native AMD64')
            try:envelope=_recognize_setup_support_dll(native_raw)
            except CompilerTraceError as exc:exc.evidence['rejected_image']=row;raise
            row.update(classification='pinned_vctip_setup_support_native_image',support_child_tool_root=str(managed_tool_root),support_native_envelope=envelope)
        elif name in self.rows:
            matches=[r for r in self.rows[name] if p==r['path']];image_need(len(matches)==1,'compiler-support module escaped exact file path')
            want=matches[0]
            image_need(p==want['path'] and (row['volume'],row['index'])==want['identity'] and row['sha256']==want['sha256'],'compiler-support module escaped exact file pin')
            if managed_raw is not None:
                known_root=managed_tool_root is not None and managed_tool_root/'vctip.exe' in self.allowed and any(r['path'].parent==managed_tool_root for n in ('cl.exe','ml64.exe') for r in self.rows.get(n,()))
                image_need(known_root and p.suffix.casefold()=='.dll' and p.parent==managed_tool_root,'PE32 image is not an exact current-child compiler-tool DLL')
                options={'_legacy_tool_coff':True}
                # Finite tool role, not basename authority: path, identity, hash
                # and fresh direct-child VCTIP LOAD proof were consumed above.
                if name=='microsoft.visualstudio.remotecontrol.dll':options['_tool_resource_tail']=True
                try:envelope=_recognize_anycpu_tool_dll(managed_raw,**options)
                except CompilerTraceError as exc:exc.evidence['rejected_image']=row;raise
                row.update(machine='I386_AnyCPU_ILONLY',native_image=False,image_size=envelope['image_size'],classification='pinned_anycpu_il_tool_dll',IL_only_envelope=envelope,managed_child_tool_root=str(managed_tool_root))
            else:row['classification']='pinned_compiler_module'
        else:
            if managed_raw is not None:
                identity=_facade_domain(p,self.windows)
                known_root=managed_tool_root is not None and managed_tool_root/'vctip.exe' in self.allowed and any(r['path'].parent==managed_tool_root for n in ('cl.exe','ml64.exe') for r in self.rows.get(n,()))
                image_need(identity is not None and known_root,'unbound/OS PE32 managed image refused')
                try:envelope=_recognize_anycpu_tool_dll(managed_raw,_facade_identity=identity)
                except CompilerTraceError as exc:exc.evidence['rejected_image']=row;raise
                row.update(machine='I386_AnyCPU_ILONLY_OS_facade',native_image=False,image_size=envelope['image_size'],classification='operator_trusted_Windows_GAC_pure_facade',IL_only_envelope=envelope,facade_child_tool_root=str(managed_tool_root),platform_domain='GAC_MSIL_framework_pure_facade',public_key_token_is_authenticity=False)
            else:
                domain=_platform_domain(p,self.windows)
                image_need(domain is not None,'unknown executable module outside reviewed finite native platform domains')
                row['classification']='operator_trusted_Windows_platform';row['platform_domain']=domain
        return p,row
    def recheck(self):
        for row in getattr(self,'native_images',{}).values():
            _ordinary_native_image(row['path']);p,current=_read_image(self.k,row['handle'],retain_native_raw=True);raw=current.pop('_native_raw',None)
            _need(p==row['path'] and current['sha256']==row['sha256'] and all(current[key]==row['info'][key] for key in ('volume','index','size','links','attributes','write')),'native-image bytes/identity drift after trace')
            _recognize_native_tool_image(raw)
        for row in getattr(self,'framework_native_images',{}).values():
            _ordinary_framework_native_image(row['path']);p,current=_read_image(self.k,row['handle'],retain_native_raw=True);raw=current.pop('_native_raw',None)
            _need(p==row['path'] and current['sha256']==row['sha256'] and all(current[key]==row['info'][key] for key in ('volume','index','size','links','attributes','write')),'framework native-image bytes/identity drift after trace')
            _recognize_framework_native_image(raw)
        for row in getattr(self,'support',{}).values():
            _ordinary(row['path']);p,current=_read_image(self.k,row['handle'],retain_native_raw=True);raw=current.pop('_native_raw',None)
            _need(p==row['path'] and current['sha256']==row['sha256'] and all(current[key]==row['info'][key] for key in ('volume','index','size','links','attributes','write')),'support bytes/identity drift after trace')
            _recognize_setup_support_dll(raw)
        for rows in self.rows.values():
            for row in rows:_need(hashlib.sha256(row['path'].read_bytes()).hexdigest()==row['sha256'],'tool bytes drift after trace')
    def close(self):
        errors=[]
        for h in reversed(self.handles):
            if not self.k.CloseHandle(h):errors.append(int(ctypes.get_last_error()))
        self.handles=[]
        if errors:raise CompilerTraceError('tool lock close failed',{'winerrors':errors})

def run_traced_compiler(argv:tuple[str,...],cwd:Path,env:dict[str,str],*,policy:CompilerTracePolicy,timeout:float=90,max_log:int=4*1024*1024)->CompilerTraceResult:
    _need(os.name=='nt' and ctypes.sizeof(ctypes.c_void_p)==8 and ctypes.sizeof(_Event)==176 and _Event.data.offset==16 and ctypes.sizeof(_PBI)==48,'requires native Win64 ABI')
    _need(type(argv) is tuple and 2<=len(argv)<=64 and all(type(v) is str and v and '\0' not in v for v in argv),'invalid compiler argv')
    _ordinary(cwd,directory=True)
    _need(type(env) is dict and all(type(k) is str and type(v) is str and k and '=' not in k and '\0' not in k+v for k,v in env.items()),'invalid closed compiler environment')
    _need(type(timeout) in (int,float) and 0<timeout<=180 and type(max_log) is int and 1<=max_log<=4*1024*1024,'invalid trace budgets')
    k,nt=_api();locked=_LockedPolicy(policy,k);root=Path(argv[0]);job=None;proc=None;pending=None;owned={};events=[];modules=[];active={};threads={};primary_error=None
    cap={'stdout':bytearray(),'stderr':bytearray()};overflow=False;total=0;pipehandles={};pipe_eof={'stdout':False,'stderr':False};creator=int(k.GetCurrentThreadId());deadline=time.monotonic()+timeout
    cleanup={'requested':False,'errors':[],'reaped':False,'job_accounting':None}
    def account():
        out=_JobAccount();_need(k.QueryInformationJobObject(job,1,ctypes.byref(out),ctypes.sizeof(out),None),'job accounting query failed')
        return {'total_processes':int(out.total),'active_processes':int(out.active),'terminated_processes':int(out.terminated)}
    def same_thread():_need(int(k.GetCurrentThreadId())==creator,'debug calls changed creating thread')
    def in_job(handle):
        yes=w.BOOL();_need(k.IsProcessInJob(handle,job,ctypes.byref(yes)) and yes.value,'debug process is outside exact owned job')
    def verify_thread(handle,tid,pid):
        own=k.OpenThread(0x40,False,tid);_need(own,'owned thread query handle open failed')
        try:_need(k.CompareObjectHandles(own,handle) and k.GetThreadId(own)==tid and k.GetProcessIdOfThread(own)==pid,'debug thread object identity mismatch')
        finally:_need(k.CloseHandle(own),'owned thread query handle close failed')
    def own_create(event,cleanup_mode=False):
        pid=int(event.pid);d=event.data.create;_need(pid not in owned and len(owned)<8,'duplicate/excess process create')
        handle=int(proc._handle) if pid==proc.pid else k.OpenProcess(0x100401,False,pid)
        _need(handle,'owned process query/wait handle open failed');duplicate=pid!=proc.pid
        try:
            _need(k.CompareObjectHandles(handle,d.process) and int(k.GetProcessId(handle))==pid,'CREATE process object identity mismatch')
            verify_thread(d.thread,int(event.tid),pid)
            if not (cleanup_mode and pid==proc.pid):in_job(handle)
            pbi=_PBI();_need(nt.NtQueryInformationProcess(handle,0,ctypes.byref(pbi),ctypes.sizeof(pbi),None)==0 and pbi.pid==pid,'CREATE parent identity query failed')
            if pid==proc.pid:_need(not owned and pbi.parent==os.getpid(),'root creating-process identity differs')
            else:_need(int(pbi.parent) in owned and not owned[int(pbi.parent)]['exit_seen'],'child lineage is not live debugger-owned parent')
        except BaseException:
            if duplicate:k.CloseHandle(handle)
            raise
        owned[pid]={'pid':pid,'parent_pid':int(pbi.parent),'primary_tid':int(event.tid),'handle':handle,'duplicate_handle':duplicate,'initial_loader_breakpoint':False,'second_chance_exceptions':0,'exit_seen':False,'exit_continued':False,'exit_code':None,'wait_terminal':False}
        threads[pid]={int(event.tid)};active[pid]={};return owned[pid]
    def close_file(p):
        event=p['event'];code=int(event.code)
        if code not in (3,6) or p['file_close_attempted']:return
        p['file_close_attempted']=True
        handle=event.data.create.file if code==3 else event.data.load.file
        _need(handle not in (None,0,_INVALID),'owned image event hFile missing')
        _need(k.CloseHandle(handle),'owned image event hFile close failed')
    def continue_event(p,status):
        same_thread();event=p['event'];_need(p['owned'] and int(event.pid) in owned and 1<=event.code<=9,'foreign/invalid event continuation refused')
        _need(k.ContinueDebugEvent(event.pid,event.tid,status),'ContinueDebugEvent failed')
        if event.code==5:owned[int(event.pid)]['exit_continued']=True
        p['continued']=True
    def register_image(p,base):
        event=p['event'];d=event.data.create if event.code==3 else event.data.load
        owner=owned[int(event.pid)]
        managed_role=_managed_tool_load_role(int(event.code),int(event.pid),proc.pid,owner.get('approved_image_path'),owner.get('approved_image_pinned'),owner['parent_pid'],root)
        path,row=locked.classify(d.file,managed_tool_root=root.parent if managed_role else None,_active_images=(int(event.pid),len(events)-1,active[int(event.pid)],modules) if managed_role else None);_need(base and base not in active[int(event.pid)] and len(modules)<512,'image base/module count ambiguous')
        row.update(pid=int(event.pid),base=base,event_index=len(events)-1,file_handle=int(d.file),unload_event_index=None,image_admission='pending')
        active[int(event.pid)][base]=len(modules);modules.append(row)
        if event.code==3:
            if event.pid==proc.pid:_need(path==root,'root CREATE image differs from explicit application')
            else:_need(path in locked.allowed,'unapproved compiler child image')
            owner['approved_image_path']=str(path);owner['approved_image_pinned']=row['classification']=='pinned_compiler_module'
        row['image_admission']='approved';return row
    def drain_pipes():
        # No reader thread or buffered stream read exists: close cannot wait on
        # a Python reader lock. ReadFile is issued only for Peek-confirmed data.
        nonlocal total,overflow
        if overflow:return
        for name,handle in pipehandles.items():
            while not pipe_eof[name]:
                available=w.DWORD()
                if not k.PeekNamedPipe(handle,None,0,None,ctypes.byref(available),None):
                    error=ctypes.get_last_error()
                    _need(error in (109,232),'owned pipe availability query failed')
                    pipe_eof[name]=True;break
                if not available.value:break
                want=min(65536,int(available.value));block=ctypes.create_string_buffer(want);got=w.DWORD()
                _need(k.ReadFile(handle,block,want,ctypes.byref(got),None) and 0<got.value<=want,'owned available pipe read failed')
                raw=block.raw[:got.value];kept=raw[:max(0,max_log-total)];cap[name].extend(kept);total+=len(kept)
                if len(kept)!=len(raw):overflow=True;return
    def service(event):
        nonlocal pending
        same_thread()
        pending={'event':event,'owned':int(event.pid) in owned,'file_close_attempted':False,'continued':False,'status':None}
        _need(len(events)<8192 and 1<=event.code<=9,'debug event cap/unsupported code')
        if event.code==3:own_create(event);pending['owned']=True
        _need(pending['owned'],'foreign debug event refused without close/continue')
        row=owned[int(event.pid)];_need(not row['exit_seen'] and int(event.tid)>0,'event after process exit/invalid thread')
        out={'index':len(events),'event':int(event.code),'pid':int(event.pid),'tid':int(event.tid)};events.append(out)
        status=DBG_CONTINUE
        try:
            if event.code==3:out['image']=register_image(pending,int(event.data.create.base or 0))
            elif event.code==2:
                h=event.data.thread.thread;verify_thread(h,int(event.tid),int(event.pid));_need(int(event.tid) not in threads[int(event.pid)],'duplicate CREATE thread');threads[int(event.pid)].add(int(event.tid))
            else:_need(int(event.tid) in threads[int(event.pid)],'event thread was not debugger-owned')
            if event.code==6:out['image']=register_image(pending,int(event.data.load.base or 0))
            elif event.code==7:
                base=int(event.data.ptr or 0);_need(base in active[int(event.pid)],'unload of unknown module');idx=active[int(event.pid)].pop(base);modules[idx]['unload_event_index']=out['index'];out['base']=base
            elif event.code==1:
                raw=bytes(event.data.raw);exc=struct.unpack_from('<I',raw,0)[0];address=struct.unpack_from('<Q',raw,16)[0];chance=struct.unpack_from('<I',raw,152)[0];_need(chance in (0,1),'invalid exception chance')
                out.update(exception=exc,address=address,first_chance=chance);status=DBG_EXCEPTION_NOT_HANDLED
                ntdll=[modules[idx] for idx in active[int(event.pid)].values() if Path(modules[idx]['path']).name.casefold()=='ntdll.dll' and modules[idx]['classification']=='operator_trusted_Windows_platform' and modules[idx]['base']<=address<modules[idx]['base']+modules[idx]['image_size']]
                if exc==0x80000003 and chance==1 and not row['initial_loader_breakpoint'] and int(event.tid)==row['primary_tid'] and len(ntdll)==1:
                    row['initial_loader_breakpoint']=True;status=DBG_CONTINUE;out['verified_initial_loader_breakpoint']=True
                if chance==0:row['second_chance_exceptions']+=1
            elif event.code==4:threads[int(event.pid)].remove(int(event.tid))
            elif event.code==5:
                row['exit_seen']=True;row['exit_code']=struct.unpack_from('<I',bytes(event.data.raw),0)[0];out['exit_code']=row['exit_code']
                for idx in active[int(event.pid)].values():modules[idx]['process_exit_event_index']=out['index']
            elif event.code==8:out['debug_string_length']=struct.unpack_from('<H',bytes(event.data.raw),10)[0]
            elif event.code==9:raise CompilerTraceError('RIP debug event is not successful compilation')
            pending['status']=status;out['continue_status']=status
        finally:close_file(pending)
        continue_event(pending,status);pending=None
    def cleanup_owned():
        nonlocal pending
        cleanup['requested']=True;end=time.monotonic()+10
        def error(x):
            if len(cleanup['errors'])<64:cleanup['errors'].append(str(x))
        if job and not k.TerminateJobObject(job,0xE014):error('TerminateJobObject failed winerror='+str(ctypes.get_last_error()))
        # Root is owned by the retained Popen handle even if initial Job assignment failed.
        if proc is not None and k.WaitForSingleObject(int(proc._handle),0)!=0:
            if not k.TerminateProcess(int(proc._handle),0xE014):error('exact root TerminateProcess failed winerror='+str(ctypes.get_last_error()))
        while time.monotonic()<end:
            try:
                if pending is not None:
                    p=pending;e=p['event']
                    if not p['owned'] and e.code==3:
                        own_create(e,cleanup_mode=True);p['owned']=True
                    _need(p['owned'] and 1<=e.code<=9,'cleanup refuses foreign/invalid event')
                    close_file(p)
                    if not p['continued']:continue_event(p,p['status'] if p['status'] is not None else (DBG_EXCEPTION_NOT_HANDLED if e.code==1 else DBG_CONTINUE))
                    pending=None
                a=account()
                drain_pipes()
                root_terminal=proc is None or k.WaitForSingleObject(int(proc._handle),0)==0
                if a['active_processes']==0 and root_terminal and all(k.WaitForSingleObject(row['handle'],0)==0 for row in owned.values()):break
                event=_Event();same_thread()
                if not k.WaitForDebugEvent(ctypes.byref(event),100):
                    _need(ctypes.get_last_error()==121,'cleanup debug wait failed');continue
                pending={'event':event,'owned':int(event.pid) in owned,'file_close_attempted':False,'continued':False,'status':None}
            except BaseException as x:error(x);break
        for row in owned.values():
            if k.WaitForSingleObject(row['handle'],0)!=0:
                if not k.DebugActiveProcessStop(row['pid']):error('owned detach failed pid='+str(row['pid']))
                if k.WaitForSingleObject(row['handle'],max(0,int((end-time.monotonic())*1000)))!=0:error('owned process unreaped pid='+str(row['pid']))
        # The retained root is ours even when CREATE validation failed before
        # registration. Never infer its terminal state from an empty Job/map.
        if proc is not None and proc.pid not in owned and k.WaitForSingleObject(int(proc._handle),0)!=0:
            if not k.DebugActiveProcessStop(proc.pid):error('retained root detach failed pid='+str(proc.pid))
            if k.WaitForSingleObject(int(proc._handle),max(0,int((end-time.monotonic())*1000)))!=0:error('retained root unreaped pid='+str(proc.pid))
        try:
            cleanup['job_accounting']=account();cleanup['root_physical_terminal']=proc is None or k.WaitForSingleObject(int(proc._handle),0)==0
            cleanup['reaped']=cleanup['root_physical_terminal'] and cleanup['job_accounting']['active_processes']==0 and all(k.WaitForSingleObject(r['handle'],0)==0 for r in owned.values())
            snapshots=[];cleanup['process_terminal_snapshots']=snapshots
            candidates={pid:row['handle'] for pid,row in owned.items()}
            if proc is not None:candidates.setdefault(proc.pid,int(proc._handle))
            for pid,handle in candidates.items():
                wait=int(k.WaitForSingleObject(handle,0));value=w.DWORD();ok=bool(k.GetExitCodeProcess(handle,ctypes.byref(value)))
                snapshots.append({'pid':pid,'wait_result':wait,'physical_terminal':wait==0,'exit_query_succeeded':ok,'physical_exit_code':int(value.value) if ok else None,'normal_exit_seen':owned.get(pid,{}).get('exit_seen',False),'exit_continued':owned.get(pid,{}).get('exit_continued',False)})
            drain_pipes();cleanup['pipe_eof']=dict(pipe_eof)
        except BaseException as x:error(x)
    try:
        _need(root.is_absolute() and root.name.casefold() in ('cl.exe','ml64.exe') and root.name.casefold() in locked.rows and any(row['path']==root for row in locked.rows[root.name.casefold()]),'explicit primary compiler is not exact pinned CL/ML64')
        _need(not any(n.upper().startswith(('CL','_CL_','ML','LETHE_','PYTHON','LINK','LIB')) for n in env if n.upper() not in ('SYSTEMROOT','WINDIR','PATH','TEMP','TMP','INCLUDE','VSLANG','PROCESSOR_ARCHITECTURE','NUMBER_OF_PROCESSORS')),'unexpected compiler option environment')
        job=k.CreateJobObjectW(None,None);_need(job,'job creation failed');limits=_JobLimits();limits.basic.flags=0x2000
        _need(k.SetInformationJobObject(job,9,ctypes.byref(limits),ctypes.sizeof(limits)),'kill-on-close job setup failed')
        proc=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,creationflags=0x1|0x4)
        _need(k.AssignProcessToJobObject(job,int(proc._handle)),'suspended primary compiler job assignment failed');in_job(int(proc._handle))
        import msvcrt
        pipehandles.update({name:msvcrt.get_osfhandle(stream.fileno()) for name,stream in [('stdout',proc.stdout),('stderr',proc.stderr)]})
        _need(nt.NtResumeProcess(int(proc._handle))==0,'primary compiler resume failed')
        while not owned or not all(row['exit_continued'] for row in owned.values()):
            drain_pipes();_need(time.monotonic()<deadline and not overflow,'compiler trace timeout/log cap exceeded')
            event=_Event();same_thread()
            if not k.WaitForDebugEvent(ctypes.byref(event),min(100,max(1,int((deadline-time.monotonic())*1000)))):
                _need(ctypes.get_last_error()==121,'WaitForDebugEvent failed');continue
            service(event)
        for row in owned.values():
            _need(k.WaitForSingleObject(row['handle'],max(0,int((deadline-time.monotonic())*1000)))==0,'EXIT continuation did not reach physical terminal')
            row['wait_terminal']=True;value=w.DWORD();_need(k.GetExitCodeProcess(row['handle'],ctypes.byref(value)) and value.value==row['exit_code'],'wait handle/EXIT code mismatch')
            _need(row['initial_loader_breakpoint'] and row['second_chance_exceptions']==0,'missing loader breakpoint or fatal exception')
        samples=[];cleanup['job_accounting_samples']=samples;settle_start=time.monotonic()
        while True:
            a=account();cleanup['job_accounting']=a;samples.append({'elapsed_seconds':time.monotonic()-settle_start,**a})
            _need(a['total_processes']==len(owned),'job/debug tree completeness mismatch')
            if a['active_processes']==0:break
            _need(time.monotonic()<deadline and len(samples)<16384,'job terminal accounting did not settle within existing trace budget')
            time.sleep(min(.02,max(0,deadline-time.monotonic())))
        proc.wait(timeout=10)
        while not all(pipe_eof.values()) and time.monotonic()<deadline and not overflow:
            drain_pipes()
            if not all(pipe_eof.values()):time.sleep(.01)
        _need(all(pipe_eof.values()) and not overflow,'compiler pipe lifetime/log cap failure')
        locked.recheck();cleanup['reaped']=True
        exit_code=int(proc.returncode);status='exited' if exit_code==0 and all(row['exit_code']==0 for row in owned.values()) else 'compiler_failure'
        return CompilerTraceResult(exit_code,bytes(cap['stdout']),bytes(cap['stderr']),status,tuple(events),tuple(modules),tuple({k:v for k,v in row.items() if k not in ('handle','duplicate_handle')} for row in owned.values()),cleanup)
    except BaseException as x:
        primary_error=x
        if proc is not None:
            cleanup_owned()
            try:proc.wait(timeout=1)
            except BaseException as wait_error:cleanup['errors'].append('root wait: '+str(wait_error))
        evidence={'primary_error':str(x),'cause_evidence':x.evidence if isinstance(x,CompilerTraceError) else {},'events':events,'loaded_modules':modules,'processes':[{k:v for k,v in row.items() if k not in ('handle','duplicate_handle')} for row in owned.values()],'cleanup':cleanup,'literal_stdout':bytes(cap['stdout']).decode(errors='replace'),'literal_stderr':bytes(cap['stderr']).decode(errors='replace'),'stdout_sha256':hashlib.sha256(cap['stdout']).hexdigest(),'stderr_sha256':hashlib.sha256(cap['stderr']).hexdigest(),'capture_truncated':overflow,'root_pid':proc.pid if proc else None,'creator_thread':creator}
        raise CompilerTraceError('compiler trace rejected: '+str(x),evidence,stdout=bytes(cap['stdout']),stderr=bytes(cap['stderr'])) from x
    finally:
        resource_errors=[]
        if proc is not None:
            for stream in (proc.stdout,proc.stderr):
                try:stream.close()
                except OSError as x:resource_errors.append(str(x))
        for row in owned.values():
            if row['duplicate_handle'] and not k.CloseHandle(row['handle']):resource_errors.append('owned child wait handle close failed')
        if job and not k.CloseHandle(job):resource_errors.append('job close failed')
        try:locked.close()
        except BaseException as x:resource_errors.append(str(x))
        if resource_errors:
            if primary_error is not None:cleanup['errors'].extend(resource_errors)
            else:raise CompilerTraceError('trace resource close failure',{'errors':resource_errors,'events':events,'loaded_modules':modules,'cleanup':cleanup},stdout=bytes(cap['stdout']),stderr=bytes(cap['stderr']))
