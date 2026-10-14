"""The public native harness must reap owned children without changing failures."""
import ctypes
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from _native_debugger import DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED


class Function:
    def __init__(self, callback): self.callback = callback
    def __call__(self, *args): return self.callback(*args)


class FakeKernel:
    def __init__(self, monkeypatch, mode='timeout', *, debugged=False):
        self.mode, self.debugged = mode, debugged
        self.error = 0; self.closed=[]; self.terminated=False; self.exited=False
        self.terminate_calls=[]; self.continues=[]; self.waits=[]; self.deleted=0
        self.pipe_calls=0; self.continue_failures=0; self.events=[]
        if debugged:
            self.events=[(3,101,0,1,9001),(1,101,0x80000003,1,0)]
            if mode=='foreign':self.events=[(3,999,0,1,9001)]
            if mode=='invalid':self.events=[(10,101,0,1,0)]
            if mode=='debug_missing':self.events=[(3,101,0,1,9001),(5,101,0,1,0)]
            if mode=='chance_invalid':self.events=[(3,101,0,1,9001),(1,101,0x80000003,2,0)]
            if mode in ('debug_ok','debug_av','debug_false_zero'):
                if mode in ('debug_av','debug_false_zero'):self.events.append((1,101,0xC0000005,0,0))
                self.events.append((5,101,0,1,0))
        monkeypatch.setattr(ctypes,'get_last_error',lambda:self.error,raising=False)
        monkeypatch.setattr(ctypes,'set_last_error',lambda value:setattr(self,'error',value),raising=False)
        funcs={name:Function(getattr(self,name)) for name in (
            'CreatePipe','SetHandleInformation','InitializeProcThreadAttributeList',
            'UpdateProcThreadAttribute','CreateProcessW','CloseHandle','WaitForSingleObject',
            'WaitForDebugEvent','ContinueDebugEvent','TerminateProcess','DebugActiveProcessStop',
            'GetExitCodeProcess','GetExitCodeThread','CheckRemoteDebuggerPresent','ReadFile',
            'DeleteProcThreadAttributeList')}
        funcs['GetStdHandle']=Function(lambda *_:123)
        self.library=SimpleNamespace(**funcs)
        monkeypatch.setattr(ctypes,'WinDLL',lambda *_args,**_kwargs:self.library,raising=False)
    def CreatePipe(self,r,w,*_):
        self.pipe_calls+=1
        if self.mode=='pipe2' and self.pipe_calls==2:self.error=8;return 0
        r._obj.value=1000+(self.pipe_calls-1)*2;w._obj.value=r._obj.value+1;return 1
    def SetHandleInformation(self,*_):return 1
    def InitializeProcThreadAttributeList(self,storage,_n,_flags,size):size._obj.value=64;return 1
    def UpdateProcThreadAttribute(self,*_):return 1
    def CreateProcessW(self,*args):
        if self.mode=='create':self.error=5;return 0
        p=args[-1]._obj;p.hProcess=0x100000001;p.hThread=0x100000002;p.dwProcessId=101;p.dwThreadId=202;return 1
    def CloseHandle(self,h):
        value=h.value if hasattr(h,'value') else h;self.closed.append(value)
        if self.mode=='close' and value==1000:self.error=6;return 0
        return 1
    def WaitForSingleObject(self,h,ms):
        self.waits.append((h,ms))
        if self.exited or self.terminated or self.mode=='normal_ok':return 0
        if self.mode=='wait_failed' and ms==30000:self.error=6;return 0xFFFFFFFF
        return 258
    def TerminateProcess(self,h,code):
        self.terminate_calls.append((h,code))
        if self.mode=='terminate_failed':self.error=5;return 0
        self.terminated=True;return 1
    def DebugActiveProcessStop(self,pid):self.exited=True;return 1
    def WaitForDebugEvent(self,out,_ms):
        if self.terminated:self.events=[(5,101,0,1,0)]
        if not self.events:self.error=121;return 0
        code,pid,exception,chance,hfile=self.events.pop(0);e=out._obj
        e.dwDebugEventCode=code;e.dwProcessId=pid;e.dwThreadId=202
        raw=bytearray(160)
        if code==1:raw[:4]=exception.to_bytes(4,'little');raw[152:156]=chance.to_bytes(4,'little')
        else:raw[:ctypes.sizeof(ctypes.c_void_p)]=hfile.to_bytes(ctypes.sizeof(ctypes.c_void_p),'little')
        ctypes.memmove(ctypes.addressof(e.payload),bytes(raw),160);return 1
    def ContinueDebugEvent(self,pid,tid,status):
        self.continues.append((pid,tid,status))
        if self.mode=='continue_failed' and not self.terminated:self.error=5;return 0
        if not self.events and self.mode in ('debug_ok','debug_av','debug_missing','debug_false_zero'):self.exited=True
        return 1
    def GetExitCodeProcess(self,_h,out):out._obj.value=(0xC0000005 if self.mode=='debug_av' else 0) if self.exited or self.mode=='normal_ok' else 259;return 1
    def GetExitCodeThread(self,_h,out):out._obj.value=259;return 1
    def CheckRemoteDebuggerPresent(self,_h,out):out._obj.value=1;return 1
    def ReadFile(self,*_):self.error=109;return 0
    def DeleteProcThreadAttributeList(self,*_):self.deleted+=1


def run(fake,tmp_path):
    from test_native_runtime_hardening_stress import _run_packed_forced_aslr
    return _run_packed_forced_aslr(tmp_path/'owned-fixture.exe',memory_guard=False,
                                  process_hardening=False,debugged=fake.debugged)


def cleanup_note(error):
    notes=[x for x in error.__notes__ if x.startswith('native child cleanup: ')]
    return json.loads(notes[-1].split(': ',1)[1])


@pytest.mark.parametrize('mode,debugged,message',[
    ('timeout',False,'forced-ASLR child wait failed: 258'),
    ('wait_failed',False,'forced-ASLR child wait failed: 4294967295'),
    ('debug_timeout',True,'debugged child wait failed'),
])
def test_public_failure_terminates_and_reaps_exact_owned_child(monkeypatch,tmp_path,mode,debugged,message):
    fake=FakeKernel(monkeypatch,mode,debugged=debugged)
    with pytest.raises(AssertionError,match=message) as caught:run(fake,tmp_path)
    assert fake.terminate_calls==[(0x100000001,0xE014)]
    report=cleanup_note(caught.value)['child']
    assert report['reaped'] and report['final_wait_result']==0
    assert fake.closed.count(0x100000001)==fake.closed.count(0x100000002)==1
    if debugged:
        assert report['exit_event_continued']
        assert fake.continues[-1]==(101,202,DBG_CONTINUE)
    if mode=='wait_failed':assert 'WaitForSingleObject winerror=6' in caught.value.__notes__


@pytest.mark.parametrize('mode,debugged,code',[
    ('normal_ok',False,0),('debug_ok',True,0),('debug_av',True,0xC0000005),
])
def test_public_positive_and_unhandled_exception_status_not_reclassified(monkeypatch,tmp_path,mode,debugged,code):
    fake=FakeKernel(monkeypatch,mode,debugged=debugged);result=run(fake,tmp_path)
    assert result.returncode==code and not fake.terminate_calls
    if mode=='debug_av':assert (101,202,DBG_EXCEPTION_NOT_HANDLED) in fake.continues


@pytest.mark.parametrize('mode,message',[
    ('continue_failed','ContinueDebugEvent failed'),('foreign','another process'),
])
def test_pending_event_failure_closes_hfile_and_keeps_primary_error(monkeypatch,tmp_path,mode,message):
    fake=FakeKernel(monkeypatch,mode,debugged=True)
    with pytest.raises(AssertionError,match=message) as caught:run(fake,tmp_path)
    assert fake.closed.count(9001)==(0 if mode=='foreign' else 1)
    assert fake.terminate_calls==[(0x100000001,0xE014)]
    assert cleanup_note(caught.value)['child']['reaped']
    assert all(pid==101 for pid,_,_ in fake.continues)


@pytest.mark.parametrize('mode,closed,deleted',[('pipe2',2,0),('create',4,1)])
def test_partial_setup_closes_only_acquired_resources(monkeypatch,tmp_path,mode,closed,deleted):
    fake=FakeKernel(monkeypatch,mode)
    with pytest.raises(AssertionError):run(fake,tmp_path)
    assert len(fake.closed)==closed and fake.deleted==deleted and not fake.terminate_calls


def test_failed_reaping_is_recorded_without_replacing_timeout(monkeypatch,tmp_path):
    fake=FakeKernel(monkeypatch,'terminate_failed')
    with pytest.raises(AssertionError,match='forced-ASLR child wait failed: 258') as caught:run(fake,tmp_path)
    report=cleanup_note(caught.value)['child']
    assert report['reaped'] is False and 'not proven terminal' in report['errors'][-1]
    assert 0x100000001 in fake.closed and 0x100000002 in fake.closed


def test_close_failure_does_not_skip_other_resources_or_hide_timeout(monkeypatch,tmp_path):
    fake=FakeKernel(monkeypatch,'close')
    with pytest.raises(AssertionError,match='forced-ASLR child wait failed: 258') as caught:run(fake,tmp_path)
    assert cleanup_note(caught.value)['resource_errors']
    assert fake.closed[-2:]==[0x100000002,0x100000001]


@pytest.mark.parametrize('mode,message',[
    ('foreign','another process'),('invalid','invalid debug event'),
    ('debug_missing','initial loader breakpoint'),
    ('chance_invalid','invalid exception chance'),
    ('debug_false_zero','fatal debug exception'),
])
def test_optimized_public_runner_keeps_ownership_and_primary_verdicts(tmp_path,mode,message):
    # The subprocess controller uses explicit raises, not removable assertions.
    script = r"""
import json,sys
from pathlib import Path
sys.path[:0]=[sys.argv[1],str(Path(sys.argv[1]).parent)]
import pytest
from test_native_child_lifetime import FakeKernel,run
patch=pytest.MonkeyPatch()
try:
    fake=FakeKernel(patch,sys.argv[2],debugged=True)
    try:run(fake,Path(sys.argv[3]))
    except AssertionError as error:
        if sys.argv[4] not in str(error):raise RuntimeError('wrong primary failure: '+str(error))
    else:raise RuntimeError('optimized primary verdict incorrectly became success')
    if sys.argv[2]=='foreign':
        if 9001 in fake.closed or any(pid!=101 for pid,_,_ in fake.continues):
            raise RuntimeError('foreign debug resource/control ownership escaped')
    print('OPTIMIZED_PRIMARY_FAILURE_RETAINED mode='+sys.argv[2])
finally:patch.undo()
"""
    result=subprocess.run([sys.executable,'-I','-B','-OO','-c',script,
                           str(Path(__file__).resolve().parent),mode,str(tmp_path),message],
                          capture_output=True,text=True,timeout=20,check=False)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='OPTIMIZED_PRIMARY_FAILURE_RETAINED mode='+mode
    assert result.stderr==''
