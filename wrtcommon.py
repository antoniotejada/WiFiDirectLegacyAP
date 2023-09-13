import ctypes
from ctypes import wintypes
import logging

import comtypes

logger = logging.getLogger(__name__)

from wrtbase import *

combase=ctypes.WinDLL('combase.dll')

def check_hresult(hr):
    if (hr not in [comtypes.hresult.S_OK, comtypes.hresult.S_FALSE]):
        raise comtypes.COMError(hr, comtypes.FormatError(hr),
                    (None, None, 0, None, None))

class HString(HSTRING):
    def __init__(self, s_or_hstr = None):
        if (isinstance(s_or_hstr, HSTRING)):
            super(HString, self).__init__(s_or_hstr.value)

        elif (isinstance(s_or_hstr, long)):
            # XXX Fix com methods returning long instead of HSTRING
            # XXX Fix HSTRING not promoting to string/HString
            super(HString, self).__init__(s_or_hstr)
    
        else:
            u = unicode(s_or_hstr)
            hr = combase.WindowsCreateString(u, len(u), ctypes.byref(self))
            logger.info("WindowsCreateString 0x%x 0x%x", hr, self.value)

            check_hresult(hr)
        
    def __str__(self):
        # Note passing length seems to return length of string plus the
        # null terminator, despite what MSDN says. Don't ask for length and
        # assume zero-terminated to be on the safe side (at the expense of not
        # supporting non-zero terminated). See
        # https://learn.microsoft.com/en-us/windows/win32/api/winstring/nf-winstring-windowsgetstringrawbuffer
        p = combase.WindowsGetStringRawBuffer(self, None)
        logger.info("WindowsGetStringRawBuffer %r", p)

        return ctypes.wstring_at(p)

    def __del__(self):
        hr = combase.WindowsDeleteString(self)
        logger.info("WindowsDeleteString %x", hr)
        
        check_hresult(hr)

        self.value = None

def activate_static(runtime_class_name, interface):
    logger.info("runtime_class %s, interface %r", runtime_class_name, interface)
    statics = ctypes.POINTER(interface)()
    hr = combase.RoGetActivationFactory(
        HString(runtime_class_name),
        ctypes.byref(interface._iid_), 
        ctypes.byref(statics)
    )
    logger.info("RoActivateFactory %x", hr)
    check_hresult(hr)
    return statics

def activate_instance(runtime_class_name, interface):
    inspectable = wintypes.POINTER(IInspectable)()
    hr = combase.RoActivateInstance(
        HString(runtime_class_name),
        ctypes.byref(inspectable)
    )
    logger.info("RoActivateInstance %x", hr)
    check_hresult(hr)
    obj = inspectable.QueryInterface(interface)
    return obj

class AsyncOperationHandler(comtypes.COMObject):
    def __init__(self):
        super(AsyncOperationHandler, self).__init__()

    def IInspectable_GetIids(self, this, iidCount, iids):
        # XXX Untested
        logger.info("")
        ifaces = []
        for iface in self._com_interfaces_:
            if iface not in [IInspectable, comtypes.IUnknown]:
                ifaces.append(iface._iid_)
        
        pv = combase.CoTaskMemAlloc(len(ifaces) * 4)
        iids.content = pv
        iidCount.content = len(ifaces)
        return comtypes.hresult.S_OK

    def IInspectable_GetRuntimeClassName(self, this):
        logger.info("")
        return comtypes.hresult.E_NOTIMPL

    def IInspectable_GetTrustLevel(self, this):
        logger.info("")
        return comtypes.hresult.E_NOTIMPL

    def IAsyncInfo_Cancel(self, this):
        logger.info("")
        return comtypes.hresult.E_NOTIMPL

    def IAsyncInfo_Close(self, this):
        logger.info("")
        return comtypes.hresult.E_NOTIMPL

    def IAsyncOperation_Cancel(self, this):
        logger.info("")
        return comtypes.hresult.E_NOTIMPL

    def IAsyncOperation_Close(self, this):
        logger.info("")
        return comtypes.hresult.E_NOTIMPL

def make_typed_event_handler_class(event_handler_interface, sender_class, args_class, fn):
    logger.info("%r %r %r %r", event_handler_interface, sender_class, args_class, fn)
    # comtypes will call with this signature, adding self and this to the
    # parameters
    def invoke_wrapper(self, this, sender, args):
        logger.info("sender %r args %r", sender, args)
        
        hr = fn(sender, args)

        # Check result is none, can't check for HRESULT because S_OK is int, not
        # HRESULT
        if (hr is None):
            raise Exception("Python function for event handler didn't return required HRESULT %r" % hr)
    
    # XXX Not clear this is the best name, asynchandlers get here too and
    #     templated instances already have a name?
    name = "TypedEventHandler_%s_%s" % (sender_class.__name__, args_class.__name__) 
    cls = type(
        name,
        (AsyncOperationHandler,),
        dict(
            _event_handler_interface_ = event_handler_interface,
            # See https://svn.python.org/projects/ctypes/tags/comtypes-0.3.2/docs/com_interfaces.html
            _com_interfaces_ = [
                IAsyncOperation,
                IInspectable,
                IAgileObject,
                event_handler_interface,
            ],
            Invoke = invoke_wrapper,
        )
    )
    return cls


# See https://learn.microsoft.com/en-us/windows/win32/api/eventtoken/ns-eventtoken-eventregistrationtoken
class EventRegistrationToken(ctypes.Structure):
    _fields_ = [
        ('value', ctypes.c_int64),
    ]