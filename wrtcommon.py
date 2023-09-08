import ctypes
from ctypes import wintypes
import logging
import string

import comtypes

logger = logging.getLogger(__name__)

HSTRING = wintypes.HANDLE
ENUM = wintypes.UINT

combase=ctypes.WinDLL('combase.dll')

def check_hresult(hr):
    if (hr not in [comtypes.hresult.S_OK, comtypes.hresult.S_FALSE]):
        raise comtypes.COMError(hr, comtypes.FormatError(hr),
                    (None, None, 0, None, None))

def array_to_guid(a):
    assert len(a) == 11, "Unexpected length %d" % len(a)
    
    data1, data2, data3, data4 = a[0], a[1], a[2], a[3:]

    s = "{%08X-%04X-%04X-%s-%s}" % (
        data1,
        data2,
        data3,
        # https://devblogs.microsoft.com/oldnewthing/20220928-00/?p=107221
        string.join(["%02X" % b for b in data4[:2]], ""),
        string.join(["%02X" % b for b in data4[2:]], ""),
    )
    logger.info("array_to_guid %s %s", a, s)

    return comtypes.GUID(s)

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

class TrustLevel(ENUM):
    BaseTrust = 0
    PartialTrust = BaseTrust + 1
    FullTrust = PartialTrust + 1

IID_IInspectable = comtypes.GUID('{AF86E2E0-B12D-4C6A-9C5A-D7AA65101E90}')
class IInspectable(comtypes.IUnknown):
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/inspectable.idl

    [
    object,
    uuid(AF86E2E0-B12D-4c6a-9C5A-D7AA65101E90),
    pointer_default(unique)
    ]
    interface IInspectable : IUnknown
    {
        HRESULT GetIids(
            [out] ULONG * iidCount,
            [out, size_is(,*iidCount)] IID ** iids);

        HRESULT GetRuntimeClassName( [out] HSTRING * className);

        HRESULT GetTrustLevel([out] TrustLevel * trustLevel);
    }
    """
    _case_insensitive_ = True
    _idlflags_ = []
    _iid_ = IID_IInspectable
    _methods_ = [
        comtypes.COMMETHOD(
            [comtypes.helpstring('Method GetIids')],
            comtypes.HRESULT,
            'GetIids',
            (['out'], wintypes.POINTER(wintypes.ULONG), 'iidCount'),
            (['out'], wintypes.POINTER(wintypes.POINTER(comtypes.IID)), 'iids'),
        ),
        comtypes.COMMETHOD(
            [comtypes.helpstring('Method GetRuntimeClassName')],
            comtypes.HRESULT,
            'GetRuntimeClassName',
            (['out'], wintypes.POINTER(HSTRING), 'className'),
        ),
        comtypes.COMMETHOD(
            [comtypes.helpstring('Method GetTrustLevel')],
            comtypes.HRESULT,
            'GetTrustLevel',
            (['out'], wintypes.POINTER(TrustLevel), 'trustLevel'),
        ),
    ]

# https://learn.microsoft.com/en-us/windows/win32/api/objidlbase/nn-objidlbase-iagileobject
IID_IAgileObject = comtypes.GUID("{94EA2B94-E9CC-49E0-C0FF-EE64CA8F5B90}")
class IAgileObject(comtypes.IUnknown):
    # This is a marker-only interface, it doesn't have methods
    _iid_ = IID_IAgileObject
    _case_insensitive_ = True
    _idlflags_ = []
    _methods_ = [
    ]

# https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/AsyncInfo.idl
# https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/asyncinfo.h
# {00000036-0000-0000-C000-000000000046}
class AsyncStatus(ENUM):
    Started = 0
    Completed = 1
    Canceled = 2
    Error = 3
IID_IAsyncInfo = array_to_guid((54, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70))
class IAsyncInfo(IInspectable):
    """
    // Properties
    [propget] HRESULT Id([out, retval] unsigned __int32 *id);

    // provide a C++ overload for async status that doesn't rely on 
    // the global definition of asyncstatus to support _HIDE_GLOBAL_ASYNC_STATUS
    [propget] HRESULT Status([out, retval] AsyncStatus *status);

    [propget] HRESULT ErrorCode([out,retval] HRESULT *errorCode);
    
    // Methods
    HRESULT Cancel();
    HRESULT Close();
    """
    _iid_ = IID_IAsyncInfo
    _case_insensitive_ = True
    _idlflags_ = []
    _methods_ = [
        # [propget] HRESULT Id([out, retval] unsigned __int32 *id);
        comtypes.COMMETHOD(
            ['propget'], wintypes.HRESULT, "Id", 
            (['out', 'retval'], wintypes.POINTER(ctypes.c_int32)),
        ),
        # [propget] HRESULT Status([out, retval] AsyncStatus *status);
        comtypes.COMMETHOD(
            ['propget'], wintypes.HRESULT, "Status", 
            (['out', 'retval'], wintypes.POINTER(AsyncStatus)),
        ),
        # [propget] HRESULT ErrorCode([out,retval] HRESULT *errorCode);
        comtypes.COMMETHOD(
            ['propget'], wintypes.HRESULT, "ErrorCode", 
            (['out', 'retval'], wintypes.POINTER(comtypes.HRESULT)),
        ),
        # HRESULT Cancel();
        comtypes.COMMETHOD(
            [], wintypes.HRESULT, "Cancel"
        ),
        # HRESULT Close();
        comtypes.COMMETHOD(
            [], wintypes.HRESULT, "Close"
        ),
    ]
    
class IAsyncOperation(IAsyncInfo):
    # See https://learn.microsoft.com/en-us/uwp/api/windows.foundation.iasyncoperation-1?view=winrt-22621
    pass
    
# See https://learn.microsoft.com/en-us/uwp/api/windows.foundation.typedeventhandler-2?view=winrt-22621
# GUID((2648818996, 27361, 4576, 132, 225, 24, 169, 5, 188, 197, 63))
# This asks for
# - INoMarshall {ECC8691B-C1DB-4DC0-855E-65F6C551AF49}, should E_NOINTERFACE
# - ??????      {00000039-0000-0000-C000-000000000046}, should E_NOINTERFACE
# - IdentityUnmarshal {0000001B-0000-0000-C000-000000000046}, should E_NOINTERFACE
# - IAgileObject {94EA2B94-E9CC-49E0-C0FF-EE64CA8F5B90}, should S_OK
# And once publisher.Start() is called it asks for
# - ITypedEventHandler {DE73CBA7-370D-550C-B23A-53DD0B4E480D}
IID_ITypedEventHandler = array_to_guid((2648818996, 27361, 4576, 132, 225, 24, 169, 5, 188, 197, 63))
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

# XXX In windows.foundation.py, but needs multi interface 
#     runtimeclass support, needed for PasswordCredential below
IPropertySet = IInspectable

# XXX Lifted from windows.security.credentials.py
IID_IPasswordCredential = comtypes.GUID('{6AB18989-C720-41A7-A6C1-FEADB36329A0}')
class IPasswordCredential(IInspectable):
    """
    [exclusiveto(Windows.Security.Credentials.PasswordCredential)]
    [uuid(6AB18989-C720-41A7-A6C1-FEADB36329A0)]
    interface IPasswordCredential : IInspectable
    {
    [propget] HRESULT Resource([out] [retval] HSTRING* resource);
    [propput] HRESULT Resource([in] HSTRING resource);
    [propget] HRESULT UserName([out] [retval] HSTRING* userName);
    [propput] HRESULT UserName([in] HSTRING userName);
    [propget] HRESULT Password([out] [retval] HSTRING* password);
    [propput] HRESULT Password([in] HSTRING password);
    HRESULT RetrievePassword();
    [propget] HRESULT Properties([out] [retval] Windows.Foundation.Collections.IPropertySet** props);
    }
    """
    _iid_ = IID_IPasswordCredential

IPasswordCredential._methods_ = [
    # [propget] HRESULT Resource([out] [retval] HSTRING* resource)
    comtypes.COMMETHOD(
        ['propget'], wintypes.HRESULT, 'Resource',
        (['out','retval'], wintypes.POINTER(HSTRING), 'resource'),
    ),
    # [propput] HRESULT Resource([in] HSTRING resource)
    comtypes.COMMETHOD(
        ['propput'], wintypes.HRESULT, 'Resource',
        (['in'], HSTRING, 'resource'),
    ),
    # [propget] HRESULT UserName([out] [retval] HSTRING* userName)
    comtypes.COMMETHOD(
        ['propget'], wintypes.HRESULT, 'UserName',
        (['out','retval'], wintypes.POINTER(HSTRING), 'userName'),
    ),
    # [propput] HRESULT UserName([in] HSTRING userName)
    comtypes.COMMETHOD(
        ['propput'], wintypes.HRESULT, 'UserName',
        (['in'], HSTRING, 'userName'),
    ),
    # [propget] HRESULT Password([out] [retval] HSTRING* password)
    comtypes.COMMETHOD(
        ['propget'], wintypes.HRESULT, 'Password',
        (['out','retval'], wintypes.POINTER(HSTRING), 'password'),
    ),
    # [propput] HRESULT Password([in] HSTRING password)
    comtypes.COMMETHOD(
        ['propput'], wintypes.HRESULT, 'Password',
        (['in'], HSTRING, 'password'),
    ),
    # [None] HRESULT RetrievePassword()
    comtypes.COMMETHOD(
        [], wintypes.HRESULT, 'RetrievePassword',
    ),
    # [propget] HRESULT Properties([out] [retval] Windows.Foundation.Collections.IPropertySet** props)
    comtypes.COMMETHOD(
        ['propget'], wintypes.HRESULT, 'Properties',
        (['out','retval'], wintypes.POINTER(wintypes.POINTER(IPropertySet)), 'props'),
    ),
]

class PasswordCredential(IPasswordCredential):
    """
    [activatable(0x06020000)]
    [activatable(Windows.Security.Credentials.ICredentialFactory, 0x06020000)]
    runtimeclass PasswordCredential
    {
    [default] interface Windows.Security.Credentials.IPasswordCredential;
    }
    """
    def __new__(cls):
        return activate_instance('Windows.Security.Credentials.PasswordCredential', IPasswordCredential)

# XXX Letting PasswordCredential = class(IPasswordCredential) fails, investigate
#     and fix (maybe doing activate_instance on __new__ is overwriting?)
PasswordCredential = IPasswordCredential

# XXX Placeholders needed for IDeviceInformation
IMapView_2_HSTRING_IInspectable = IInspectable
IAsyncOperation_1_DeviceThumbnail = IInspectable
EnclosureLocation = IInspectable
DeviceInformationUpdate = IInspectable

# XXX Lifted from windows.devices.enumeration.py 
IID_IDeviceInformation = comtypes.GUID('{ABA0FB95-4398-489D-8E44-E6130927011F}')
class IDeviceInformation(IInspectable):
    """
    [exclusiveto(Windows.Devices.Enumeration.DeviceInformation)]
    [uuid(ABA0FB95-4398-489D-8E44-E6130927011F)]
    interface IDeviceInformation : IInspectable
    {
    [propget] HRESULT Id([out] [retval] HSTRING* value);
    [propget] HRESULT Name([out] [retval] HSTRING* value);
    [propget] HRESULT IsEnabled([out] [retval] boolean* value);
    [propget] HRESULT IsDefault([out] [retval] boolean* value);
    [propget] HRESULT EnclosureLocation([out] [retval] Windows.Devices.Enumeration.EnclosureLocation** value);
    [propget] HRESULT Properties([out] [retval] Windows.Foundation.Collections.IMapView<HSTRING, IInspectable*>** value);
    HRESULT Update([in] Windows.Devices.Enumeration.DeviceInformationUpdate* updateInfo);
    HRESULT GetThumbnailAsync([out] [retval] Windows.Foundation.IAsyncOperation<Windows.Devices.Enumeration.DeviceThumbnail*>** asyncOp);
    HRESULT GetGlyphThumbnailAsync([out] [retval] Windows.Foundation.IAsyncOperation<Windows.Devices.Enumeration.DeviceThumbnail*>** asyncOp);
    }
    """
    _iid_ = IID_IDeviceInformation

IDeviceInformation._methods_ = [
    # [propget] HRESULT Id([out] [retval] HSTRING* value)
    comtypes.COMMETHOD(
        ['propget'], wintypes.HRESULT, 'Id',
        (['out','retval'], wintypes.POINTER(HSTRING), 'value'),
    ),
    # [propget] HRESULT Name([out] [retval] HSTRING* value)
    comtypes.COMMETHOD(
        ['propget'], wintypes.HRESULT, 'Name',
        (['out','retval'], wintypes.POINTER(HSTRING), 'value'),
    ),
    # [propget] HRESULT IsEnabled([out] [retval] boolean* value)
    comtypes.COMMETHOD(
        ['propget'], wintypes.HRESULT, 'IsEnabled',
        (['out','retval'], wintypes.POINTER(wintypes.BOOL), 'value'),
    ),
    # [propget] HRESULT IsDefault([out] [retval] boolean* value)
    comtypes.COMMETHOD(
        ['propget'], wintypes.HRESULT, 'IsDefault',
        (['out','retval'], wintypes.POINTER(wintypes.BOOL), 'value'),
    ),
    # [propget] HRESULT EnclosureLocation([out] [retval] Windows.Devices.Enumeration.EnclosureLocation** value)
    comtypes.COMMETHOD(
        ['propget'], wintypes.HRESULT, 'EnclosureLocation',
        (['out','retval'], wintypes.POINTER(wintypes.POINTER(EnclosureLocation)), 'value'),
    ),
    # [propget] HRESULT Properties([out] [retval] Windows.Foundation.Collections.IMapView<HSTRING,IInspectable*>** value)
    comtypes.COMMETHOD(
        ['propget'], wintypes.HRESULT, 'Properties',
        (['out','retval'], wintypes.POINTER(wintypes.POINTER(IMapView_2_HSTRING_IInspectable)), 'value'),
    ),
    # [None] HRESULT Update([in] Windows.Devices.Enumeration.DeviceInformationUpdate* updateInfo)
    comtypes.COMMETHOD(
        [], wintypes.HRESULT, 'Update',
        (['in'], wintypes.POINTER(DeviceInformationUpdate), 'updateInfo'),
    ),
    # [None] HRESULT GetThumbnailAsync([out] [retval] Windows.Foundation.IAsyncOperation<Windows.Devices.Enumeration.DeviceThumbnail*>** asyncOp)
    comtypes.COMMETHOD(
        [], wintypes.HRESULT, 'GetThumbnailAsync',
        (['out','retval'], wintypes.POINTER(wintypes.POINTER(IAsyncOperation_1_DeviceThumbnail)), 'asyncOp'),
    ),
    # [None] HRESULT GetGlyphThumbnailAsync([out] [retval] Windows.Foundation.IAsyncOperation<Windows.Devices.Enumeration.DeviceThumbnail*>** asyncOp)
    comtypes.COMMETHOD(
        [], wintypes.HRESULT, 'GetGlyphThumbnailAsync',
        (['out','retval'], wintypes.POINTER(wintypes.POINTER(IAsyncOperation_1_DeviceThumbnail)), 'asyncOp'),
    ),
]

class DeviceInformation(IDeviceInformation):
    """
    [static(Windows.Devices.Enumeration.IDeviceInformationStatics, Windows.Foundation.UniversalApiContract, 1.0)]
    [static(Windows.Devices.Enumeration.IDeviceInformationStatics2, Windows.Foundation.UniversalApiContract, 1.0)]
    runtimeclass DeviceInformation
    {
    [default] interface Windows.Devices.Enumeration.IDeviceInformation;
    }
    """

# XXX Lifted from windows.devices.enumeration.py
class DevicePairingKinds(ENUM):
    """
    enum DevicePairingKinds
    {
    None            = 0x0,
    ConfirmOnly     = 0x1,
    DisplayPin      = 0x2,
    ProvidePin      = 0x4,
    ConfirmPinMatch = 0x8
    };
    """
    None_ = 0
    ConfirmPinMatch = 0
    ConfirmOnly = 0
    ProvidePin = 0
    DisplayPin = 0

# XXX More placeholders
IVector_1_WiFiDirectInformationElement = IInspectable
IVector_1_WiFiDirectConfigurationMethod = IInspectable
IBuffer = IInspectable
IVectorView_1_EndpointPair = IInspectable

"""
https://learn.microsoft.com/en-us/previous-versions/br205803(v=vs.85)

MIDL_INTERFACE("d34abe17-fb19-57be-bc41-0eb83dea151c")
__FIAsyncOperationCompletedHandler_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE Invoke( 
        /* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice *asyncInfo,
        /* [in] */ AsyncStatus status) = 0;
    
};
"""
FWiFiDirectDevice_AsyncStatus = ctypes.PYFUNCTYPE(wintypes.HRESULT, wintypes.POINTER("WiFiDirectDevice"), wintypes.POINTER("AsyncStatus"))
IID_IAsyncOperationCompletedHandler_1_WiFiDirectDevice = comtypes.GUID("{d34abe17-fb19-57be-bc41-0eb83dea151c}")
# XXX This is not really used but find out and fill-in with the default base
#     class GUID if it exists?
IID_IAsyncEventHandler = IID_IAsyncOperationCompletedHandler_1_WiFiDirectDevice

"""
https://learn.microsoft.com/en-us/previous-versions/br205802(v=vs.85)

MIDL_INTERFACE("dad01b61-a82d-566c-ba82-224c11500669")
__FIAsyncOperation_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice : public IInspectable
{
public:
    virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_Completed( 
        /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice *handler) = 0;
    
    virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_Completed( 
        /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice **handler) = 0;
    
    virtual HRESULT STDMETHODCALLTYPE GetResults( 
        /* [retval][out] */ __RPC__deref_out_opt ABI::Windows::Devices::WiFiDirect::IWiFiDirectDevice **results) = 0;
    
};

XXX Requires the following entry manually added to the .idl

[contract(Windows.Foundation.UniversalApiContract, 1.0)]
[uuid(dad01b61-a82d-566c-ba82-224c11500669)]
interface IAsyncOperation_1_WiFiDirectDevice : IInspectable
{
    [propput] HRESULT Completed([in] IAsyncOperationCompletedHandler<Windows.Devices.WiFiDirect.WiFiDirectDevice*>* handler);
    [propget] HRESULT Completed([out] [retval] IAsyncOperationCompletedHandler<Windows.Devices.WiFiDirect.WiFiDirectDevice*>** handler);
    HRESULT GetResults([out] [retval] Windows.Devices.WiFiDirect.IWiFiDirectDevice** results);
}
"""

"""
XXX This GUID is queryinterfaced but only appears on the .h?
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/windows.devices.wifidirect.h
MIDL_INTERFACE("de73cba7-370d-550c-b23a-53dd0b4e480d")
__FITypedEventHandler_2_Windows__CDevices__CWiFiDirect__CWiFiDirectAdvertisementPublisher_Windows__CDevices__CWiFiDirect__CWiFiDirectAdvertisementPublisherStatusChangedEventArgs : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE Invoke( 
        /* [in] */ __RPC__in_opt ABI::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher *sender,
        /* [in] */ __RPC__in_opt ABI::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisherStatusChangedEventArgs *e) = 0;
    
};

template <>
struct __declspec(uuid("de73cba7-370d-550c-b23a-53dd0b4e480d"))
ITypedEventHandler<ABI::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisher*,ABI::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatusChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisher*, ABI::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatusChangedEventArgs*, ABI::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisherStatusChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisher, Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatusChangedEventArgs>"; 
    }
};
"""
# https://learn.microsoft.com/en-us/previous-versions/hh438424(v=vs.85)
FWiFiDirectAdvertisementPublisher_WiFiDirectAdvertisementPublisherStatusChangedEventArgs = ctypes.PYFUNCTYPE(wintypes.HRESULT, wintypes.POINTER("IWiFiDirectAdvertisementPublisher"), wintypes.POINTER("IIWiFiDirectAdvertisementPublisherStatusChangedEventArgs"))
IID_TypedEventHandler_2_WiFiDirectAdvertisementPublisher_WiFiDirectAdvertisementPublisherStatusChangedEventArgs = comtypes.GUID("{DE73CBA7-370D-550C-B23A-53DD0B4E480D}")

"""
XXX This GUID is queryinterfaced but only appears on the .h?
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/windows.devices.wifidirect.h

MIDL_INTERFACE("d04b0403-1fe2-532f-8e47-4823a14e624f")
__FITypedEventHandler_2_Windows__CDevices__CWiFiDirect__CWiFiDirectConnectionListener_Windows__CDevices__CWiFiDirect__CWiFiDirectConnectionRequestedEventArgs : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE Invoke( 
        /* [in] */ __RPC__in_opt ABI::Windows::Devices::WiFiDirect::IWiFiDirectConnectionListener *sender,
        /* [in] */ __RPC__in_opt ABI::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequestedEventArgs *e) = 0;
    
};

template <>
struct __declspec(uuid("d04b0403-1fe2-532f-8e47-4823a14e624f"))
ITypedEventHandler<ABI::Windows::Devices::WiFiDirect::WiFiDirectConnectionListener*,ABI::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequestedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::WiFiDirect::WiFiDirectConnectionListener*, ABI::Windows::Devices::WiFiDirect::IWiFiDirectConnectionListener*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequestedEventArgs*, ABI::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequestedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Devices.WiFiDirect.WiFiDirectConnectionListener, Windows.Devices.WiFiDirect.WiFiDirectConnectionRequestedEventArgs>"; 
    }
};
"""
FWiFiDirectConnectionListener_WiFiDirectConnectionRequestedEventArgs = ctypes.PYFUNCTYPE(wintypes.HRESULT, wintypes.POINTER("IWiFiDirectConnectionListener"), wintypes.POINTER("IWiFiDirectConnectionRequestedEventArgs"))
IID_TypedEventHandler_2_WiFiDirectConnectionListener_WiFiDirectConnectionRequestedEventArgs = comtypes.GUID("{d04b0403-1fe2-532f-8e47-4823a14e624f}")

"""
XXX This GUID is queryinterfaced but only appears on the .h?
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/windows.devices.wifidirect.h

template <>
struct __declspec(uuid("9208929a-2a3c-50ad-aa08-a0a986edbabe"))
ITypedEventHandler<ABI::Windows::Devices::WiFiDirect::WiFiDirectDevice*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::WiFiDirect::WiFiDirectDevice*, ABI::Windows::Devices::WiFiDirect::IWiFiDirectDevice*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Devices.WiFiDirect.WiFiDirectDevice, Object>"; 
    }
};

"""
FWiFiDirectDevice_IInspectable = ctypes.PYFUNCTYPE(wintypes.HRESULT, wintypes.POINTER("IWiFiDirectDevice"), wintypes.POINTER("IIInspectable"))
IID_TypedEventHandler_2_WiFiDirectDevice_IInspectable = comtypes.GUID("{9208929A-2A3C-50AD-AA08-A0A986EDBABE}")
