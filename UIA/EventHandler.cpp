#include "Header.h"


EventHandler::EventHandler() : _refCount(1), _eventCount(0)
{
}

// IUnknown methods.
ULONG STDMETHODCALLTYPE EventHandler::AddRef()
{
    ULONG ret = InterlockedIncrement(&_refCount);
    return ret;
}

ULONG STDMETHODCALLTYPE EventHandler::Release()
{
    ULONG ret = InterlockedDecrement(&_refCount);
    if (ret == 0)
    {
        delete this;
        return 0;
    }
    return ret;
}
HRESULT STDMETHODCALLTYPE EventHandler::QueryInterface(REFIID riid, void** ppInterface)
{
    if (riid == __uuidof(IUnknown))
        *ppInterface = static_cast<IUIAutomationEventHandler*>(this);
    else if (riid == __uuidof(IUIAutomationEventHandler))
        *ppInterface = static_cast<IUIAutomationEventHandler*>(this);
    else
    {
        *ppInterface = NULL;
        return E_NOINTERFACE;
    }
    this->AddRef();
    return S_OK;
}
HRESULT STDMETHODCALLTYPE EventHandler::HandleAutomationEvent(IUIAutomationElement* pSender, EVENTID eventID)
{
    BSTR Bname;
    HRESULT res;
    std::wstring name;
    res = pSender->get_CurrentName(&Bname);
    if (FAILED(res))
    {
        return ERROR_ACCESS_DENIED;
    }
    name = std::wstring(Bname, SysStringLen(Bname));
    switch (eventID)
    {
        case UIA_Window_WindowOpenedEventId:
            std::wcout << "opened: " << name << std::endl;
            break;
        case UIA_Window_WindowClosedEventId:
            std::wcout << "closed: " << name << std::endl;
            break;
            //more logic here
    }
    
    

    
    return ERROR_SUCCESS;
}