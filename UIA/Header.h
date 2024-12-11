#pragma once
#include <stdio.h>
#include <comdef.h>
#include <uiautomation.h>
#include <windows.h>
#include <string>
#include <iostream>
#include <fcntl.h>
#include <io.h>
#include <list>
#include <vector>

class EventHandler : public IUIAutomationEventHandler {
private:
    LONG _refCount;
    std::wstring name;
public:

    int _eventCount;
    EventHandler();
    ULONG STDMETHODCALLTYPE AddRef();
    ULONG STDMETHODCALLTYPE Release();
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppInterface);
    HRESULT STDMETHODCALLTYPE HandleAutomationEvent(IUIAutomationElement* pSender, EVENTID eventID);
};