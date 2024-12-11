#include <iostream>
#include "Header.h"
using namespace std;
#define cout wcout

int main()
{
    IUIAutomation* _automation;
    HRESULT hr;
    IUIAutomationElement* pTargetElement = NULL;
    EventHandler* pEventHandler = new EventHandler();
    BSTR Bname;
    wstring name;
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    hr = CoCreateInstance(__uuidof(CUIAutomation), NULL, CLSCTX_INPROC_SERVER, __uuidof(IUIAutomation), (void**)&_automation);
    //cout << hr << endl;
    hr = _automation->GetRootElement(&pTargetElement);
   // cout << hr << endl;
    pTargetElement->get_CurrentName(&Bname);
    name = wstring(Bname, SysStringLen(Bname));
    cout << name << endl;
    hr = _automation->AddAutomationEventHandler(UIA_Window_WindowOpenedEventId, pTargetElement, TreeScope_Subtree, NULL, (IUIAutomationEventHandler*)pEventHandler);
    if (FAILED(hr))
    {
       // ret = 1;
        cout << "[X] Init: Failed " << hex << hr << endl;
        //cleanup(pEventHandler, pTargetElement);
    }
    hr = _automation->AddAutomationEventHandler(UIA_Window_WindowClosedEventId, pTargetElement, TreeScope_Subtree, NULL, (IUIAutomationEventHandler*)pEventHandler);
    if (FAILED(hr))
    {
        //ret = 1;
        cout << "[X] Init: Failed " << hex << hr << endl;
        //cleanup(pEventHandler, pTargetElement);
    }
    wcout << "[V] Init: Succeeded!" << endl;
    wcout << "[*] Listening..." << endl;
    while (1)
    {
        //logic here
    }

}