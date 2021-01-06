#include "config.hpp"

struct charPointerCmp {
	bool operator()(const char* s1, const char* s2) const {
		return strcmp(s1, s2) < 0;
	}
};

//BEGIN GLOBAL
extern "C" LONG(__stdcall * RtlNtStatusToDosError) (IN ULONG status) = NULL;
char globalErrorMessageBuffer[640] = { 0 };

char* minecraftWorkingPath = nullptr;
char* javaProgramPath = nullptr;
char* javaProgramParameters = nullptr;
std::map<PCH, PCH, charPointerCmp> fileAccessMap;
//END GLOBAL

char* QueryErrorString(DWORD Error) {
	FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), 0, (LPSTR) &globalErrorMessageBuffer, 640, NULL);
	for (int i = 0; i < 640; i++) {
		if (globalErrorMessageBuffer[i] == '\r' || globalErrorMessageBuffer[i] == '\n') {
			globalErrorMessageBuffer[i] = '\0';
		}
	}
	return globalErrorMessageBuffer;
}


static const char* SE_OBJECT_TYPE_STRINGS[] = { "SE_UNKNOWN_OBJECT_TYPE", "SE_FILE_OBJECT", "SE_SERVICE","SE_PRINTER" ,"SE_REGISTRY_KEY" ,"SE_LMSHARE" ,"SE_KERNEL_OBJECT" ,"SE_WINDOW_OBJECT" ,"SE_DS_OBJECT" ,"SE_DS_OBJECT_ALL" ,"SE_PROVIDER_DEFINED_OBJECT" ,"SE_WMIGUID_OBJECT" ,"SE_REGISTRY_WOW64_32KEY" ,"SE_REGISTRY_WOW64_64KEY" };

const char* GetSeObjectTypeStrings(SE_OBJECT_TYPE objectType) {
	return SE_OBJECT_TYPE_STRINGS[objectType];
}

BOOLEAN IsPath(PCCH path) {
	WIN32_FIND_DATAA FindFileData;
	auto handle = FindFirstFileA(path, &FindFileData);
	FindClose(handle);

	if ((handle != INVALID_HANDLE_VALUE) && (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

BOOLEAN CoverCapabilitiyToWellKnownSID(const WELL_KNOWN_SID_TYPE* capabilitiyList, PSID_AND_ATTRIBUTES sidList, size_t capabilitiyCount) {
	for (int i = 0; i < capabilitiyCount; i++) {
		DWORD dwSIDSize = SECURITY_MAX_SID_SIZE;
		sidList[i].Sid = new unsigned char[SECURITY_MAX_SID_SIZE];
		sidList[i].Attributes = SE_GROUP_ENABLED;
		if (!CreateWellKnownSid(capabilitiyList[i], NULL, sidList[i].Sid, &dwSIDSize) || !IsWellKnownSid(sidList[i].Sid, capabilitiyList[i])) {
			printf("[*] Error in cover capabilitiy to well-known SID. Error message is: [%s]\n", QueryErrorString(GetLastError()));
			return FALSE;
		}
	}

	return true;
}

BOOL SetObjectAccess(PSID appcontainerSid, HANDLE objectHandle, SE_OBJECT_TYPE objectType, DWORD accessMask, BOOLEAN IsRevoke) {
	EXPLICIT_ACCESS_A explicitAccess;
	PACL originalAcl = NULL, newAcl = NULL;
	NTSTATUS status = ERROR_SUCCESS;

	explicitAccess.grfAccessMode = IsRevoke ? REVOKE_ACCESS : SET_ACCESS;
	explicitAccess.grfAccessPermissions = accessMask;
	explicitAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT | CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;

	explicitAccess.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
	explicitAccess.Trustee.pMultipleTrustee = NULL;
	explicitAccess.Trustee.ptstrName = (CHAR*) appcontainerSid;
	explicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_GROUP;

	if ((status = GetSecurityInfo(objectHandle, objectType, DACL_SECURITY_INFORMATION, NULL, NULL, &originalAcl, NULL, NULL)) != ERROR_SUCCESS) {
		printf("[!] Failed to quert object <%p> 's acl. Error message is: [%s]\n", objectHandle, QueryErrorString(RtlNtStatusToDosError(status)));
		return FALSE;
	}

	if ((status = SetEntriesInAclA(1, &explicitAccess, originalAcl, &newAcl)) != ERROR_SUCCESS) {
		printf("[!] Failed to modify object <%p> 's acl. Error message is: [%s]\n", objectHandle, QueryErrorString(RtlNtStatusToDosError(status)));
		return FALSE;
	}

	if ((status = SetSecurityInfo(objectHandle, objectType, DACL_SECURITY_INFORMATION, NULL, NULL, newAcl, NULL)) != ERROR_SUCCESS) {
		printf("[!] Failed to set object <%p> 's acl. Error message is: [%s]\n", objectHandle, QueryErrorString(RtlNtStatusToDosError(status)));
		LocalFree(newAcl);
		return FALSE;
	}

	LocalFree(newAcl);
	printf("[*] Succeed %s access to %s object %p with access mask 0x%08X\n", IsRevoke ? "revoke" : "grant", GetSeObjectTypeStrings(objectType), objectHandle, IsRevoke ? 0 : accessMask);

	return TRUE;
}

VOID SetFileAccess(PSID containerSID, PCCH path, PCCH access) {
	HANDLE fileHandle = CreateFileA(path, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		printf("[!] Unable to open file %s, error message is: [%s]. Skip this file.\n", path, QueryErrorString(GetLastError()));
		return;
	}

	if (_stricmp(access, "W") == 0) {
		printf("[*] Set <%s> permissions to read-write.\n", path);
		if (!SetObjectAccess(containerSID, fileHandle, SE_FILE_OBJECT, FILE_ALL_ACCESS, FALSE)) {
			printf("[!] Unable modify the permissions. Ignore this file.\n");
		}
	} else if (_stricmp(access, "R") == 0) {
		printf("[*] Set <%s> permissions to read-only.\n", path);
		if (!SetObjectAccess(containerSID, fileHandle, SE_FILE_OBJECT, FILE_GENERIC_READ, FALSE)) {
			printf("[!] Unable modify the permissions. Ignore this file.\n");
		}
	} else if (_stricmp(access, "N") == 0) {
		printf("[*] Revoke all permissions on the file <%s>.\n", path);
		if (!SetObjectAccess(containerSID, fileHandle, SE_FILE_OBJECT, FILE_ALL_ACCESS, TRUE)) {
			printf("[!] Unable modify the permissions. Ignore this file.\n");
		}
	} else {
		printf("[!] Unknown permission text, ignore <%s>\n", path);
	}

	CloseHandle(fileHandle);
}

VOID SetPathAccess(PSID containerSID, PCCH path, PCCH access) {
	PCH cpoiedPath = reinterpret_cast<PCH>(malloc(MAX_PATH));
	WIN32_FIND_DATAA FindFileData = { 0 };

	SetFileAccess(containerSID, path, access);

	if (cpoiedPath == nullptr) {
		return;
	}

	RtlZeroMemory(cpoiedPath, MAX_PATH);
	strncpy_s(cpoiedPath, MAX_PATH, path, strlen(path));
	strcat_s(cpoiedPath, MAX_PATH, "\\*");

	auto handle = FindFirstFileA(cpoiedPath, &FindFileData);

	if (INVALID_HANDLE_VALUE == handle) {
		free(cpoiedPath);
		return;
	}

	do {
		if (strcmp(FindFileData.cFileName, ".") == 0 || strcmp(FindFileData.cFileName, "..") == 0) {
			continue;
		}

		RtlZeroMemory(cpoiedPath, MAX_PATH);
		strncpy_s(cpoiedPath, MAX_PATH, path, strlen(path));
		strcat_s(cpoiedPath, MAX_PATH, "\\");
		strcat_s(cpoiedPath, MAX_PATH, FindFileData.cFileName);

		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			SetPathAccess(containerSID, cpoiedPath, access);
		} else {
			SetFileAccess(containerSID, cpoiedPath, access);
		}
	} while (FindNextFile(handle, &FindFileData) != 0);

	free(cpoiedPath);
	FindClose(handle);
}

void printUseage(const char* processName) {
	printf("Binklac Minecraft sandbox for Microsoft Windows, Version : %s\n", SANDBOX_VERSION);
	printf("(c) 2020 Binklac Workstation. All rights reserved. \n\n");

	printf("Useage: %s \n\t[/D path] [/J java-program] [/P parameters-for-java] \n\t[/F filename-or-path1,access;filename-or-path2,access;...] \n\t[/Remap filename-or-path1,destination;filename-or-path2,destination;...]\n\n", processName);

	printf("描述:\n\t使用该工具使Minecraft运行在一个隔离的环境中。\n\n");

	printf("参数列表:\n");
	printf("\t/D path                       启动目录。\n");
	printf("\t/J java-program               java.exe或者javaw.exe的位置，注意，应当尽可能的使用绝对路径。\n");
	printf("\t/P parameters-for-java        java.exe或者javaw.exe的参数，沙盒将会原封不动的将它们传递给Java\n");
	printf("\t/F filename-or-path1,access;filename-or-path2,access;...\n");
	printf("\t                              设置文件或目录的权限，使Minecraft可以读取或写入它们。\n");
	printf("\t                              可选的权限有R, RW, N。\n");
	printf("\t                              \tR: 允许读取该文件但不可写入该文件\n");
	printf("\t                              \tW: 允许读取和写入该文件， 在Windows上，这个标志将会扩展到\"完全控制\"\n");
	printf("\t                              \tN: 对该文件没有任何权限，任何针对文件的操作将会得到一个权限异常\n\n");
	printf("\t                              当输入的目标为一个目录的时候，对该目录的权限将会应用到其子目录及内部文件上\n");
	printf("\t                              在分配权限时，应当遵守最小权限原则，只应该对必要的文件和目录设置对应的权限\n");
	printf("\t                              最简单的方法是给予Java和Minecraft目录读取权限，并且给予存档目录和配置文件目录写入权限\n");
	printf("\t/Remap filename-or-path1,destination;filename-or-path2,destination;...\n");
	printf("\t                              强制重定向Minecraft对某个文件或者目录的读写操作，用于强制性版本隔离。\n");
	printf("\t                              注意: 当前版本未实现该功能，需要使用请切换至Dev-1.7分支\n");
}

VOID praseFileList(PCCH filelist) {
	PCCH delimiter = ";";
	PCH context = NULL;

	PCH stringBuffer = reinterpret_cast<PCH>(_strdup(filelist));
	if (stringBuffer == nullptr) {
		exit(-1);
	}

	PCH file = strtok_s(stringBuffer, delimiter, &context);

	while (file != NULL) {
		PCH access = nullptr;
		PCH comma = strstr(file, ",");

		if (comma != nullptr) {
			access = comma + 1;
			*comma = '\0';
		} else {
			access = const_cast<PCH>("N");
		}

		fileAccessMap.insert(std::pair<PCH, PCH>(_strdup(file), _strdup(access)));
		file = strtok_s(NULL, delimiter, &context);
	}

	free(stringBuffer);
}

void praseCommand(int argc, char* argv[]) {
	for (int i = 0; i < argc; i++) {
		if (_stricmp(argv[i], "/D") == 0) {
			minecraftWorkingPath = argv[i + 1];
		}

		if (_stricmp(argv[i], "/J") == 0) {
			javaProgramPath = argv[i + 1];
		}

		if (_stricmp(argv[i], "/P") == 0) {
			javaProgramParameters = argv[i + 1];
		}

		if (_stricmp(argv[i], "/F") == 0) {
			praseFileList(argv[i + 1]);
		}

		if (_stricmp(argv[i], "/H") == 0) {
			printUseage(argv[0]);
			exit(0);
		}
	}

	if (javaProgramPath == nullptr || javaProgramParameters == nullptr) {
		printf("[X] Not enough parameters provided, use /H option to view help.\n");
		exit(-1);
	}

	if (minecraftWorkingPath == nullptr) {
		printf("[!] The program will use the default working directory, which may cause unexpected behavior.\n");
	}

	if (fileAccessMap.size() == 0) {
		printf("[!] It looks like you haven't set any accessible directories and the game may crash.\n");
	}
}

int main(int argc, char* argv[]) {
	PSID containerSID = NULL;
	SIZE_T attributeSize = 0;
	STARTUPINFOEX startupInfo = { 0 };
	PROCESS_INFORMATION processInfo = { 0 };
	SECURITY_CAPABILITIES securityCapabilities = { 0 };

	praseCommand(argc, argv);

	printf("[*] Binklac Minecraft sandbox for Microsoft Windows, Version %s \n", SANDBOX_VERSION);
	printf("[*] Start creating Windows AppContainer for Minecraft...\n");
	printf("[*] Container Info:\n\tContainer Name: %ws.\n\tContainer Display Name: %ws.\n", pcwContainerName, pcwContainerDisplayName);

	HRESULT createResult = CreateAppContainerProfile(pcwContainerName, pcwContainerDisplayName, pcwContainerDescription, nullptr, 0, &containerSID);
	switch (createResult) {
		case S_OK:
			printf("[*] The Windows AppContainer was successfully created.\n");
			break;
		case E_ACCESSDENIED:
			printf("[X] Unable to creating Windows AppContainer due to you does not have permission to create it. Please try to restart the app with other permissions.\n");
			return -1;
			break;
		case HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS):
			printf("[!] The requested Appcontainer has been created. If you have never started the program before, please report the problem and stop this program, it will lead to unexpected behavior.\n");

			printf("[*] Attempting to recover an existing container.\n");
			if (DeriveAppContainerSidFromAppContainerName(pcwContainerName, &containerSID) != S_OK) {
				printf("[X] Unable to recover Windows AppContainer. This is most likely due to a program error. Please report this to the developer.\n");
				return -1;
			} else {
				printf("[*] The Windows AppContainer was successfully recovered.\n");
			}

			break;
		default:
			printf("[X] Unable to creating Windows AppContainer. This is most likely due to a program error. Please report this to the developer.\n");
			return -1;
			break;
	}

	PSTR containerStringSID = nullptr;
	if (ConvertSidToStringSidA(containerSID, &containerStringSID)) {
		printf("[*] AppContainer SID: %s\n", containerStringSID);
	}

	size_t numberOfCapability = sizeof(capabilitiyList) / sizeof(WELL_KNOWN_SID_TYPE);
	PSID_AND_ATTRIBUTES sidList = reinterpret_cast<PSID_AND_ATTRIBUTES>(malloc(sizeof(SID_AND_ATTRIBUTES) * numberOfCapability));
	if (!CoverCapabilitiyToWellKnownSID(capabilitiyList, sidList, numberOfCapability)) {
		printf("[X] Unable to complete the conversion between AppContainer Capabilitiy and SID. Process will exit.\n");
		return -1;
	}

	securityCapabilities.AppContainerSid = containerSID;
	securityCapabilities.Capabilities = sidList;
	securityCapabilities.CapabilityCount = static_cast<DWORD>(numberOfCapability);
	InitializeProcThreadAttributeList(NULL, 1, NULL, &attributeSize);
	startupInfo.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(malloc(attributeSize));

	if (!InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, NULL, &attributeSize)) {
		printf("[X] Error in InitializeProcThreadAttributeList. Process will exit.\n");
		return -1;
	}

	if (!UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &securityCapabilities, sizeof(securityCapabilities), NULL, NULL)) {
		printf("[X] Error in UpdateProcThreadAttribute. Process will exit.\n");
		return -1;
	}

	auto winsta = OpenWindowStationA("WinSta0", true, GENERIC_ALL);
	if (winsta == NULL) {
		printf("[X] Unable to open window station, the error message is: [%s].\n", QueryErrorString(GetLastError()));
		return -1;
	}

	if (!SetObjectAccess(containerSID, winsta, SE_WINDOW_OBJECT, WINSTA_PRIVILEGE, FALSE)) {
		CloseWindowStation(winsta);
		printf("[X] Unable to modifying window station permissions, the error message is: [%s].\n", QueryErrorString(GetLastError()));
		return -1;
	}

	CloseWindowStation(winsta);

	for (auto iter = fileAccessMap.begin(); iter != fileAccessMap.end(); iter++) {
		auto path = iter->first;
		auto access = iter->second;

		if (!IsPath(path)) {
			printf("[*] Modifying the permissions of file <%s> ...\n", path);
			SetFileAccess(containerSID, path, access);
		} else {
			printf("[*] Modifying the permissions of path <%s> ...\n", path);
			SetPathAccess(containerSID, path, access);
		}

		free(reinterpret_cast<void*>(const_cast<PCH>(access)));
	}

	if (!CreateProcessA(javaProgramPath, javaProgramParameters, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED, NULL, minecraftWorkingPath, (LPSTARTUPINFOA) &startupInfo, &processInfo)) {
		printf("[X] Unable to start the Java process, the error message is: [%s].\n", QueryErrorString(GetLastError()));
		return -1;
	};

	printf("[*] The game process is successfully created. Below this line is the log output of the game.\n");

	ResumeThread(processInfo.hThread);

	WaitForSingleObject(processInfo.hProcess, INFINITE);
	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);

	printf("[*] The game process is exited. Below this line is the log output of the sandbox.\n");


	for (auto iter = fileAccessMap.begin(); iter != fileAccessMap.end(); iter++) {
		auto path = iter->first;
		auto access = iter->second;

		if (!IsPath(path)) {
			printf("[*] Revoke the permissions of file <%s> ...\n", path);
			SetFileAccess(containerSID, path, "N");
		} else {
			printf("[*] Revoke the permissions of path <%s> ...\n", path);
			SetPathAccess(containerSID, path, "N");
		}

		free(reinterpret_cast<void*>(const_cast<PCH>(path)));
	}

	winsta = OpenWindowStationA("WinSta0", true, GENERIC_ALL);
	if (winsta == NULL) {
		printf("[X] Unable to open window station, the error message is: [%s].\n", QueryErrorString(GetLastError()));
		return -1;
	}

	if (!SetObjectAccess(containerSID, winsta, SE_WINDOW_OBJECT, WINSTA_PRIVILEGE, TRUE)) {
		CloseWindowStation(winsta);
		printf("[X] Unable to modifying window station permissions, the error message is: [%s].\n", QueryErrorString(GetLastError()));
		return -1;
	}

	CloseWindowStation(winsta);

	return 0;
}