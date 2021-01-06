#pragma once

#include "sandbox.hpp"

constexpr auto SANDBOX_VERSION = "1.0.0";

//����б�ָʾ��Ӧ��������"����"���ھ��󲿷������ֻ��Ҫ������صľͺ�
//see https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-well_known_sid_type
const static WELL_KNOWN_SID_TYPE capabilitiyList[] = {
	WinCapabilityInternetClientSid,                 //ָʾӦ�ó���������Internet�ͻ��˹��ܵ�SID��
};

//��������޸���ݴ��룬������������ɳ�м��ݣ����޸�������ĿΪ�Լ���!!
PCWSTR pcwContainerName = L"1F569D27-44C0-4578-B879-F2EC017A8751";
PCWSTR pcwContainerDisplayName = L"Binklac Minecraft Container";
PCWSTR pcwContainerDescription = L"һ�����ڸ���Minecraft�ͻ��˵�����\0";


#define WINSTA_PRIVILEGE ( /* ����ΪMinecraft���õ�������Ȩ�ޣ����Ը�����Ҫ�޸�*/ \
WINSTA_READATTRIBUTES   |  /*��ȡ����*/                                           \
WINSTA_ACCESSCLIPBOARD  |  /*���Ƽ�����*/                                         \
WINSTA_WRITEATTRIBUTES  |  /*д������(���룬������Ϸ������)*/                     \
WINSTA_ENUMERATE        |  /*��ȡˢ����*/                                         \
WINSTA_READSCREEN       |  /*��ȡ��Ļ*/                                           \
STANDARD_RIGHTS_REQUIRED   /*�����ı���Ȩ��*/                                     \
)