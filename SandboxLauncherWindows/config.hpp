#pragma once

#include "sandbox.hpp"

constexpr auto SANDBOX_VERSION = "1.0.0";

//这个列表指示了应用容器的"能力"，在绝大部分情况下只需要网络相关的就好
//see https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-well_known_sid_type
const static WELL_KNOWN_SID_TYPE capabilitiyList[] = {
	WinCapabilityInternetClientSid,                 //指示应用程序容器的Internet客户端功能的SID。
};

//如果你想修改这份代码，并且与其他的沙盒兼容，请修改以下项目为自己的!!
PCWSTR pcwContainerName = L"1F569D27-44C0-4578-B879-F2EC017A8751";
PCWSTR pcwContainerDisplayName = L"Binklac Minecraft Container";
PCWSTR pcwContainerDescription = L"一个用于隔离Minecraft客户端的容器\0";


#define WINSTA_PRIVILEGE ( /* 以下为Minecraft会用到的桌面权限，可以根据需要修改*/ \
WINSTA_READATTRIBUTES   |  /*读取属性*/                                           \
WINSTA_ACCESSCLIPBOARD  |  /*控制剪贴板*/                                         \
WINSTA_WRITEATTRIBUTES  |  /*写入属性(必须，否则游戏不可玩)*/                     \
WINSTA_ENUMERATE        |  /*获取刷新率*/                                         \
WINSTA_READSCREEN       |  /*读取屏幕*/                                           \
STANDARD_RIGHTS_REQUIRED   /*其它的必须权限*/                                     \
)