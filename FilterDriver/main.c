#pragma warning (disable : 4201)

#define NDIS_SUPPORT_NDIS6 1
#define INITGUID

#include <ndis.h>
#include <wdm.h>
#include <fwpsk.h>
#include <guiddef.h>
#include <fwpmk.h>
#include "ipmib.h"

#include <ip2string.h>

#define UINT_MAX 0xFFFFFFFF
#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17
#define PROTOCOL_ICMP 1

#define UTILS_TAG_UNICODE_STRING 'utus'


///
/// **************************************************************************************************
/// *                           NETWORK FILTER CALLOUTS                                              *
/// **************************************************************************************************
///

void GetNetwork5TupleIndexesForLayer(
    _In_ UINT16 layerId,
    _Out_ UINT* appId,
    _Out_ UINT* localAddressIndex,
    _Out_ UINT* remoteAddressIndex,
    _Out_ UINT* localPortIndex,
    _Out_ UINT* remotePortIndex,
    _Out_ UINT* protocolIndex,
    _Out_ UINT* icmpIndex

)
{
    switch (layerId)
    {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
        *appId = FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID;
        *localAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
        *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
        *localPortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
        *remotePortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
        *protocolIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
        *icmpIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_ICMP_TYPE;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        *appId = FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID;
        *localAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
        *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
        *localPortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT;
        *remotePortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
        *protocolIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
        *icmpIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_ICMP_TYPE;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
        *appId = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_APP_ID;
        *localAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS;
        *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS;
        *localPortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT;
        *remotePortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT;
        *protocolIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL;
        *icmpIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ICMP_TYPE;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
        *appId = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_APP_ID;
        *localAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS;
        *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS;
        *localPortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT;
        *remotePortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT;
        *protocolIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL;
        *icmpIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ICMP_TYPE;
        break;
    default:
        *appId = UINT_MAX;
        *localAddressIndex = UINT_MAX;
        *remoteAddressIndex = UINT_MAX;
        *localPortIndex = UINT_MAX;
        *remotePortIndex = UINT_MAX;
        *protocolIndex = UINT_MAX;
        *icmpIndex = UINT_MAX;
    }
}

void GetICMPv6TypeValue(UINT8 ICMPIndex, WCHAR* ICMPTypeValue)
{
    switch (ICMPIndex)
    {
    case 0:
        wcscpy_s(ICMPTypeValue, 128, L"Reserved");
        break;

    case 1:
        wcscpy_s(ICMPTypeValue, 128, L"Destination Unreachable");
        break;

    case 2:
        wcscpy_s(ICMPTypeValue, 128, L"Packet Too Big");
        break;

    case 3:
        wcscpy_s(ICMPTypeValue, 128, L"Time Exceeded");
        break;

    case 4:
        wcscpy_s(ICMPTypeValue, 128, L"Parameter Problem");
        break;

    case 100:
    case 101:
        wcscpy_s(ICMPTypeValue, 128, L"Private experimentation");
        break;

    case 127:
        wcscpy_s(ICMPTypeValue, 128, L"Reserved for expansion of ICMPv6 error messages");
        break;

    case 128:
        wcscpy_s(ICMPTypeValue, 128, L"Echo Request");
        break;

    case 129:
        wcscpy_s(ICMPTypeValue, 128, L"Echo Reply");
        break;

    case 130:
        wcscpy_s(ICMPTypeValue, 128, L"Multicast Listener Query");
        break;

    case 131:
        wcscpy_s(ICMPTypeValue, 128, L"Multicast Listener Report");
        break;

    case 132:
        wcscpy_s(ICMPTypeValue, 128, L"Multicast Listener Done");
        break;

    case 133:
        wcscpy_s(ICMPTypeValue, 128, L"Router Solicitation");
        break;

    case 134:
        wcscpy_s(ICMPTypeValue, 128, L"Router Advertisement");
        break;

    case 135:
        wcscpy_s(ICMPTypeValue, 128, L"Neighbor Solicitation");
        break;

    case 136:
        wcscpy_s(ICMPTypeValue, 128, L"Neighbor Advertisement");
        break;

    case 137:
        wcscpy_s(ICMPTypeValue, 128, L"Redirect Message");
        break;

    case 138:
        wcscpy_s(ICMPTypeValue, 128, L"Router Renumbering");
        break;

    case 139:
        wcscpy_s(ICMPTypeValue, 128, L"ICMP Node Information Query");
        break;

    case 140:
        wcscpy_s(ICMPTypeValue, 128, L"ICMP Node Information Response");
        break;

    case 141:
        wcscpy_s(ICMPTypeValue, 128, L"Inverse Neighbor Discovery Solicitation Message");
        break;

    case 142:
        wcscpy_s(ICMPTypeValue, 128, L"Inverse Neighbor Discovery Advertisement Message");
        break;

    case 143:
        wcscpy_s(ICMPTypeValue, 128, L"Version 2 Multicast Listener Report");
        break;

    case 144:
        wcscpy_s(ICMPTypeValue, 128, L"Home Agent Address Discovery Request Message");
        break;

    case 145:
        wcscpy_s(ICMPTypeValue, 128, L"Home Agent Address Discovery Reply Message");
        break;

    case 146:
        wcscpy_s(ICMPTypeValue, 128, L"Mobile Prefix Solicitation");
        break;

    case 147:
        wcscpy_s(ICMPTypeValue, 128, L"Mobile Prefix Advertisement");
        break;

    case 148:
        wcscpy_s(ICMPTypeValue, 128, L"Certification Path Solicitation Message");
        break;

    case 149:
        wcscpy_s(ICMPTypeValue, 128, L"Certification Path Advertisement Message");
        break;

    case 150:
        wcscpy_s(ICMPTypeValue, 128, L"ICMP messages utilized by experimental mobility protocols such as Seamoby");
        break;

    case 151:
        wcscpy_s(ICMPTypeValue, 128, L"Multicast Router Advertisement");
        break;

    case 152:
        wcscpy_s(ICMPTypeValue, 128, L"Multicast Router Solicitation");
        break;

    case 153:
        wcscpy_s(ICMPTypeValue, 128, L"Multicast Router Termination");
        break;

    case 154:
        wcscpy_s(ICMPTypeValue, 128, L"FMIPv6 Messages");
        break;

    case 155:
        wcscpy_s(ICMPTypeValue, 128, L"RPL Control Message");
        break;

    case 156:
        wcscpy_s(ICMPTypeValue, 128, L"ILNPv6 Locator Update Message");
        break;

    case 157:
        wcscpy_s(ICMPTypeValue, 128, L"Duplicate Address Request");
        break;

    case 158:
        wcscpy_s(ICMPTypeValue, 128, L"Duplicate Address Confirmation");
        break;

    case 159:
        wcscpy_s(ICMPTypeValue, 128, L"MPL Control Message");
        break;

    case 160:
        wcscpy_s(ICMPTypeValue, 128, L"Extended Echo Request");
        break;

    case 161:
        wcscpy_s(ICMPTypeValue, 128, L"Extended Echo Reply");
        break;

    case 200:
    case 201:
        wcscpy_s(ICMPTypeValue, 128, L"Private experimentation");
        break;

    case 255:
        wcscpy_s(ICMPTypeValue, 128, L"Reserved for expansion of ICMPv6 informational messages");
        break;

    default:
        wcscpy_s(ICMPTypeValue, 128, L"Unassigned");
        break;
    }
}

void GetICMPv4TypeValue(UINT8 ICMPIndex, WCHAR* ICMPTypeValue)
{
    switch (ICMPIndex)
    {
    case 0:
        wcscpy_s(ICMPTypeValue, 128, L"Echo Reply");
        break;

    case 1:
    case 2:
    case 7:
        wcscpy_s(ICMPTypeValue, 128, L"Unassigned");
        break;

    case 3:
        wcscpy_s(ICMPTypeValue, 128, L"Destination Unreachable");
        break;

    case 4:
        wcscpy_s(ICMPTypeValue, 128, L"Source Quench (Deprecated)");
        break;

    case 5:
        wcscpy_s(ICMPTypeValue, 128, L"Redirect");
        break;

    case 6:
        wcscpy_s(ICMPTypeValue, 128, L"Alternate Host Address (Deprecated)");
        break;

    case 8:
        wcscpy_s(ICMPTypeValue, 128, L"Echo");
        break;

    case 9:
        wcscpy_s(ICMPTypeValue, 128, L"Router Advertisement");
        break;

    case 10:
        wcscpy_s(ICMPTypeValue, 128, L"Router Solicitation");
        break;

    case 11:
        wcscpy_s(ICMPTypeValue, 128, L"Time Exceeded");
        break;

    case 12:
        wcscpy_s(ICMPTypeValue, 128, L"Parameter Problem");
        break;

    case 13:
        wcscpy_s(ICMPTypeValue, 128, L"Timestamp");
        break;

    case 14:
        wcscpy_s(ICMPTypeValue, 128, L"Timestamp Reply");
        break;

    case 15:
    case 16:
    case 17:
    case 18:
        wcscpy_s(ICMPTypeValue, 128, L"Deprecated");
        break;

    case 19:
        wcscpy_s(ICMPTypeValue, 128, L"Reserved (for Security)");
        break;

    case 30:
        wcscpy_s(ICMPTypeValue, 128, L"Traceroute (Deprecated)");
        break;

    case 31:
        wcscpy_s(ICMPTypeValue, 128, L"Datagram Conversion Error (Deprecated)");
        break;

    case 32:
        wcscpy_s(ICMPTypeValue, 128, L"Mobile Host Redirect (Deprecated)");
        break;

    case 33:
        wcscpy_s(ICMPTypeValue, 128, L"IPv6 Where-Are-You (Deprecated)");
        break;

    case 34:
        wcscpy_s(ICMPTypeValue, 128, L"IPv6 I-Am-Here (Deprecated)");
        break;

    case 35:
        wcscpy_s(ICMPTypeValue, 128, L"Mobile Registration Request (Deprecated)");
        break;

    case 36:
        wcscpy_s(ICMPTypeValue, 128, L"Mobile Registration Reply (Deprecated)");
        break;

    case 37:
        wcscpy_s(ICMPTypeValue, 128, L"Domain Name Request (Deprecated)");
        break;

    case 38:
        wcscpy_s(ICMPTypeValue, 128, L"Domain Name Reply (Deprecated)");
        break;

    case 39:
        wcscpy_s(ICMPTypeValue, 128, L"SKIP (Deprecated)");
        break;

    case 40:
        wcscpy_s(ICMPTypeValue, 128, L"Photuris");
        break;

    case 41:
        wcscpy_s(ICMPTypeValue, 128, L"Experimental Mobility Protocols (Seamoby)");
        break;

    case 42:
        wcscpy_s(ICMPTypeValue, 128, L"Extended Echo Request");
        break;

    case 43:
        wcscpy_s(ICMPTypeValue, 128, L"Extended Echo Reply");
        break;

    case 253:
        wcscpy_s(ICMPTypeValue, 128, L"RFC3692-style Experiment 1");
        break;

    case 254:
        wcscpy_s(ICMPTypeValue, 128, L"RFC3692-style Experiment 2");
        break;

    case 255:
        wcscpy_s(ICMPTypeValue, 128, L"Reserved");
        break;

    default:
        wcscpy_s(ICMPTypeValue, 128, L"Unassigned");
        break;
    }
}

void NTAPI
DefaultClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER3* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(classifyOut);

    UINT appId = 0;
    UINT localAddressIndex = 0;
    UINT remoteAddressIndex = 0;
    UINT localPortIndex = 0;
    UINT remotePortIndex = 0;
    UINT protocolIndex = 0;
    UINT icmpIndex = 0;

    GetNetwork5TupleIndexesForLayer(inFixedValues->layerId,
        &appId,
        &localAddressIndex,
        &remoteAddressIndex,
        &localPortIndex,
        &remotePortIndex,
        &protocolIndex,
        &icmpIndex);

	FWPS_INCOMING_VALUE* app = &inFixedValues->incomingValue[appId];
    FWPS_INCOMING_VALUE* localAddress = &inFixedValues->incomingValue[localAddressIndex];
    FWPS_INCOMING_VALUE* localPort = &inFixedValues->incomingValue[localPortIndex];
    FWPS_INCOMING_VALUE* remoteAddress = &inFixedValues->incomingValue[remoteAddressIndex];
    FWPS_INCOMING_VALUE* remotePort = &inFixedValues->incomingValue[remotePortIndex];
	FWPS_INCOMING_VALUE* protocol = &inFixedValues->incomingValue[protocolIndex];
	FWPS_INCOMING_VALUE* icmp = &inFixedValues->incomingValue[icmpIndex];

	UNREFERENCED_PARAMETER(app);
    UNREFERENCED_PARAMETER(localAddress);
    UNREFERENCED_PARAMETER(localPort);
    UNREFERENCED_PARAMETER(remoteAddress);
    UNREFERENCED_PARAMETER(remotePort);
    UNREFERENCED_PARAMETER(protocol);
	UNREFERENCED_PARAMETER(icmp);

    WCHAR protocolString[25] = { 0 };
    switch (protocol->value.uint8)
    {
        case PROTOCOL_TCP:
            wcscpy_s(protocolString, sizeof(protocolString) / sizeof(WCHAR), L"TCP");
            break;
        case PROTOCOL_UDP:
            wcscpy_s(protocolString, sizeof(protocolString) / sizeof(WCHAR), L"UDP");
            break;
        case PROTOCOL_ICMP:
            wcscpy_s(protocolString, sizeof(protocolString) / sizeof(WCHAR), L"ICMP");
            break;
        default:
            wcscpy_s(protocolString, sizeof(protocolString) / sizeof(WCHAR), L"Other");
    }

	WCHAR icmpTypeString[128] = { 0 };

    FWP_BYTE_BLOB* appBlob = app->value.byteBlob;
    UNICODE_STRING appPathString;

    BOOLEAN ok = FALSE;
    if (appBlob && (PWCH)appBlob->data)
    {
        appPathString.Buffer = (PWCH)appBlob->data;
        appPathString.Length = (USHORT)appBlob->size;
        appPathString.MaximumLength = (USHORT)appBlob->size;
        ok = TRUE;
    }

    switch(localAddress->value.type)
    {
        case FWP_UINT32: 
        {
			GetICMPv4TypeValue(icmp->value.uint8, icmpTypeString);
            /*struct in_addr ipAddress = {0};

            WCHAR ipAddressBuffer[100] = { 0 };
            ULONG ipAddressBufferSize = ARRAYSIZE(ipAddressBuffer);

            ipAddress.S_un.S_addr = RtlUlongByteSwap(localAddress->value.uint32);*/
            //RtlIpv4AddressToStringExW(&ipAddress, localPort->value.uint16, &ipAddressBuffer[0], &ipAddressBufferSize);

            DbgPrintEx(0, 0, "IPv4\n");

            DbgPrintEx(
                0,
                0,
                "%u.%u.%u.%u:%u\n",
                (localAddress->value.uint32 >> 24) & 0xFF,
                (localAddress->value.uint32 >> 16) & 0xFF,
                (localAddress->value.uint32 >> 8) & 0xFF,
                (localAddress->value.uint32) & 0xFF,
                localPort->value.uint16
            );

            DbgPrintEx(
                0,
                0,
				"%u.%u.%u.%u:%u\n",
                (remoteAddress->value.uint32 >> 24) & 0xFF,
                (remoteAddress->value.uint32 >> 16) & 0xFF,
                (remoteAddress->value.uint32 >> 8) & 0xFF,
                (remoteAddress->value.uint32) & 0xFF,
				remotePort->value.uint16
            );

            DbgPrintEx(
                0,
                0,
                "Protocol: %ws\n",
                protocolString
            );

            DbgPrintEx(
                0,
                0,
                "ICMP Type: %ws (%u)\n",
                icmpTypeString,
                icmp->value.uint8
            );

            if (ok)
            {
                DbgPrintEx(
                    0,
                    0,
                    "AppId: %wZ\n",
                    &appPathString
                );
            }

            //__debugbreak();
			RtlZeroMemory(icmpTypeString, sizeof(icmpTypeString));
        }
        break;

        case FWP_UINT64:
        {
			GetICMPv6TypeValue(icmp->value.uint8, icmpTypeString);

            DbgPrintEx(0, 0, "IPv6\n");

           /* DbgPrintEx(
                0,
                0,
                "%u.%u.%u.%u.%u.%u.%u.%u:%u\n",
				(localAddress->value.uint64 >> 32) & 0xFF,
				(localAddress->value.uint64 >> 48) & 0xFF,
				(localAddress->value.uint64 >> 40) & 0xFF,
                (localAddress->value.uint64 >> 32) & 0xFF,
                (localAddress->value.uint64 >> 24) & 0xFF,
                (localAddress->value.uint64 >> 16) & 0xFF,
                (localAddress->value.uint64 >> 8) & 0xFF,
                (localAddress->value.uint64) & 0xFF,
                localPort->value.uint16
            );

            DbgPrintEx(
                0,
                0,
                "%u.%u.%u.%u.%u.%u.%u.%u:%u\n",
                (localAddress->value.uint32 >> 56) & 0xFF,
                (localAddress->value.uint32 >> 48) & 0xFF,
                (localAddress->value.uint32 >> 40) & 0xFF,
                (localAddress->value.uint32 >> 32) & 0xFF,
                (localAddress->value.uint32 >> 24) & 0xFF,
                (localAddress->value.uint32 >> 16) & 0xFF,
                (localAddress->value.uint32 >> 8) & 0xFF,
                (localAddress->value.uint32) & 0xFF,
                remotePort->value.uint16
            );*/

            DbgPrintEx(
                0,
                0,
                "Protocol: %ws\n",
                protocolString
            );

            DbgPrintEx(
                0,
                0,
                "ICMP Type: %ws (%u)\n",
                icmpTypeString,
                icmp->value.uint8
            );

            if (ok)
            {
                DbgPrintEx(
                    0,
                    0,
                    "AppId: %wZ\n",
                    &appPathString
                );
            }
        }
        break;

        default:
        {
            
        }
	    break;
    }
}

NTSTATUS NTAPI
DefaultNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}

void NTAPI
DefaultDeleteFn(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}

///
/// **************************************************************************************************
/// *                           GLOBAL DATA AREA                                                     *
/// **************************************************************************************************
///

static PDEVICE_OBJECT gNetworkDeviceObject = NULL;
static HANDLE gFilterEngine = NULL;

#define gFwpProviderKey { 0x927e39f6, 0xe5f3, 0x4ed6, { 0xb4, 0xe0, 0xe6, 0x3d, 0xa, 0x1, 0xf7, 0x4 } }

static FWPM_PROVIDER gFwpProvider =
{
    .providerKey = gFwpProviderKey,
    .displayData.name = L"Dsmk - Network Filter Provider",
    .displayData.description = L"Used to filter network connections",
    .flags = 0,
    .providerData = {0},
    .serviceName = NULL
};
static FWPM_SUBLAYER gFwpFilterSubLayer =
{
    .subLayerKey = { 0x97317c16, 0x25f6, 0x4b9d, { 0x9d, 0x4c, 0xec, 0x96, 0x89, 0xc6, 0xf5, 0xf } },
    .displayData.name = L"Dsmk - Network Filter Sublayer",
    .displayData.description = L"Used to filter network connections",
    .flags = 0,
    .providerKey = &gFwpProvider.providerKey,
    .providerData = {0},
    .weight = 0x100
};

#define gAleAuthConnectV4CalloutKeyGuid { 0x18b4d00e, 0x1540, 0x45f5, { 0xa1, 0xfb, 0x4f, 0x8d, 0xd7, 0xe9, 0x6e, 0x00 } }

static FWPM_CALLOUT gAleAuthConnectV4ManagementCallout =
{
    .calloutKey = gAleAuthConnectV4CalloutKeyGuid,
    .displayData.name = L"Dsmk - Callout for FWPM_LAYER_ALE_AUTH_CONNECT_V4",
    .displayData.description = L"This filtering layer allows for authorizing connect requests for outgoing TCP connections.",
    .flags = 0,
    .providerKey = &gFwpProvider.providerKey,
    .providerData = {0},
    .applicableLayer = {0},
    .calloutId = 0
};
static FWPS_CALLOUT gAleAuthConnectV4StateCallout =
{
    .calloutKey = gAleAuthConnectV4CalloutKeyGuid,
    .flags = 0,
    .classifyFn = DefaultClassifyFn,
    .flowDeleteFn = DefaultDeleteFn,
    .notifyFn = DefaultNotifyFn,
};
static UINT32 gAleAuthConnectV4StateCalloutID = 0;
static FWPM_FILTER gAleAuthConnectV4Filter =
{
    .filterKey = {0},
    .displayData.name = L"Dsmk - Filter for FWPM_LAYER_ALE_AUTH_CONNECT_V4",
    .displayData.description = L"This filtering layer allows for authorizing connect requests for outgoing TCP connections.",
    .flags = FWPM_FILTER_FLAG_NONE,
    .providerKey = &gFwpProvider.providerKey,
    .providerData = {0},
    .layerKey = {0},
    .subLayerKey = {0},
    .weight.type = FWP_EMPTY,
    .weight.uint64 = 0,
    .numFilterConditions = 0,
    .filterCondition = NULL,
    .action = {0},
    .providerContextKey = {0},
    .reserved = NULL,
    .filterId = 0,
    .effectiveWeight = {0}
};

#define gAleAuthRecvAcceptV4CalloutKeyGuid { 0x9f16b155, 0xc170, 0x4e3e, { 0x96, 0xf1, 0xe2, 0x9c, 0x31, 0x97, 0x33, 0x62 } }

static FWPM_CALLOUT gAleAuthRecvAcceptV4ManagementCallout =
{
    .calloutKey = gAleAuthRecvAcceptV4CalloutKeyGuid,
    .displayData.name = L"Dsmk - Callout for FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
    .displayData.description = L"This filtering layer allows for authorizing receive and accept requests for incoming TCP connections.",
    .flags = 0,
    .providerKey = &gFwpProvider.providerKey,
    .providerData = {0},
    .applicableLayer = {0},
    .calloutId = 0
};
static FWPS_CALLOUT gAleAuthRecvAcceptV4StateCallout =
{
    .calloutKey = gAleAuthRecvAcceptV4CalloutKeyGuid,
    .flags = 0,
    .classifyFn = DefaultClassifyFn,
    .flowDeleteFn = DefaultDeleteFn,
    .notifyFn = DefaultNotifyFn,
};
static UINT32 gAleAuthRecvAcceptV4StateCalloutID = 0;
static FWPM_FILTER gAleAuthRecvAcceptV4Filter =
{
    .filterKey = {0},
    .displayData.name = L"Dsmk - Filter for FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
    .displayData.description = L"This filtering layer allows for authorizing receive and accept requests for incoming TCP connections.",
    .flags = FWPM_FILTER_FLAG_NONE,
    .providerKey = &gFwpProvider.providerKey,
    .providerData = {0},
    .layerKey = {0},
    .subLayerKey = {0},
    .weight.type = FWP_EMPTY,
    .weight.uint64 = 0,
    .numFilterConditions = 0,
    .filterCondition = NULL,
    .action = {0},
    .providerContextKey = {0},
    .reserved = NULL,
    .filterId = 0,
    .effectiveWeight = {0}
};

#define gAleAuthConnectV6CalloutKeyGuid { 0x1d0e0358, 0x7c2, 0x480f, { 0xba, 0x9e, 0x62, 0x92, 0x9e, 0x64, 0x9, 0xbe } }

static FWPM_CALLOUT gAleAuthConnectV6ManagementCallout =
{
    .calloutKey = gAleAuthConnectV6CalloutKeyGuid,
    .displayData.name = L"Dsmk - Callout for FWPM_LAYER_ALE_AUTH_CONNECT_V6",
    .displayData.description = L"This filtering layer allows for authorizing connect requests for outgoing TCP connections.",
    .flags = 0,
    .providerKey = &gFwpProvider.providerKey,
    .providerData = {0},
    .applicableLayer = {0},
    .calloutId = 0
};
static FWPS_CALLOUT gAleAuthConnectV6StateCallout =
{
    .calloutKey = gAleAuthConnectV6CalloutKeyGuid,
    .flags = 0,
    .classifyFn = DefaultClassifyFn,
    .flowDeleteFn = DefaultDeleteFn,
    .notifyFn = DefaultNotifyFn,
};
static UINT32 gAleAuthConnectV6StateCalloutID = 0;
static FWPM_FILTER gAleAuthConnectV6Filter =
{
    .filterKey = {0},
    .displayData.name = L"Dsmk - Filter for FWPM_LAYER_ALE_AUTH_CONNECT_V6",
    .displayData.description = L"This filtering layer allows for authorizing connect requests for outgoing TCP connections.",
    .flags = FWPM_FILTER_FLAG_NONE,
    .providerKey = &gFwpProvider.providerKey,
    .providerData = {0},
    .layerKey = {0},
    .subLayerKey = {0},
    .weight.type = FWP_EMPTY,
    .weight.uint64 = 0,
    .numFilterConditions = 0,
    .filterCondition = NULL,
    .action = {0},
    .providerContextKey = {0},
    .reserved = NULL,
    .filterId = 0,
    .effectiveWeight = {0}
};

#define gAleAuthRecvAcceptV6CalloutKeyGuid { 0x4b8c96e8, 0xef00, 0x4f9f, { 0x8f, 0x4a, 0xeb, 0x9, 0xcf, 0xc, 0x40, 0xe8 } }

static FWPM_CALLOUT gAleAuthRecvAcceptV6ManagementCallout =
{
    .calloutKey = gAleAuthRecvAcceptV6CalloutKeyGuid,
    .displayData.name = L"Dsmk - Callout for FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6",
    .displayData.description = L"This filtering layer allows for authorizing receive and accept requests for incoming TCP connections.",
    .flags = 0,
    .providerKey = &gFwpProvider.providerKey,
    .providerData = {0},
    .applicableLayer = {0},
    .calloutId = 0
};
static FWPS_CALLOUT gAleAuthRecvAcceptV6StateCallout =
{
    .calloutKey = gAleAuthRecvAcceptV6CalloutKeyGuid,
    .flags = 0,
    .classifyFn = DefaultClassifyFn,
    .flowDeleteFn = DefaultDeleteFn,
    .notifyFn = DefaultNotifyFn,
};
static UINT32 gAleAuthRecvAcceptV6StateCalloutID = 0;
static FWPM_FILTER gAleAuthRecvAcceptV6Filter =
{
    .filterKey = {0},
    .displayData.name = L"Dsmk - Filter for FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6",
    .displayData.description = L"This filtering layer allows for authorizing receive and accept requests for incoming TCP connections.",
    .flags = FWPM_FILTER_FLAG_NONE,
    .providerKey = &gFwpProvider.providerKey,
    .providerData = {0},
    .layerKey = {0},
    .subLayerKey = {0},
    .weight.type = FWP_EMPTY,
    .weight.uint64 = 0,
    .numFilterConditions = 0,
    .filterCondition = NULL,
    .action = {0},
    .providerContextKey = {0},
    .reserved = NULL,
    .filterId = 0,
    .effectiveWeight = {0}
};

///
/// **************************************************************************************************
/// *                           NETWORK FILTER REGISTRATION REGION                                   *
/// **************************************************************************************************
///

VOID
DriverUnregisterNetworkFilter()
{
    /* Unregister the FWPM_LAYER_ALE_AUTH_CONNECT_V4 callout. */
    if (gAleAuthConnectV4Filter.filterId != 0)
    {
        FwpmFilterDeleteById(gFilterEngine, gAleAuthConnectV4Filter.filterId);
        RtlZeroMemory(&gAleAuthConnectV4Filter, sizeof(gAleAuthConnectV4Filter));
    }
    if (gAleAuthConnectV4StateCalloutID != 0)
    {
        FwpsCalloutUnregisterById(gAleAuthConnectV4StateCalloutID);
        gAleAuthConnectV4StateCalloutID = 0;
    }
    if (gAleAuthConnectV4ManagementCallout.calloutId != 0)
    {
        FwpmCalloutDeleteById(gFilterEngine, gAleAuthConnectV4ManagementCallout.calloutId);
        RtlZeroMemory(&gAleAuthConnectV4ManagementCallout, sizeof(gAleAuthConnectV4ManagementCallout));
    }

    /* Unregister the FWPM_LAYER_ALE_RECV_ACCEPT_V4 callout. */
    if (gAleAuthRecvAcceptV4Filter.filterId != 0)
    {
		FwpmFilterDeleteById(gFilterEngine, gAleAuthRecvAcceptV4Filter.filterId);
		RtlZeroMemory(&gAleAuthRecvAcceptV4Filter, sizeof(gAleAuthRecvAcceptV4Filter));
    }

    if (gAleAuthRecvAcceptV4StateCalloutID != 0)
    {
        FwpsCalloutUnregisterById(gAleAuthRecvAcceptV4StateCalloutID);
        gAleAuthRecvAcceptV4StateCalloutID = 0;
	}

    if (gAleAuthRecvAcceptV4ManagementCallout.calloutId != 0)
    {
        FwpmCalloutDeleteById(gFilterEngine, gAleAuthRecvAcceptV4ManagementCallout.calloutId);
        RtlZeroMemory(&gAleAuthRecvAcceptV4ManagementCallout, sizeof(gAleAuthRecvAcceptV4ManagementCallout));
	}

    /* Unregister for FWPM_LAYER_ALE_AUTH_CONNECT_V6      */
    if (gAleAuthConnectV6Filter.filterId != 0)
    {
        FwpmFilterDeleteById(gFilterEngine, gAleAuthConnectV6Filter.filterId);
        RtlZeroMemory(&gAleAuthConnectV6Filter, sizeof(gAleAuthConnectV6Filter));
    }
    if (gAleAuthConnectV6StateCalloutID != 0)
    {
        FwpsCalloutUnregisterById(gAleAuthConnectV6StateCalloutID);
        gAleAuthConnectV6StateCalloutID = 0;
    }
    if (gAleAuthConnectV6ManagementCallout.calloutId != 0)
    {
        FwpmCalloutDeleteById(gFilterEngine, gAleAuthConnectV6ManagementCallout.calloutId);
        RtlZeroMemory(&gAleAuthConnectV6ManagementCallout, sizeof(gAleAuthConnectV6ManagementCallout));
    }

    /* Unregister for FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6  */
    if (gAleAuthRecvAcceptV6Filter.filterId != 0)
    {
        FwpmFilterDeleteById(gFilterEngine, gAleAuthRecvAcceptV6Filter.filterId);
        RtlZeroMemory(&gAleAuthRecvAcceptV6Filter, sizeof(gAleAuthRecvAcceptV6Filter));
    }

    if (gAleAuthRecvAcceptV6StateCalloutID != 0)
    {
        FwpsCalloutUnregisterById(gAleAuthRecvAcceptV6StateCalloutID);
        gAleAuthRecvAcceptV6StateCalloutID = 0;
    }

    if (gAleAuthRecvAcceptV6ManagementCallout.calloutId != 0)
    {
        FwpmCalloutDeleteById(gFilterEngine, gAleAuthRecvAcceptV6ManagementCallout.calloutId);
        RtlZeroMemory(&gAleAuthRecvAcceptV6ManagementCallout, sizeof(gAleAuthRecvAcceptV6ManagementCallout));
    }

    /* Delete the sublayer. */
    if (&gFwpProvider.providerKey == gFwpFilterSubLayer.providerKey)
    {
        FwpmSubLayerDeleteByKey(gFilterEngine, &gFwpFilterSubLayer.subLayerKey);
        RtlZeroMemory(&gFwpFilterSubLayer, sizeof(gFwpFilterSubLayer));
    }

    /* Delete the provider. */
    if (gFwpProvider.displayData.name != NULL)
    {
        FwpmProviderDeleteByKey(gFilterEngine, &gFwpProvider.providerKey);
        RtlZeroMemory(&gFwpProvider, sizeof(gFwpProvider));
    }

    /* Close the engine. */
    if (NULL != gFilterEngine)
    {
        FwpmEngineClose(gFilterEngine);
        gFilterEngine = NULL;
    }
}

NTSTATUS
DriverRegisterNetworkFilter()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    /* The FwpmEngineOpen0 function opens a session to the filter engine. */
    status = FwpmEngineOpen(NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        NULL,
        &gFilterEngine);
    if (!NT_SUCCESS(status))
    {
        gFilterEngine = NULL;
        goto CleanUp;
    }

    /* Add the provider. */
    status = FwpmProviderAdd(gFilterEngine, &gFwpProvider, NULL);
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(&gFwpProvider, sizeof(gFwpProvider));
        goto CleanUp;
    }

    /* Add the sublayer. */
    status = FwpmSubLayerAdd(gFilterEngine, &gFwpFilterSubLayer, NULL);
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(&gFwpFilterSubLayer, sizeof(gFwpFilterSubLayer));
        goto CleanUp;
    }

    /* Register to FWPM_LAYER_ALE_AUTH_CONNECT_V4. */
    gAleAuthConnectV4ManagementCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    status = FwpmCalloutAdd(gFilterEngine, &gAleAuthConnectV4ManagementCallout, NULL, &gAleAuthConnectV4ManagementCallout.calloutId);
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(&gAleAuthConnectV4ManagementCallout, sizeof(gAleAuthConnectV4ManagementCallout));
        goto CleanUp;
    }

    status = FwpsCalloutRegister(gNetworkDeviceObject, &gAleAuthConnectV4StateCallout, &gAleAuthConnectV4StateCalloutID);
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(&gAleAuthConnectV4StateCallout, sizeof(gAleAuthConnectV4StateCallout));
        gAleAuthConnectV4StateCalloutID = 0;

        goto CleanUp;
    }

    gAleAuthConnectV4Filter.action.calloutKey = gAleAuthConnectV4ManagementCallout.calloutKey;
    gAleAuthConnectV4Filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    gAleAuthConnectV4Filter.layerKey = gAleAuthConnectV4ManagementCallout.applicableLayer;
    gAleAuthConnectV4Filter.subLayerKey = gFwpFilterSubLayer.subLayerKey;
    status = FwpmFilterAdd(gFilterEngine, &gAleAuthConnectV4Filter, NULL, &gAleAuthConnectV4Filter.filterId);
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(&gAleAuthConnectV4Filter, sizeof(gAleAuthConnectV4Filter));
        goto CleanUp;
    }

    /* Register to FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4. */
    gAleAuthRecvAcceptV4ManagementCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    status = FwpmCalloutAdd(gFilterEngine, &gAleAuthRecvAcceptV4ManagementCallout, NULL, &gAleAuthRecvAcceptV4ManagementCallout.calloutId);
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(&gAleAuthRecvAcceptV4ManagementCallout, sizeof(gAleAuthRecvAcceptV4ManagementCallout));
        goto CleanUp;
    }

    status = FwpsCalloutRegister(gNetworkDeviceObject, &gAleAuthRecvAcceptV4StateCallout, &gAleAuthRecvAcceptV4StateCalloutID);
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(&gAleAuthRecvAcceptV4StateCallout, sizeof(gAleAuthRecvAcceptV4StateCallout));
        gAleAuthRecvAcceptV4StateCalloutID = 0;
        goto CleanUp;
    }

    gAleAuthRecvAcceptV4Filter.action.calloutKey = gAleAuthRecvAcceptV4ManagementCallout.calloutKey;
    gAleAuthRecvAcceptV4Filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    gAleAuthRecvAcceptV4Filter.layerKey = gAleAuthRecvAcceptV4ManagementCallout.applicableLayer;
    gAleAuthRecvAcceptV4Filter.subLayerKey = gFwpFilterSubLayer.subLayerKey;
    status = FwpmFilterAdd(gFilterEngine, &gAleAuthRecvAcceptV4Filter, NULL, &gAleAuthRecvAcceptV4Filter.filterId);
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(&gAleAuthRecvAcceptV4Filter, sizeof(gAleAuthRecvAcceptV4Filter));
        goto CleanUp;
    }

    /* Register to FWPM_LAYER_ALE_AUTH_CONNECT_V6. */
    gAleAuthConnectV6ManagementCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    status = FwpmCalloutAdd(gFilterEngine, &gAleAuthConnectV6ManagementCallout, NULL, &gAleAuthConnectV6ManagementCallout.calloutId);
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(&gAleAuthConnectV6ManagementCallout, sizeof(gAleAuthConnectV6ManagementCallout));
        goto CleanUp;
    }

    status = FwpsCalloutRegister(gNetworkDeviceObject, &gAleAuthConnectV6StateCallout, &gAleAuthConnectV6StateCalloutID);
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(&gAleAuthConnectV6StateCallout, sizeof(gAleAuthConnectV6StateCallout));
        gAleAuthConnectV6StateCalloutID = 0;
        goto CleanUp;
    }

    gAleAuthConnectV6Filter.action.calloutKey = gAleAuthConnectV6ManagementCallout.calloutKey;
    gAleAuthConnectV6Filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    gAleAuthConnectV6Filter.layerKey = gAleAuthConnectV6ManagementCallout.applicableLayer;
    gAleAuthConnectV6Filter.subLayerKey = gFwpFilterSubLayer.subLayerKey;
    status = FwpmFilterAdd(gFilterEngine, &gAleAuthConnectV6Filter, NULL, &gAleAuthConnectV6Filter.filterId);
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(&gAleAuthConnectV6Filter, sizeof(gAleAuthConnectV6Filter));
        goto CleanUp;
    }

    /* Register to FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6. */
    gAleAuthRecvAcceptV6ManagementCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
    status = FwpmCalloutAdd(gFilterEngine, &gAleAuthRecvAcceptV6ManagementCallout, NULL, &gAleAuthRecvAcceptV6ManagementCallout.calloutId);
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(&gAleAuthRecvAcceptV6ManagementCallout, sizeof(gAleAuthRecvAcceptV6ManagementCallout));
        goto CleanUp;
    }

    status = FwpsCalloutRegister(gNetworkDeviceObject, &gAleAuthRecvAcceptV6StateCallout, &gAleAuthRecvAcceptV6StateCalloutID);
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(&gAleAuthRecvAcceptV6StateCallout, sizeof(gAleAuthRecvAcceptV6StateCallout));
        gAleAuthRecvAcceptV6StateCalloutID = 0;
        goto CleanUp;
    }

    gAleAuthRecvAcceptV6Filter.action.calloutKey = gAleAuthRecvAcceptV6ManagementCallout.calloutKey;
    gAleAuthRecvAcceptV6Filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    gAleAuthRecvAcceptV6Filter.layerKey = gAleAuthRecvAcceptV6ManagementCallout.applicableLayer;
    gAleAuthRecvAcceptV6Filter.subLayerKey = gFwpFilterSubLayer.subLayerKey;
    status = FwpmFilterAdd(gFilterEngine, &gAleAuthRecvAcceptV6Filter, NULL, &gAleAuthRecvAcceptV6Filter.filterId);
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(&gAleAuthRecvAcceptV6Filter, sizeof(gAleAuthRecvAcceptV6Filter));
        goto CleanUp;
    }


CleanUp:
    if (!NT_SUCCESS(status))
    {
        DriverUnregisterNetworkFilter();
    }
    return status;
}

///
/// **************************************************************************************************
/// *                           DRIVER LOAD - UNLOAD REGION                                          *
/// **************************************************************************************************
///

VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    /* Unregister the network filter. */
    DriverUnregisterNetworkFilter();

    /* We no longer need the device object. */
    if (NULL != gNetworkDeviceObject)
    {
        IoDeleteDevice(gNetworkDeviceObject);
        gNetworkDeviceObject = NULL;
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_UNSUCCESSFUL;

    /* Set unload routine. */
    DriverObject->DriverUnload = DriverUnload;

    /* Create the device for being associated with network filter. */
    status = IoCreateDevice(DriverObject,
        0,
        NULL,
        FILE_DEVICE_NETWORK,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &gNetworkDeviceObject);
    if (!NT_SUCCESS(status))
    {
        gNetworkDeviceObject = NULL;
        return status;
    }

    /* Register the network filter callouts. */
    status = DriverRegisterNetworkFilter();
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(gNetworkDeviceObject);
        gNetworkDeviceObject = NULL;

        return status;
    }

    /* All good. */
    return STATUS_SUCCESS;
}