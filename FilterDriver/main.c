#pragma warning (disable : 4201)

#define NDIS_SUPPORT_NDIS6 1
#define INITGUID

#include <ndis.h>
#include <wdm.h>
#include <fwpsk.h>
#include <guiddef.h>
#include <fwpmk.h>

#include <ip2string.h>

#define UINT_MAX 0xFFFFFFFF
#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17
#define PROTOCOL_ICMP 1


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

	FWPS_INCOMING_VALUE* appId = &inFixedValues->incomingValue[appId];
    FWPS_INCOMING_VALUE* localAddress = &inFixedValues->incomingValue[localAddressIndex];
    FWPS_INCOMING_VALUE* localPort = &inFixedValues->incomingValue[localPortIndex];
    FWPS_INCOMING_VALUE* remoteAddress = &inFixedValues->incomingValue[remoteAddressIndex];
    FWPS_INCOMING_VALUE* remotePort = &inFixedValues->incomingValue[remotePortIndex];
	FWPS_INCOMING_VALUE* protocol = &inFixedValues->incomingValue[protocolIndex];
	FWPS_INCOMING_VALUE* icmpIndex = &inFixedValues->incomingValue[icmpIndex];

	UNREFERENCED_PARAMETER(appId);
    UNREFERENCED_PARAMETER(localAddress);
    UNREFERENCED_PARAMETER(localPort);
    UNREFERENCED_PARAMETER(remoteAddress);
    UNREFERENCED_PARAMETER(remotePort);
    UNREFERENCED_PARAMETER(protocol);
	UNREFERENCED_PARAMETER(icmpIndex);

    {
        NT_ASSERT(localAddress->value.type == FWP_UINT32);
        NT_ASSERT(localPort->value.type == FWP_UINT16);
     
        struct in_addr ipAddress = { 0 };
     
        WCHAR ipAddressBuffer[100] = { 0 };
        ULONG ipAddressBufferSize = ARRAYSIZE(ipAddressBuffer);
     
        ipAddress.S_un.S_addr = RtlUlongByteSwap(localAddress->value.int32);
        RtlIpv4AddressToStringExW(&ipAddress, localPort->value.int16, &ipAddressBuffer[0], &ipAddressBufferSize);
     
        __debugbreak();
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