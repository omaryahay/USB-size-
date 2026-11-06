#include <ntddk.h>
#include <wdf.h>

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD EvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;

#define IOCTL_USG_QUERY_STATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_USG_SET_POLICY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)

typedef struct _USG_POLICY {
    ULONG Enabled;
    ULONGLONG MaxBytes;
} USG_POLICY, *PUSG_POLICY;

static USG_POLICY g_Policy = { 0, 265000000000ULL };

static VOID EvtIoDeviceControl(
    WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t OutputBufferLength,
    size_t InputBufferLength,
    ULONG IoControlCode
)
{
    UNREFERENCED_PARAMETER(Queue);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t information = 0;

    if (IoControlCode == IOCTL_USG_QUERY_STATE &&
        OutputBufferLength >= sizeof(USG_POLICY)) {
        PUSG_POLICY out = NULL;
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(USG_POLICY), (PVOID*)&out, NULL);
        if (NT_SUCCESS(status)) {
            *out = g_Policy;
            information = sizeof(USG_POLICY);
        }
    } else if (IoControlCode == IOCTL_USG_SET_POLICY &&
               InputBufferLength >= sizeof(USG_POLICY)) {
        PUSG_POLICY in = NULL;
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(USG_POLICY), (PVOID*)&in, NULL);
        if (NT_SUCCESS(status)) {
            // TODO: Restrict this IOCTL to a privileged service using secure device ACLs.
            // This control driver is not yet connected to a storage filter.
            g_Policy = *in;
        }
    }

    WdfRequestCompleteWithInformation(Request, status, information);
}

NTSTATUS EvtDeviceAdd(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
{
    UNREFERENCED_PARAMETER(Driver);
    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetExclusive(DeviceInit, TRUE);

    WDFDEVICE device;
    NTSTATUS status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) return status;

    DECLARE_CONST_UNICODE_STRING(sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    status = WdfDeviceCreateSymbolicLink(device, &RTL_CONSTANT_STRING(L"\\DosDevices\\UsbStorageGuard"));
    if (!NT_SUCCESS(status)) return status;

    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;
    UNREFERENCED_PARAMETER(sddl);
    return WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, EvtDeviceAdd);
    return WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
}
