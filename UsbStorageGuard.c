#include <ntddk.h>
#include <wdf.h>
#include <ntddstor.h>   // IOCTL_STORAGE_READ_CAPACITY
#include <wdmsec.h>     // SDDL_DEVOBJ_SYS_ALL_ADM_ALL

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD EvtDeviceAdd;
EVT_WDF_DEVICE_PREPARE_HARDWARE EvtDevicePrepareHardware;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;
EVT_WDF_IO_IN_CALLER_CONTEXT EvtIoInCallerContext;
EVT_WDF_REQUEST_COMPLETION_ROUTINE EvtCreateCompletion;

#define IOCTL_USG_QUERY_STATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_USG_SET_POLICY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)

typedef struct _USG_POLICY {
    ULONG Enabled;
    ULONG Reserved;
    ULONGLONG MaxBytes;
} USG_POLICY, *PUSG_POLICY;

typedef struct _DEVICE_CONTEXT {
    ULONGLONG DiskBytes;     // 0 = لم تُقرأ بعد
    BOOLEAN   IsUsbStorage;  // هل الجهاز الحالي USBSTOR؟
    BOOLEAN   Blocked;       // نتيجة القرار
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, GetDeviceContext)

static USG_POLICY  g_Policy = { 0, 0, 265000000000ULL }; // Enabled=0 افتراضياً
static WDFSPINLOCK g_PolicyLock;
static WDFDEVICE   g_ControlDevice;

/* ---------- قراءة سعة القرص عبر IOCTL_STORAGE_READ_CAPACITY ---------- */
static NTSTATUS QueryDiskCapacity(WDFDEVICE Device, PULONGLONG Bytes)
{
    WDFIOTARGET target = WdfDeviceGetIoTarget(Device);
    WDF_MEMORY_DESCRIPTOR outDesc;
    STORAGE_READ_CAPACITY  cap = {0};
    WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&outDesc, &cap, sizeof(cap));

    NTSTATUS status = WdfIoTargetSendIoctlSynchronously(
        target, NULL, IOCTL_STORAGE_READ_CAPACITY, NULL, &outDesc, NULL, NULL);

    if (NT_SUCCESS(status)) {
        *Bytes = (ULONGLONG)cap.DiskLength.QuadPart;
    }
    return status;
}

/* ---------- هل الجهاز الحالي تابع لفئة USBSTOR؟ ---------- */
static BOOLEAN IsUsbStorDevice(WDFDEVICE Device)
{
    WDFDEVICE pdo = WdfDeviceWdmGetPhysicalDevice(Device);
    WCHAR buf[256] = {0};
    UNICODE_STRING id;
    id.Buffer = buf; id.MaximumLength = sizeof(buf); id.Length = 0;

    // DeviceID لجهاز USBSTOR يبدأ بـ USBSTOR\Disk...
    if (NT_SUCCESS(IoGetDeviceProperty(
            WdfDeviceWdmGetPhysicalDevice(Device),
            DevicePropertyHardwareID, buf, sizeof(buf), NULL))) {
        return (wcsstr(buf, L"USBSTOR") != NULL);
    }
    UNREFERENCED_PARAMETER(pdo); UNREFERENCED_PARAMETER(id);
    return FALSE;
}

/* ---------- EvtDevicePrepareHardware: نقطة قراءة السعة عند الإدراج ---------- */
NTSTATUS EvtDevicePrepareHardware(WDFDEVICE Device, WDFCMRESLIST Raw, WDFCMRESLIST Translated)
{
    UNREFERENCED_PARAMETER(Raw); UNREFERENCED_PARAMETER(Translated);
    PDEVICE_CONTEXT ctx = GetDeviceContext(Device);
    ctx->DiskBytes    = 0;
    ctx->IsUsbStorage = IsUsbStorDevice(Device);
    ctx->Blocked      = FALSE;

    if (ctx->IsUsbStorage) {
        ULONGLONG bytes = 0;
        if (NT_SUCCESS(QueryDiskCapacity(Device, &bytes))) {
            ctx->DiskBytes = bytes;
            WdfSpinLockAcquire(g_PolicyLock);
            USG_POLICY p = g_Policy;
            WdfSpinLockRelease(g_PolicyLock);

            if (p.Enabled && bytes > p.MaxBytes) {
                ctx->Blocked = TRUE;
                DbgPrint("[USG] USBSTOR blocked: %llu bytes > limit %llu\n", bytes, p.MaxBytes);
            }
        }
    }
    return STATUS_SUCCESS;
}

/* ---------- حظر IRP_MJ_CREATE على الجهاز المحظور ---------- */
static VOID EvtCreateCompletion(WDFREQUEST Request, WDFIOTARGET Target, PWDF_REQUEST_COMPLETION_PARAMS Params, WDFCONTEXT Context)
{
    UNREFERENCED_PARAMETER(Target); UNREFERENCED_PARAMETER(Context);
    WdfRequestComplete(Request, Params->IoStatus.Status);
}

static VOID EvtIoInCallerContext(WDFDEVICE Device, WDFREQUEST Request)
{
    PDEVICE_CONTEXT ctx = GetDeviceContext(Device);
    WDF_REQUEST_PARAMETERS params;
    WDF_REQUEST_PARAMETERS_INIT(&params);
    WdfRequestGetParameters(Request, &params);

    // إذا كان الجهاز محظوراً، ارفض أي فتح له
    if (params.Type == WdfRequestTypeCreate && ctx->Blocked) {
        WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
        return;
    }
    WdfDeviceEnqueueRequest(Device, Request);
}

/* ---------- IOCTL على جهاز التحكم (الخدمة فقط) ---------- */
static VOID EvtIoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request,
    size_t OutLen, size_t InLen, ULONG IoControlCode)
{
    UNREFERENCED_PARAMETER(Queue);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t info = 0;

    if (IoControlCode == IOCTL_USG_QUERY_STATE && OutLen >= sizeof(USG_POLICY)) {
        PUSG_POLICY out = NULL;
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(USG_POLICY), (PVOID*)&out, NULL);
        if (NT_SUCCESS(status)) {
            WdfSpinLockAcquire(g_PolicyLock);
            *out = g_Policy;
            WdfSpinLockRelease(g_PolicyLock);
            info = sizeof(USG_POLICY);
        }
    } else if (IoControlCode == IOCTL_USG_SET_POLICY && InLen >= sizeof(USG_POLICY)) {
        PUSG_POLICY in = NULL;
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(USG_POLICY), (PVOID*)&in, NULL);
        if (NT_SUCCESS(status)) {
            if (in->Enabled > 1) { status = STATUS_INVALID_PARAMETER; }
            else {
                WdfSpinLockAcquire(g_PolicyLock);
                g_Policy = *in;
                WdfSpinLockRelease(g_PolicyLock);
                info = 0;
            }
        }
    }
    WdfRequestCompleteWithInformation(Request, status, info);
}

/* ---------- EvtDeviceAdd: نُسجّل كمرشح، وننشئ جهاز تحكم منفصل ---------- */
NTSTATUS EvtDeviceAdd(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
{
    WdfFdoInitSetFilter(DeviceInit);            // ← هذا ما يجعله مرشحاً فعلياً

    // جهاز التحكم (الواجهة الوحيدة لخدمة Windows)
    PWDFDEVICE_INIT ctrlInit = WdfControlDeviceInitAllocate(Driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (!ctrlInit) return STATUS_INSUFFICIENT_RESOURCES;

    WdfDeviceInitSetDeviceType(ctrlInit, FILE_DEVICE_UNKNOWN);
    WDFDEVICE ctrl;
    NTSTATUS status = WdfDeviceCreate(&ctrlInit, WDF_NO_OBJECT_ATTRIBUTES, &ctrl);
    if (!NT_SUCCESS(status)) { WdfDeviceInitFree(ctrlInit); return status; }

    DECLARE_CONST_UNICODE_STRING(symLink, L"\\DosDevices\\UsbStorageGuard");
    status = WdfDeviceCreateSymbolicLink(ctrl, &symLink);
    if (!NT_SUCCESS(status)) return status;

    WDF_OBJECT_ATTRIBUTES attrs;
    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
    attrs.ParentObject = ctrl;
    status = WdfSpinLockCreate(&attrs, &g_PolicyLock);
    if (!NT_SUCCESS(status)) return status;

    WDF_IO_QUEUE_CONFIG qc;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&qc, WdfIoQueueDispatchSequential);
    qc.EvtIoDeviceControl = EvtIoDeviceControl;
    status = WdfIoQueueCreate(ctrl, &qc, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) return status;
    WdfControlFinishInitializing(ctrl);
    g_ControlDevice = ctrl;

    // جهاز المرشح نفسه
    WDF_OBJECT_ATTRIBUTES devAttrs;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&devAttrs, DEVICE_CONTEXT);
    WDFDEVICE filterDevice;
    status = WdfDeviceCreate(&DeviceInit, &devAttrs, &filterDevice);
    if (!NT_SUCCESS(status)) return status;

    WDF_PNPPOWER_EVENT_CALLBACKS pnp;
    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp);
    pnp.EvtDevicePrepareHardware = EvtDevicePrepareHardware;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnp);

    // اعتراض CREATE قبل وصوله للسائق السفلي
    WDF_IO_QUEUE_CONFIG fqc;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&fqc, WdfIoQueueDispatchSequential);
    fqc.EvtIoDeviceControl = NULL;
    status = WdfIoQueueCreate(filterDevice, &fqc, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) return status;

    WdfDeviceInitSetIoInCallerContextCallback(DeviceInit, EvtIoInCallerContext);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG cfg;
    WDF_DRIVER_CONFIG_INIT(&cfg, EvtDeviceAdd);
    return WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &cfg, WDF_NO_HANDLE);
}
