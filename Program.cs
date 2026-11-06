// ============================================================
//  USB Storage Guard Advanced — Privileged Windows Service
//  Author : Omar Yahya Silan (عمر يحي سيلان)
//  Role   : Sole IOCTL owner of \\.\UsbStorageGuard
// ============================================================

using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace UsbStorageGuardService
{
    public class GuardService : ServiceBase
    {
        const string PipeName = "UsbStorageGuard.pipe";
        const uint IOCTL_QUERY = 0x00222000;
        const uint IOCTL_SET   = 0x00222004;

        [StructLayout(LayoutKind.Sequential)]
        struct Policy { public uint Enabled; public uint Reserved; public ulong MaxBytes; }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern SafeFileHandle CreateFile(string name, uint access, uint share,
            IntPtr sec, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "DeviceIoControl")]
        static extern bool DeviceIoControlOut(SafeFileHandle h, uint code,
            IntPtr inBuf, int inSize, out Policy outBuf, int outSize,
            out int returned, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "DeviceIoControl")]
        static extern bool DeviceIoControlIn(SafeFileHandle h, uint code,
            ref Policy inBuf, int inSize, IntPtr outBuf, int outSize,
            out int returned, IntPtr overlapped);

        public GuardService() { ServiceName = "UsbStorageGuard"; }

        protected override void OnStart(string[] args) => StartPipeServer();

        void StartPipeServer()
        {
            var ps = new PipeSecurity();
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            ps.AddAccessRule(new PipeAccessRule(admins, PipeAccessRights.FullControl, AccessControlType.Allow));
            ps.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));

            var server = new NamedPipeServerStream(PipeName, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, ps);

            server.WaitForConnectionAsync().ContinueWith(t =>
            {
                if (!t.IsFaulted)
                {
                    try
                    {
                        using var reader = new StreamReader(server, Encoding.UTF8);
                        using var writer = new StreamWriter(server, Encoding.UTF8) { AutoFlush = true };
                        var line = reader.ReadLine();
                        writer.WriteLine(Handle(line));
                    }
                    catch { }
                }
                server.Dispose();
                StartPipeServer();
            });
        }

        string Handle(string json)
        {
            try
            {
                var req = JsonSerializer.Deserialize<Request>(json);
                using var h = CreateFile(@"\\.\UsbStorageGuard",
                    0x80000000 | 0x40000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
                if (h.IsInvalid) return Error(Marshal.GetLastWin32Error());

                if (req.Op == "get")
                {
                    if (!DeviceIoControlOut(h, IOCTL_QUERY, IntPtr.Zero, 0, out var p,
                        Marshal.SizeOf<Policy>(), out _, IntPtr.Zero))
                        return Error(Marshal.GetLastWin32Error());
                    return JsonSerializer.Serialize(p);
                }
                if (req.Op == "set")
                {
                    var p = new Policy { Enabled = req.Enabled, MaxBytes = req.MaxBytes };
                    if (!DeviceIoControlIn(h, IOCTL_SET, ref p, Marshal.SizeOf<Policy>(),
                        IntPtr.Zero, 0, out _, IntPtr.Zero))
                        return Error(Marshal.GetLastWin32Error());
                    return "OK";
                }
                return Error(87);
            }
            catch (Exception ex) { return Error(ex.HResult); }
        }

        static string Error(int code) => $"{{\"error\":{code}}}";
        record Request(string Op, uint Enabled, ulong MaxBytes);
    }

    static class Program
    {
        static void Main() => ServiceBase.Run(new GuardService());
    }
}
