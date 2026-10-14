// CleanMemory - frees RAM. Closes Steam; no other process is killed.
//   1. Closes Steam and all its processes (graceful "-shutdown" first, then force-kill).
//   2. Trims the working set of every running process (pages go to standby, not lost).
//   3. Flushes the modified page list to disk.
//   4. Purges the standby list (cached file data) so it shows up as "free".
// Requires administrator rights (requested via the embedded manifest).

using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32;

class CleanMemory
{
    // ---- Win32 / NT imports ----
    [StructLayout(LayoutKind.Sequential)]
    struct MEMORYSTATUSEX
    {
        public uint dwLength, dwMemoryLoad;
        public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile,
                     ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID Luid; public uint Attributes; }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX m);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("psapi.dll", SetLastError = true)]
    static extern bool EmptyWorkingSet(IntPtr hProcess);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string sys, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES p,
                                             uint len, IntPtr prev, IntPtr retLen);

    [DllImport("ntdll.dll")]
    static extern int NtSetSystemInformation(int infoClass, ref int info, int length);

    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint PROCESS_SET_QUOTA = 0x0100;
    const uint TOKEN_ADJUST_PRIVILEGES = 0x20, TOKEN_QUERY = 0x8;
    const uint SE_PRIVILEGE_ENABLED = 0x2;

    const int SystemMemoryListInformation = 80;
    const int MemoryFlushModifiedList = 3;
    const int MemoryPurgeStandbyList = 4;

    // ---- helpers ----
    static MEMORYSTATUSEX GetMemory()
    {
        var m = new MEMORYSTATUSEX();
        m.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
        GlobalMemoryStatusEx(ref m);
        return m;
    }

    static string Mb(ulong bytes) { return (bytes / (1024 * 1024)).ToString("N0") + " MB"; }

    static bool EnablePrivilege(string name)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
            return false;
        try
        {
            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Attributes = SE_PRIVILEGE_ENABLED };
            if (!LookupPrivilegeValue(null, name, out tp.Luid)) return false;
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;
            return Marshal.GetLastWin32Error() == 0; // ERROR_NOT_ALL_ASSIGNED otherwise
        }
        finally { CloseHandle(token); }
    }

    static bool SystemMemoryCommand(int command)
    {
        return NtSetSystemInformation(SystemMemoryListInformation, ref command, sizeof(int)) == 0;
    }

    // Steam-related processes, matched by name prefix: steam, steamwebhelper, SteamService,
    // steamerrorreporter, gameoverlayui, ...
    static readonly string[] SteamPrefixes = { "steam", "gameoverlayui" };

    static Process[] GetSteamProcesses()
    {
        return Process.GetProcesses().Where(p =>
            SteamPrefixes.Any(s => p.ProcessName.StartsWith(s, StringComparison.OrdinalIgnoreCase))).ToArray();
    }

    // Returns the number of Steam processes that were running.
    static int CloseSteam()
    {
        var procs = GetSteamProcesses();
        if (procs.Length == 0) return 0;

        // Graceful first, so Steam can finish cloud saves and write its config.
        // Only done if the main client is running, so this never launches Steam.
        var client = procs.FirstOrDefault(p => p.ProcessName.Equals("steam", StringComparison.OrdinalIgnoreCase));
        if (client != null)
        {
            try
            {
                string exe = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamExe", null) as string
                             ?? client.MainModule.FileName;
                Process.Start(exe, "-shutdown");
                client.WaitForExit(15000);
            }
            catch { }
        }

        // Force-kill whatever is left (helpers, service, or a client that ignored -shutdown).
        foreach (var p in GetSteamProcesses())
        {
            try { p.Kill(); p.WaitForExit(3000); }
            catch { }
            finally { p.Dispose(); }
        }
        foreach (var p in procs) p.Dispose();
        return procs.Length;
    }

    static int TrimAllWorkingSets()
    {
        int trimmed = 0;
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA, false, p.Id);
                if (h == IntPtr.Zero) continue; // protected/system process - skip
                if (EmptyWorkingSet(h)) trimmed++;
                CloseHandle(h);
            }
            catch { }
            finally { p.Dispose(); }
        }
        return trimmed;
    }

    static void Main()
    {
        Console.Title = "Clean Memory";
        var before = GetMemory();
        Console.WriteLine("Before: {0} free of {1} ({2}% in use)\n",
            Mb(before.ullAvailPhys), Mb(before.ullTotalPhys), before.dwMemoryLoad);

        bool admin = EnablePrivilege("SeProfileSingleProcessPrivilege");
        EnablePrivilege("SeIncreaseQuotaPrivilege");
        EnablePrivilege("SeDebugPrivilege");

        Console.Write("[1/4] Closing Steam...                ");
        int steam = CloseSteam();
        int left = GetSteamProcesses().Length;
        Console.WriteLine(steam == 0 ? "not running"
                        : left == 0 ? steam + " processes closed"
                        : left + " processes could not be closed");

        Console.WriteLine("[2/4] Trimming process working sets... {0} processes trimmed", TrimAllWorkingSets());

        if (admin)
        {
            Console.WriteLine("[3/4] Flushing modified page list...  {0}",
                SystemMemoryCommand(MemoryFlushModifiedList) ? "OK" : "failed");
            Console.WriteLine("[4/4] Purging standby list...         {0}",
                SystemMemoryCommand(MemoryPurgeStandbyList) ? "OK" : "failed");
        }
        else
        {
            Console.WriteLine("[3/4] Skipped - run as administrator to flush/purge system lists.");
            Console.WriteLine("[4/4] Skipped.");
        }

        var after = GetMemory();
        long freed = (long)after.ullAvailPhys - (long)before.ullAvailPhys;
        Console.WriteLine("\nAfter:  {0} free of {1} ({2}% in use)",
            Mb(after.ullAvailPhys), Mb(after.ullTotalPhys), after.dwMemoryLoad);
        Console.WriteLine("Freed:  {0:N0} MB", freed / (1024 * 1024));

        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey(true);
    }
}
