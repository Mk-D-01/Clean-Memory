// CleanMemory - frees RAM before playing VALORANT, then launches it.
//   1. Closes the apps listed in kill-list.txt (next to the exe). Steam gets a graceful
//      "-shutdown", other apps get their window closed, and anything left is force-killed.
//      Riot Client, VALORANT, Vanguard and core Windows processes are never touched.
//   2. Trims the working set of background processes (pages go to standby, not lost).
//   3. Flushes the modified page list to disk.
//   4. Purges the LOW-PRIORITY standby list only, so useful file cache (e.g. VALORANT's
//      own game files from the last session) is kept and loading stays fast.
//   5. Launches VALORANT through the Riot Client.
// Options: --no-launch  --dry-run (show what would be closed, change nothing)  --no-pause
// Requires administrator rights (requested via the embedded manifest).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
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
    const int MemoryPurgeLowPriorityStandbyList = 5;

    // ---- configuration ----
    const string KillListFile = "kill-list.txt";

    const string DefaultKillList =
@"# Apps CleanMemory closes before launching VALORANT.
# One process name per line (the "".exe"" is optional). Lines starting with # are ignored.
# Riot Client, VALORANT, Vanguard and core Windows processes are always protected.

# Steam
steam
steamwebhelper
steamservice
steamerrorreporter
gameoverlayui

# Other launchers
EpicGamesLauncher
EpicWebHelper
Battle.net
EADesktop
upc

# Browsers - usually the biggest RAM users. Reopen and use ""restore tabs"" after playing.
brave
chrome
msedge
firefox
opera

# Remove the # if you don't need these while playing
# Discord
# Spotify
# GitHubDesktop
";

    // Never closed and never trimmed: the game, its launcher, its anti-cheat, and Windows itself.
    static readonly HashSet<string> Protected = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Riot Client", "RiotClientServices", "RiotClientUx", "RiotClientUxRender", "RiotClientCrashHandler",
        "VALORANT", "VALORANT-Win64-Shipping", "vgc", "vgtray", "vgk",
        "System", "Idle", "Registry", "smss", "csrss", "wininit", "winlogon", "services", "lsass",
        "svchost", "dwm", "explorer", "fontdrvhost", "MsMpEng", "audiodg", "Memory Compression",
        "CleanMemory"
    };

    const string ValorantProcess = "VALORANT-Win64-Shipping";

    // ---- helpers ----
    static MEMORYSTATUSEX GetMemory()
    {
        var m = new MEMORYSTATUSEX();
        m.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
        GlobalMemoryStatusEx(ref m);
        return m;
    }

    static string Mb(ulong bytes) { return (bytes / (1024 * 1024)).ToString("N0") + " MB"; }

    // Prints the change in available memory since the last call.
    static ulong lastAvail;
    static string Delta()
    {
        ulong now = GetMemory().ullAvailPhys;
        long diff = ((long)now - (long)lastAvail) / (1024 * 1024);
        lastAvail = now;
        return string.Format("  [{0}{1:N0} MB]", diff >= 0 ? "+" : "", diff);
    }

    static bool IsAdmin()
    {
        return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    }

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

    // Returns "OK" or the NTSTATUS code, e.g. 0xC0000061 = privilege not held.
    static string SystemMemoryCommand(int command)
    {
        int status = NtSetSystemInformation(SystemMemoryListInformation, ref command, sizeof(int));
        return status == 0 ? "OK" : string.Format("failed (NTSTATUS 0x{0:X8})", status);
    }

    static bool IsRunning(string name)
    {
        var procs = Process.GetProcessesByName(name);
        foreach (var p in procs) p.Dispose();
        return procs.Length > 0;
    }

    // Reads kill-list.txt next to the exe, creating it with defaults on first run.
    static HashSet<string> LoadKillList()
    {
        string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, KillListFile);
        if (!File.Exists(path))
        {
            try { File.WriteAllText(path, DefaultKillList); }
            catch { }
        }
        string[] lines = File.Exists(path) ? File.ReadAllLines(path) : DefaultKillList.Split('\n');

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string raw in lines)
        {
            string line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("#")) continue;
            if (line.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) line = line.Substring(0, line.Length - 4);
            if (!Protected.Contains(line)) names.Add(line);
        }
        return names;
    }

    static Process[] GetListedProcesses(HashSet<string> names)
    {
        return Process.GetProcesses().Where(p => names.Contains(p.ProcessName)).ToArray();
    }

    // Closes every listed process. Returns how many were running; 'left' is how many survived.
    static int CloseApps(HashSet<string> names, bool dryRun, out int left)
    {
        var procs = GetListedProcesses(names);
        left = 0;
        if (procs.Length == 0) return 0;

        if (dryRun)
        {
            Console.WriteLine();
            foreach (var g in procs.GroupBy(p => p.ProcessName, StringComparer.OrdinalIgnoreCase))
                Console.WriteLine("        would close {0} ({1} processes)", g.Key, g.Count());
            foreach (var p in procs) p.Dispose();
            return procs.Length;
        }

        // Graceful first: Steam finishes cloud saves via -shutdown (only if the client is
        // already running, so this never launches Steam); other apps get their windows closed.
        int waitMs = 5000;
        var steam = procs.FirstOrDefault(p => p.ProcessName.Equals("steam", StringComparison.OrdinalIgnoreCase));
        if (steam != null)
        {
            try
            {
                string exe = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamExe", null) as string
                             ?? steam.MainModule.FileName;
                using (Process.Start(exe, "-shutdown")) { }
                waitMs = 15000;
            }
            catch { }
        }
        foreach (var p in procs)
        {
            try { if (p.MainWindowHandle != IntPtr.Zero) p.CloseMainWindow(); }
            catch { }
        }

        var deadline = DateTime.Now.AddMilliseconds(waitMs);
        while (DateTime.Now < deadline && procs.Any(p => { try { return !p.HasExited; } catch { return false; } }))
            Thread.Sleep(250);

        // Force-kill whatever is left (helpers, services, or apps that ignored the close request).
        foreach (var p in GetListedProcesses(names))
        {
            try { p.Kill(); p.WaitForExit(3000); }
            catch { }
            finally { p.Dispose(); }
        }
        foreach (var p in procs) p.Dispose();

        left = GetListedProcesses(names).Length;
        return procs.Length;
    }

    static int TrimBackgroundWorkingSets()
    {
        int trimmed = 0;
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (Protected.Contains(p.ProcessName)) continue;
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

    // Riot records the client location in RiotClientInstalls.json; fall back to the default path.
    static string FindRiotClient()
    {
        try
        {
            string json = File.ReadAllText(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                @"Riot Games\RiotClientInstalls.json"));
            var m = Regex.Match(json, "\"rc_default\"\\s*:\\s*\"([^\"]+)\"");
            if (m.Success)
            {
                string path = m.Groups[1].Value.Replace('/', '\\');
                if (File.Exists(path)) return path;
            }
        }
        catch { }
        string fallback = @"C:\Riot Games\Riot Client\RiotClientServices.exe";
        return File.Exists(fallback) ? fallback : null;
    }

    static string LaunchValorant()
    {
        string rc = FindRiotClient();
        if (rc == null) return "Riot Client not found - start VALORANT yourself";
        try
        {
            using (Process.Start(rc, "--launch-product=valorant --launch-patchline=live")) { }
            return "started";
        }
        catch (Exception e) { return "failed: " + e.Message; }
    }

    static void Main(string[] args)
    {
        bool noLaunch = args.Contains("--no-launch", StringComparer.OrdinalIgnoreCase);
        bool dryRun = args.Contains("--dry-run", StringComparer.OrdinalIgnoreCase);
        bool noPause = args.Contains("--no-pause", StringComparer.OrdinalIgnoreCase);

        Console.Title = "Clean Memory";
        var before = GetMemory();
        lastAvail = before.ullAvailPhys;
        Console.WriteLine("Before: {0} available of {1} ({2}% in use){3}\n",
            Mb(before.ullAvailPhys), Mb(before.ullTotalPhys), before.dwMemoryLoad, dryRun ? "  [DRY RUN]" : "");

        bool admin = IsAdmin();
        bool canPurge = admin && EnablePrivilege("SeProfileSingleProcessPrivilege");
        EnablePrivilege("SeIncreaseQuotaPrivilege");
        EnablePrivilege("SeDebugPrivilege");

        bool inGame = IsRunning(ValorantProcess);
        if (inGame) Console.WriteLine("VALORANT is already running - it will not be touched or relaunched.\n");

        Console.Write("[1/5] Closing listed apps...           ");
        int left;
        int closed = CloseApps(LoadKillList(), dryRun, out left);
        if (!dryRun)
            Console.WriteLine((closed == 0 ? "none running"
                            : left == 0 ? closed + " processes closed"
                            : left + " of " + closed + " processes could not be closed") + Delta());

        if (dryRun)
        {
            if (closed == 0) Console.WriteLine("none running");
            Console.WriteLine("\nDry run - nothing was changed. Edit {0} to choose what gets closed.", KillListFile);
        }
        else
        {
            Console.WriteLine("[2/5] Trimming background processes... {0} trimmed{1}",
                TrimBackgroundWorkingSets(), Delta());

            if (canPurge)
            {
                Console.WriteLine("[3/5] Flushing modified page list...   {0}{1}",
                    SystemMemoryCommand(MemoryFlushModifiedList), Delta());
                Console.WriteLine("[4/5] Purging low-priority cache...    {0}{1}",
                    SystemMemoryCommand(MemoryPurgeLowPriorityStandbyList), Delta());
            }
            else
            {
                Console.WriteLine("[3/5] Skipped - run as administrator to flush/purge system lists.");
                Console.WriteLine("[4/5] Skipped.");
            }

            var after = GetMemory();
            long freed = (long)after.ullAvailPhys - (long)before.ullAvailPhys;
            Console.WriteLine("\nAfter:  {0} available of {1} ({2}% in use)",
                Mb(after.ullAvailPhys), Mb(after.ullTotalPhys), after.dwMemoryLoad);
            Console.WriteLine("Freed:  {0:N0} MB\n", freed / (1024 * 1024));

            string launch = noLaunch ? "skipped (--no-launch)" : inGame ? "skipped (already running)" : LaunchValorant();
            Console.WriteLine("[5/5] Launching VALORANT...            {0}", launch);

            if (launch == "started" && !noPause)
            {
                Console.WriteLine("\nGood luck! This window closes in 5 seconds.");
                Thread.Sleep(5000);
                return;
            }
        }

        if (!noPause)
        {
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey(true);
        }
    }
}
