using Microsoft.Win32.SafeHandles;
using Silverton.Core.Build;
using Silverton.Core.Interop;
using Silverton.Core.IO;
using Silverton.Core.Log;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Silverton.Core.Environment;
using System.Linq;

/*
 * TODO:
 * [ ] Properly dispose of the pipes
 * [ ] Detect native exes that can be invoked without interception
 * [ ] Allow reading of nativeExecutionBlocklist from an environment variable
 */
namespace Silverton.Interceptor {

    // Responsible for adjusting new process launches (via CreateProcess*() methods) in order to redirect them to our launcher
    public class NewProcessInterceptor {

        private List<string> nativeExecutionDirectories = new List<string>();
        private Dictionary<string, bool> nativeExecutionBlocklist = new Dictionary<string, bool>();

        private string dotNetPath = @"";
        private string initializeXmlPath = @"";
        private string launcherDirectory = @"";

        public NewProcessInterceptor(string dotNetPath, string initializeXmlPath, string launcherDirectory, string[] nativeExecutionDirectories, string[] nativeExecutionBlocklist) {
            this.dotNetPath = dotNetPath;
            this.initializeXmlPath = initializeXmlPath;
            this.launcherDirectory = launcherDirectory;
            this.nativeExecutionDirectories = new List<string>(nativeExecutionDirectories);
            foreach (var exePath in nativeExecutionBlocklist) {
                this.nativeExecutionBlocklist[exePath.ToLower()] = true;
            }
        }

        // Patch the environment variable block of the new process
        public IntPtr PatchEnvironmentVariableBlock(IntPtr environmentVariablesBlock, bool launchAsNewUser, bool launchAsLogin) {

            var dirty = false;

            // If the environmental block isn't set, it inherits from the current process which we assume will have the necessary environment variables set
            if (environmentVariablesBlock != IntPtr.Zero) {

                var environmentVariables = GetEnvironmentVariables(environmentVariablesBlock);

                // Prevents random .NET CLR errors
                if (!environmentVariables.ContainsKey("DOTNET_CLI_TELEMETRY_OPTOUT")) {
                    environmentVariables["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
                    dirty = true;
                }

                // Prevents random MSBuild errors
                if (!environmentVariables.ContainsKey("DOTNET_EnableWriteXorExecute")) {
                    environmentVariables["DOTNET_EnableWriteXorExecute"] = "0";
                    dirty = true;
                }

                // TODO: Propagate through DOTNET_ROLL_FORWARD & DOTNET_ROOT

                // NOTE: This is IMPORTANT - dotnet.exe will NOT execute if it doesn't have a TEMP environment variable set as it will fallback to C:\Windows\MSBuild as it's temp directory
                // NOTE: We do not have to do this for processes spawned as new users as they get their own TEMP directory assigned by the OS
                if (!launchAsNewUser && !environmentVariables.ContainsKey("TEMP")) {
                    environmentVariables["TEMP"] = Path.GetTempPath();
                    dirty = true;
                }

                // I think pwsh needs this
                if (launchAsLogin && !environmentVariables.ContainsKey("PROGRAMFILESDIR")) {
                    environmentVariables["PROGRAMFILESDIR"] = Environment.SystemDirectory;
                    dirty = true;
                }

                if (dirty) {
                    // Create new environment variable block in memory
                    environmentVariablesBlock = Marshal.StringToHGlobalUni(ConvertDictionaryToEnvironmentVariableBlock(environmentVariables));
                    Logger.Log("Overwrote environmental variable block", Logger.LogLevel.DEBUG);
                }
            }

            return environmentVariablesBlock;
        }

        // Patch the dwCreationFlags
        public uint PatchCreationFlags(uint dwCreationFlags) {

            // NOTE: This is IMPORTANT - dotnet.exe will NOT execute if we create the process as a DETACHED_PROCESS as it needs a console
            dwCreationFlags = dwCreationFlags & ~(uint)0x8; // ~(DETACHED_PROCESS)

            return dwCreationFlags;
        }

        // Patch the lpApplicationName, lpCommandLine, and lpStartupInfo in order to redirect to our launcher.
        public (string, string) PatchApplicationAndCommand(string workingDirectory, string lpApplicationName, string lpCommandLine, IntPtr lpStartupInfo) {

            // NOTE: fileName can be null, in which case the first argument in the command is the file name
            var exeName = lpApplicationName;
            if (exeName == null) {
                var args = Parser.ParseArguments(lpCommandLine);
                if (args.Count > 0) {
                    exeName = args[0];
                }
            }

            // Determine if we need to bypass our launcher
            if (exeName != null) {
                exeName = exeName.Trim();
                exeName = exeName.Trim('"');
                exeName = exeName.Replace(@"\\", @"\");
                exeName = exeName.ToLower();

                // Don't intercept our launcher
                if (exeName.StartsWith(dotNetPath.ToLower())) {
                    Logger.Log($"Not intercepting process creation: {exeName}");
                    return (lpApplicationName, lpCommandLine);
                }

                // Don't intercept signed exe's that *should* run on the Xbox, unless its in our blocklist
                // Example uses of blocklist are native executables that create processes for unsigned code, like cmd.exe & conhost.exe
                if (nativeExecutionDirectories.Any(dir => exeName.ToLower().StartsWith(dir.ToLower())) && !nativeExecutionBlocklist.ContainsKey(exeName)) { // && FileIntegrity.IsSignedByOS(exeName)){ // TODO <-- Don't rely on heuristics, figure out how Xbox determines which EXEs can execute
                    Logger.Log($"Not intercepting process creation: {exeName}");
                    return (lpApplicationName, lpCommandLine);
                }
            }

            // Capture the output of the child processes Launcher logs
            (IntPtr stdOut, IntPtr stdError) = InterceptPipes(exeName, lpStartupInfo);

            // Basic escaping for quotes in paths
            var xmlPath = initializeXmlPath.Replace("\"", "\\\"");

            // Prepend the command to our argument list if it wasn't already there
            // NOTE: CommandLine should already have the first argument as the application name, if it is provided
            if (lpCommandLine == null) {
                lpCommandLine = lpApplicationName;
            }

            // Take the current working directory if none is supplied
            if (string.IsNullOrEmpty(workingDirectory)) {
                workingDirectory = Directory.GetCurrentDirectory();
            }

            // We pass along the internals needed to make this call again
            // NOTE: We need to escape our properties per MSBuild requirements
            dotNetPath = MSBuild.EscapeMSBuildPropertyValue(dotNetPath);
            initializeXmlPath = MSBuild.EscapeMSBuildPropertyValue(initializeXmlPath);
            launcherDirectory = MSBuild.EscapeMSBuildPropertyValue(launcherDirectory);
            workingDirectory = MSBuild.EscapeMSBuildPropertyValue(workingDirectory);
            lpCommandLine = MSBuild.EscapeMSBuildPropertyValue(lpCommandLine);

            // NOTE: The first character in the argument string is ignored by the OS -- we must prepend a space
            // NOTE: /nologo is used to suppress "MSBuild version 17.10.4+10fbfbf2e for .NET" in STDOUT
            var arguments = $" msbuild /nologo \"{xmlPath}\" -property:LogLevel=\"{Logger.GetLogLevel()}\" -property:DotNetExe=\"{dotNetPath}\" -property:LauncherDirectory=\"{launcherDirectory}\" -property:InitializeXml=\"{initializeXmlPath}\" -property:WorkingDirectory=\"{workingDirectory}\" -property:Command=\"{lpCommandLine}\" -property:StdOut=\"{stdOut}\" -property:StdError=\"{stdError}\" -property:ParentProcessId=\"{Process.GetCurrentProcess().Id}\"";

            Logger.Log($"Running the following command: {dotNetPath} {arguments}");
            return (dotNetPath, arguments);
        }

#nullable enable
        // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Diagnostics.Process/src/System/Diagnostics/Process.Windows.cs
        private static string ConvertDictionaryToEnvironmentVariableBlock(IDictionary<string, string?> sd) {
            // https://learn.microsoft.com/windows/win32/procthread/changing-environment-variables
            // "All strings in the environment block must be sorted alphabetically by name. The sort is
            //  case-insensitive, Unicode order, without regard to locale. Because the equal sign is a
            //  separator, it must not be used in the name of an environment variable."

            var keys = new string[sd.Count];
            sd.Keys.CopyTo(keys, 0);
            Array.Sort(keys, StringComparer.OrdinalIgnoreCase);

            // Join the null-terminated "key=val\0" strings
            var result = new StringBuilder(8 * keys.Length);
            foreach (string key in keys) {
                string? value = sd[key];

                // Ignore null values for consistency with Environment.SetEnvironmentVariable
                if (value != null) {
                    result.Append(key).Append('=').Append(value).Append('\0');
                }
            }

            return result.ToString();
        }

        // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Environment.Variables.Windows.cs#L13
        private static IDictionary<string, string?> GetEnvironmentVariables(IntPtr environmentVariablesBlock) {

            var results = new Dictionary<string, string?>();

            IntPtr currentPtr = environmentVariablesBlock;
            while (true) {
                var variable = Marshal.PtrToStringUni(currentPtr);
                if (string.IsNullOrEmpty(variable)) {
                    break;
                }

                int i = variable.IndexOf('=');
                if (i > 0) {
                    string key = variable.Substring(0, i);
                    string value = variable.Substring(i + 1);
                    try {
                        results.Add(key, value);
                    }
                    catch (ArgumentException) {
                        // Duplicates
                    }
                }
                currentPtr += variable.Length * 2 + 2;
            }

            return results;
        }
#nullable disable

        // Create a pipe to communicate between this Launcher and the child processes Launcher, allowing capturing of our logger
        private static (IntPtr, IntPtr) InterceptPipes(string exeName, IntPtr lpStartupInfo) {

            IntPtr parentOutputPipeHandle = IntPtr.Zero;
            IntPtr childOutputPipeHandle = IntPtr.Zero;
            IntPtr parentErrorPipeHandle = IntPtr.Zero;
            IntPtr childErrorPipeHandle = IntPtr.Zero;

            // Create the pipes
            CreatePipe(out parentOutputPipeHandle, out childOutputPipeHandle);
            CreatePipe(out parentErrorPipeHandle, out childErrorPipeHandle);

            // Listen to the pipe
            ListenToPipe(exeName, parentOutputPipeHandle);
            ListenToPipe(exeName, parentErrorPipeHandle);

            return (childOutputPipeHandle, childErrorPipeHandle);
        }

        // https://github.com/dotnet/runtime/blob/205adaee20a873243076dee3ef66ad70e0ee563f/src/libraries/System.Diagnostics.Process/src/System/Diagnostics/Process.Windows.cs#L534
        private static void CreatePipe(out IntPtr parentHandle, out IntPtr childHandle) {

            NativeBridge.SECURITY_ATTRIBUTES securityAttributesParent = default;
            securityAttributesParent.bInheritHandle = true;

            IntPtr hTmp = IntPtr.Zero;
            CreatePipeWithSecurityAttributes(out hTmp,
                                                    out childHandle,
                                                    ref securityAttributesParent,
                                                    0);

            IntPtr currentProcHandle = NativeBridge.GetCurrentProcess();
            if (!NativeBridge.DuplicateHandle(currentProcHandle,
                                                    hTmp,
                                                    currentProcHandle,
                                                    out parentHandle,
                                                    0,
                                                    false,
                                                    NativeBridge.DuplicateHandleOptions.DUPLICATE_SAME_ACCESS)) {
                throw new Win32Exception(0x666, "CreatePipe ERROR");
            }
        }

        private static void CreatePipeWithSecurityAttributes(out IntPtr hReadPipe, out IntPtr hWritePipe, ref NativeBridge.SECURITY_ATTRIBUTES lpPipeAttributes, int nSize) {
            bool ret = NativeBridge.CreatePipe(out hReadPipe, out hWritePipe, ref lpPipeAttributes, (uint)nSize);
            if (!ret || hReadPipe == IntPtr.Zero || hWritePipe == IntPtr.Zero) {
                throw new Win32Exception(0x666, "CreatePipeWithSecurityAttributes ERROR");
            }
        }

        // Listens to the pipe, writing all pipe output to the logger as an INFO log with the child processes name prepended
        private static void ListenToPipe(string exeName, IntPtr pipeHandle) {
            var parentStdOutHandle = new SafeFileHandle(pipeHandle, false);
            var standardOutput = new StreamReader(new FileStream(parentStdOutHandle, FileAccess.Read, 4096, false), new UTF8Encoding(), true, 4096);
            Stream s = standardOutput.BaseStream;
            var output = new AsyncStreamReader(s, (message) => {
                Logger.Log($"({exeName.Substring(exeName.LastIndexOf(@"\") + 1)}): {message}");
            }, standardOutput.CurrentEncoding);
            output.BeginReadLine();
        }
    }
}