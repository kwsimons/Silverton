using System;
using System.Runtime.InteropServices;
using System.IO;
using Silverton.Core.Interop;
using System.Reflection;
using System.Collections.Generic;
using Silverton.Core.Log;
using Silverton.Core.Environment;
using Silverton.Injector;
using Silverton.Interceptor;
using System.Linq;

namespace Silverton {
    public class Launcher {

        // Main entry point, invoked via MSBuild + initialize.xml
        public static void Launch(int logLevel, string initializeXmlPath, string dotNetPath, string launcherDirectory, string currentWorkingDirectory, string command, string[] nativeExecutionDirectories, string[] nativeExecutionBlockList, int StdOut = -11, int StdError = -12, int ParentProcessId = 0) {
            Logger.SetLogLevel(logLevel);
            Logger.SetStdError(ParentProcessId, StdError);
            Logger.SetStdOut(ParentProcessId, StdOut);
            Logger.Log($"\n\n");
            Logger.Log($"#################################");
            Logger.Log($"######### Launch #########");
            Logger.Log($"#################################");
            Logger.Log($"\tuser = {Environment.UserDomainName}\\{Environment.UserName} (interactive: {Environment.UserInteractive})");
            Logger.Log($"\tlogLevel = {logLevel}");
            Logger.Log($"\tinitializeXmlPath = {initializeXmlPath}");
            Logger.Log($"\tdotNetPath = {dotNetPath}");
            Logger.Log($"\tlauncherDirectory = {launcherDirectory}");
            Logger.Log($"\tinheritedWorkingDirectory = {Directory.GetCurrentDirectory()}");
            Logger.Log($"\tcurrentWorkingDirectory = {currentWorkingDirectory}");
            Logger.Log($"\tcommand = {command:X}");
            Logger.Log($"\tnativeCommand = {Marshal.PtrToStringUni(NativeBridge.GetCommandLineW())}\n");
            Logger.Log($"\tstdOut = {StdOut}");
            Logger.Log($"\tstdErr = {StdError}");
            Logger.Log($"\tparentProcessId = {ParentProcessId}");
            Logger.Log($"\tnativeExecutionDirectories = {string.Join(",", nativeExecutionDirectories)}");
            Logger.Log($"\tnativeExecutionBlockList3 = {string.Join(",", nativeExecutionBlockList)}");

            var newProcessInterceptor = new NewProcessInterceptor(dotNetPath, initializeXmlPath, launcherDirectory, nativeExecutionDirectories, nativeExecutionBlockList);
            var launcher = new Launcher(newProcessInterceptor, currentWorkingDirectory, command);
        }

        public Launcher(NewProcessInterceptor newProcessInterceptor, string currentWorkingDirectory, string command) {
            try {

                // Set our current working directly, as dotnet.exe modifies it
                if (!string.IsNullOrEmpty(currentWorkingDirectory)) {
                    Directory.SetCurrentDirectory(currentWorkingDirectory);
                }

                // Parse command into an executeable path and list of arguments
                string fullExePath;
                (fullExePath, command) = Parser.ParseCommand(command, currentWorkingDirectory);

                // Assume imported dlls will be in the same directory as the exe
                var dllSearchPath = Path.GetDirectoryName(fullExePath);

                // If we can invoke it within the current CLR (leveraging assemblies)
                if (CLRInjector.CanExecuteAsCLR(fullExePath)) {
                    CLRInjector.ExecuteAsCLR(newProcessInterceptor, dllSearchPath, fullExePath, command);

                // Otherwise, just do PE injection and execution
                } else {
                    Execute(newProcessInterceptor, dllSearchPath, fullExePath, command);
                }

            } catch (Exception ex) {
                Logger.Log(ex.ToString(), Logger.LogLevel.ERROR);
                Environment.ExitCode = ex.HResult;
            } finally {
                Logger.Flush();
            }

            Environment.Exit(Environment.ExitCode);
        }

        private static void Execute(NewProcessInterceptor newProcessInterceptor, string dllSearchPath, string fullExePath, string commandLine) {

            // Load our exe into memory
            var injectedExe = InjectedExe.Write(fullExePath);

            // Create a function invoker to handle patching PEB etc when calling DllMain + TLS Callbacks + Exe entry point function calls
            var functionInvoker = new NativeFunctionInvoker(injectedExe.ModuleAddress, fullExePath, commandLine);

            // Create a dll resolver to find and load dlls
            var dllResolver = new DllLoader(dllSearchPath, NativeFunctionInterceptor.GetNativeLoadLibraryAddress(), functionInvoker);

            // Override native API calls to redirect to our custom implementations
            NativeFunctionInterceptor.InstallIntercepts(dllResolver, newProcessInterceptor);

            Logger.Log($"\n");
            Logger.Log($"#################################");
            Logger.Log($"############ native main({fullExePath}) #############");
            Logger.Log($"#################################");

            // Resolve / inject the exe
            injectedExe.Resolve(functionInvoker, dllResolver);

            // Invoke!
            injectedExe.Execute(functionInvoker);
        }

        // Used in tests, installs intercepts so new processes launched will be intercepted.
        public static void TESTONLY_InstallIntercepts(int logLevel, string initializeXmlPath, string dotNetPath, string launcherDirectory, string[] nativeExecutionDirectories, string[] nativeExecutionBlockList) {

            Logger.SetLogLevel(logLevel);

            var newProcessInterceptor = new NewProcessInterceptor(dotNetPath, initializeXmlPath, launcherDirectory, nativeExecutionDirectories, nativeExecutionBlockList);

            // Create a function invoker to handle patching PEB etc when calling DllMain + TLS Callbacks + Exe entry point function calls
            var functionInvoker = new NativeFunctionInvoker(NativeBridge.GetModuleHandle(null), Assembly.GetEntryAssembly().Location, "TODO");

            // Create a dll resolver to find and load dlls
            var dllResolver = new DllLoader(Environment.CurrentDirectory, NativeFunctionInterceptor.GetNativeLoadLibraryAddress(), functionInvoker);

            // Override native API calls to redirect to our custom implementations
            NativeFunctionInterceptor.InstallIntercepts(dllResolver, newProcessInterceptor);
        }
    }
}