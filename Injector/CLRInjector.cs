using System;
using System.IO;
using System.Reflection;
using System.Collections.Generic;
using Silverton.Core.Log;
using System.Threading;
using static Silverton.Core.Interop.NativeBridge;
using Silverton.Interceptor;
using System.Runtime.Loader;
using Silverton.Core.Environment;

namespace Silverton.Injector {

    // Responsible for determining whether a DLL is a .NET CLR, and if so, load & execute it natively using the current CLR.
    public class CLRInjector {

        // Detect CLR (.NET) exes and invoke their underlying DLLs instead as the CLR is already loaded
        // Retruns true if it is a CLR and was invoked, false if it should be loaded natively and invoked
        public static bool CanExecuteAsCLR(string exePath) {

            // A CLR launcher exe has an accompanying dll with the same name
            var fullDllPath = Path.Combine(Path.GetDirectoryName(exePath), Path.GetFileNameWithoutExtension(exePath) + ".dll");
            if (!File.Exists(fullDllPath)) {
                Logger.Log("CLR dll not found, loading natively", Logger.LogLevel.TRACE);
                return false;
            }

            if (Environment.GetEnvironmentVariable("CLR_ASSEMBLY_INJECTION") == "FORCE") {
                Logger.Log("Forcing native CLR execution due to CLR_ASSEMBLY_INJECTION flag", Logger.LogLevel.DEBUG);
                return true;
            }

            if (Environment.GetEnvironmentVariable("CLR_ASSEMBLY_INJECTION") == "SKIP") {
                Logger.Log("Bypassing native CLR execution due to CLR_ASSEMBLY_INJECTION flag", Logger.LogLevel.DEBUG);
                return false;
            }

#nullable enable
            MethodInfo? entryPoint;
            try {

                // This will throw an exception if it is not a CLR dll
                var exeAssembly = Assembly.Load(File.ReadAllBytes(fullDllPath));
                
                // TODO: Remove?
                // Determine if it utilizes the same runtime as the current assembly
                foreach (var assembly in exeAssembly.GetReferencedAssemblies()) {
                    if (assembly.Name != "System.Runtime") {
                        continue;
                    }
                    if (assembly.Version != null && assembly.Version.Major != Environment.Version.Major) {
                        Logger.Log($".NET CLR dll System.Runtime version {assembly.Version} but injector is {Environment.Version}, loading natively", Logger.LogLevel.DEBUG);
                        return false;
                    }
                    Logger.Log($".NET CLR dll System.Runtime version {assembly.Version} (injector is {Environment.Version})", Logger.LogLevel.DEBUG);
                }

                // Extract the entry point method
                entryPoint = exeAssembly.EntryPoint;
            }
            catch (Exception ex) {
                Logger.Log($"Unable to load as a .NET CLR dll ({ex.Message}), loading natively: {fullDllPath}", Logger.LogLevel.TRACE);
                return false;
            }
            finally {
                // TODO: Unload the Assembly
            }

            if (entryPoint == null) {
                Logger.Log($"Found .NET CLR dll but could not find an entry point to invoke: {fullDllPath}", Logger.LogLevel.WARN);
                return false;
            }

            return true;
#nullable disable
        }

        public static void ExecuteAsCLR(NewProcessInterceptor newProcessInterceptor, string dllSearchPath, string fullExePath, string command) {

            var fullDllPath = Path.Combine(Path.GetDirectoryName(fullExePath), Path.GetFileNameWithoutExtension(fullExePath) + ".dll");

            // Load our exe into memory
            var injectedExe = InjectedExe.Write(fullDllPath);

            // Create a function invoker to handle patching PEB etc when calling DllMain + TLS Callbacks + Exe entry point function calls
            var functionInvoker = new NativeFunctionInvoker(GetModuleHandle(null), fullExePath, command);

            // Create a dll resolver to find and load dlls
            var dllResolver = new DllLoader(dllSearchPath, NativeFunctionInterceptor.GetNativeLoadLibraryAddress(), functionInvoker);

            // Create our custom load context, so we do not inherit from the current CLRs context
            // This ensures we reload all dependent Assemblies and does not rely on the current CLR assemblies that have been loaded
            var context = new CustomAssemblyLoadContext(dllSearchPath, dllResolver);

            // Override native API calls to redirect to our custom implementations
            NativeFunctionInterceptor.InstallIntercepts(dllResolver, newProcessInterceptor);

            // Resolve / inject the exe
            injectedExe.Resolve(functionInvoker, dllResolver);

            // Load the assembly into the CLR
            var assembly = LoadAssemblyFromMemory(context, injectedExe.ModuleAddress);
            var entryPoint = assembly.EntryPoint;

            // "Unlike C and C++, the name of the program is not treated as the first command-line argument in the args array"
            // Per https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/program-structure/main-command-line#overview
            // TODO: Detect CLR C/C++/C# and make this dynamic
            var arguments = Parser.ParseArguments(command);
            arguments.RemoveAt(0);

            var thread = new Thread(new ThreadStart(() => {
                try {
                    functionInvoker.Invoke(() => {
                        entryPoint.Invoke(null, entryPoint.GetParameters().Length > 0 ? new object[] { arguments.ToArray() } : null);
                    });
                }
                catch (Exception ex) {
                    if (ex is TargetInvocationException) {
                        ex = ex.InnerException;
                    }
                    Environment.ExitCode = ex.HResult;
                    Logger.Log(ex.ToString() + '\n' + ex.StackTrace, Logger.LogLevel.ERROR);
                }
            }));
            thread.Name = "Silverton injected CLR thread";

            Logger.Log($"\n");
            Logger.Log($"#################################");
            Logger.Log($"############ CLR main({fullExePath}) #############");
            Logger.Log($"#################################");
            thread.Start();
            thread.Join();
            Logger.Log($"Thread {thread.ManagedThreadId} completed: 0x{Environment.ExitCode:X}", Logger.LogLevel.DEBUG);
        }

        // By loading via LoadFromInMemoryModule instead of Assembly.FromBytes() we get more native support for Assembly metadata, such as the Assembly.Location
        // NOTE: This is critical because pwsh.exe uses Assembly.Location
        private static Assembly LoadAssemblyFromMemory(AssemblyLoadContext context, IntPtr moduleBaseAddress) {
            var loadFromInMemoryModuleFn = context.GetType().GetMethod("LoadFromInMemoryModule", BindingFlags.NonPublic | BindingFlags.Instance)!;
            return (Assembly)loadFromInMemoryModuleFn.Invoke(context, new object[] { moduleBaseAddress });
        }

        // Custom Assembly loader that looks in our specific search directory
        // This also ensures that all assemblies used in the context will be reloaded, not inheriting from the current CLR
        private class CustomAssemblyLoadContext : AssemblyLoadContext {

            private string dllSearchPath;
            private DllLoader dllLoader;

            public CustomAssemblyLoadContext(string dllSearchPath, DllLoader dllLoader) : base() {
                this.dllSearchPath = dllSearchPath;
                this.dllLoader = dllLoader;
            }

            protected override Assembly Load(AssemblyName assemblyName) {
                var dllName = assemblyName.Name;
                var path = $"{dllSearchPath}\\{dllName}.dll";

                if (File.Exists(path)) {
                    Logger.Log($"Loading CLR assembly {path}", Logger.LogLevel.TRACE);

                    // Load the dll into memory
                    // NOTE: This is a hijacked call
                    var injectedDll = dllLoader.LoadLibrary(path, 0);

                    // Load the assembly from memory
                    var assembly = LoadAssemblyFromMemory(this, injectedDll);

                    Logger.Log($"Loaded CLR assembly {path}", Logger.LogLevel.DEBUG);
                    return assembly;
                }
                return null;
            }
        }
    }
}
