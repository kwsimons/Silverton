using System;
using System.Runtime.InteropServices;

/*
 * TODO:
 * [ ] InvokeIntMain() should execute the entry point in a new thread
 */
namespace Silverton.Injector {

    /*
    Represents an injected executable

    Loading Flow:
        Step 1:
            Load EXE into memory, capture memory address
        Step 2:
            Create FunctionInvoker to be used during step 3 imports TLS callback / DllMain
        Step 3:
            Resolve imports/exports on the EXE
                Loads dependent DLLs into memory & PEB
            Load EXE into PEB
        Step 4:
            Invoke IntMain on EXE
    */
    public class InjectedExe {

        public delegate int IntMain();

        string fullExePath;
        private InMemoryPE exePE;
        private InjectedPE injectedPE;

        // Write EXE to memory, do not resolve dependencies or insert it into the PEB
        public static InjectedExe Write(string fullExePath) {
            return new InjectedExe(fullExePath, 0);
        }

        private InjectedExe(string fullExePath, int dwFlags) {

            this.fullExePath = fullExePath;

            // Load the EXE into memory, but do not resolve its imports
            this.exePE = InMemoryPE.LoadExe(fullExePath, dwFlags);

            // NOTE: This is okay for CLR Dlls we inject
            //if (!exePE.HasEntryPoint) throw new Exception($"Entry point function not found in {fullExePath}");
        }

        // Resolve the imports, load the exe into the PEB etc
        public void Resolve(NativeFunctionInvoker functionInvoker, DllLoader dllLoader) {

            // Resolve memory pointers and imports
            exePE.Resolve(dllLoader);

            this.injectedPE = InjectedPE.Inject(exePE, fullExePath, functionInvoker, true);
        }

        // Invoke the entry point
        public void Execute(NativeFunctionInvoker functionInvoker) {
            this.Execute(functionInvoker, injectedPE.InMemoryPE.EntryPointAddress);
        }

        // Invoke the entry point
        public void Execute(NativeFunctionInvoker functionInvoker, IntPtr functionAddress) {
            functionInvoker.Invoke(() => {
                this.InvokeIntMain(functionAddress);
            });
        }

        // Get the modules base address
        public IntPtr ModuleAddress {
            get { return exePE.BaseAddress; }
        }

        private const uint INFINITE_TIMEOUT = 0xFFFFFFFF;

        private void InvokeIntMain(IntPtr functionAddress) {

            // Execute it in the same thread
            IntMain function = Marshal.GetDelegateForFunctionPointer<IntMain>(functionAddress);
            function();

            /*
            // NOTE: We want this to be invoked in a new thread so that it gets clean TLS data
            {
                Logger.Log($"Thread starting at address 0x{functionAddress:X}", Logger.LogLevel.INFO);
                var threadId = IntPtr.Zero;
                var hThread = NativeBridge.CreateThread(IntPtr.Zero, 0, functionAddress, IntPtr.Zero, 0, ref threadId);
                Logger.Log($"Thread {threadId} created, waiting {unchecked((int)INFINITE_TIMEOUT)}");

                // TODO: MsgWaitForMultipleObjects() leads to premature return for sshd.exe, but WaitForSingleObject() / Thread.Join() leads to premature return for cmd.exe when invoked via conhost.exe
                // Probably need to peek at the message and then loop into MsgWaitFOrMultipleObjects() again as per MSDN?

                // Works for sshd.exe
                //var waitResult = NativeBridge.WaitForSingleObject(hThread, INFINITE_TIMEOUT);

                // Works for conhost.exe launching cmd.exe
                // On sshd.exe it returns 4294967295 (FAILURE) with error code 0x57 (ERROR_INVALID_PARAMETER)
                var waitResult = NativeBridge.MsgWaitForMultipleObjects(1, new IntPtr[] { hThread }, true, unchecked((int)INFINITE_TIMEOUT), QueueStatusFlags.QS_POSTMESSAGE);
                var error = NativeBridge.GetLastError();

                Logger.Log($"Thread {threadId} completed: 0x{waitResult:X}", Logger.LogLevel.INFO);

                if(waitResult == 0xFFFFFFFF) {
                    Logger.Log($"Error code: 0x{error:X}", Logger.LogLevel.ERROR);
                }
            }
            */
        }

    }
}
