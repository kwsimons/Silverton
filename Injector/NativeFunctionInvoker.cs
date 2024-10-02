using Silverton.Injector.Patchers;
using System;

// TODO:
// [ ] Patch GetModuleHandle(null)
namespace Silverton.Injector {

    // Responsible for allowing the invocation of native (injected) functions by applying necessary patches before invocation and restoring patches after completion.
    public class NativeFunctionInvoker {

        private IntPtr exePeAddress;
        private string fullExePath;
        private string[] arguments;

        public NativeFunctionInvoker(IntPtr exePeAddress, string fullExePath, string[] arguments) {
            this.exePeAddress = exePeAddress;
            this.fullExePath = fullExePath;
            this.arguments = arguments;
        }

        // Invoke the given native function, first applying necessary patches in order to trick native function into thinking it was executed normally
        public void Invoke(Action functionInvoker) {
            using (new PEBImageBaseAddressPatcher(exePeAddress.ToInt64()))
            using (new LdrpImageEntryFullDllNamePatcher(fullExePath))
            using (new ArgumentPatcher(fullExePath, arguments)) {
                functionInvoker();
            }
        }

    }
}
