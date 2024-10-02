using Silverton.Core.Interop;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace Silverton.Core.Environment {

    public class Parser {

        // Parse command into an executeable path and list of arguments
        public static (string, List<string>) ParseCommand(string command, string currentWorkingDirectory) {

            var arguments = ParseArguments(command);

            if (arguments.Count == 0) {
                throw new Exception("No command passed in");
            }

            string exePath = arguments[0];
            if (!Path.IsPathRooted(exePath)) {
                exePath = Path.Combine(currentWorkingDirectory, exePath);
            }

            // Replace first argument with full path variant
            arguments[0] = exePath;

            return (exePath, arguments);
        }

        // Parse the command line arguments
        public static List<string> ParseArguments(string command) {

            int numArgs = 0;
            var pArgs = NativeBridge.CommandLineToArgvW(command, out numArgs);

            if (pArgs == IntPtr.Zero) {
                throw new Exception($"Cannot parse command '{command}'");
            }

            var args = new List<string>(numArgs);
            try {
                for (int i = 0; i < numArgs; i++) {
                    args.Add(Marshal.PtrToStringUni(Marshal.ReadIntPtr(pArgs, i * IntPtr.Size)));
                }
            }
            finally {
                Marshal.FreeHGlobal(pArgs);
            }
            return args;
        }


    }
}
