using Silverton.Core.Interop;
using Silverton.Core.Log;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace Silverton.Core.Environment {

    public class Parser {

        // Parse command into an executeable path and list of arguments
        public static (string, string) ParseCommand(string command, string currentWorkingDirectory) {

            var arguments = ParseArguments(command);

            if (arguments.Count == 0) {
                throw new Exception("No command passed in");
            }

            string exePath = arguments[0];
            if (!Path.IsPathRooted(exePath)) {
                exePath = Path.Combine(currentWorkingDirectory, exePath);

                // Replace the relative path with the absolute path
                // The name of the executable in the command line that the operating system provides to a process is not necessarily identical to that in the command line that the calling process gives to the CreateProcess function.
                // The operating system may prepend a fully qualified path to an executable name that is provided without a fully qualified path.
                // https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinew#remarks
                var oldExePath = arguments[0];
                var offset = command.IndexOf(oldExePath);
                command = command.Remove(offset, oldExePath.Length).Insert(offset, exePath);
            }

            return (exePath, command);
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
            } finally {
                Marshal.FreeHGlobal(pArgs);
            }

            return args;
        }


    }
}
