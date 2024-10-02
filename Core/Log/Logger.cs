using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using Silverton.Core.Interop;

namespace Silverton.Core.Log {

    // Logger that allows log-level specificity & writing to parent process pipes
    internal class Logger {

        internal enum LogLevel : ushort {
            FATAL = 0,
            ERROR = 1,
            WARN = 2,
            INFO = 3,
            DEBUG = 4,
            TRACE = 5,
        }

        private static LogLevel maxLogLevelGranularity = LogLevel.INFO;
        private static TextWriter stdOut = Console.Out;
        private static TextWriter stdErr = Console.Error;

        // Specify the max logging specificity
        internal static void SetLogLevel(int logLevel) {
            maxLogLevelGranularity = (LogLevel) logLevel;
        }

        // Retrieve the max logging specificity
        internal static ushort GetLogLevel() {
            return (ushort)maxLogLevelGranularity;
        }

        // Override the loggers standard writer with the given pipe handle and the process that owns it
        internal static void SetStdOut(Int32 ParentProcessId, Int32 StdOut) {
            if(ParentProcessId != 0) {
                IntPtr pipe = IntPtr.Zero;
                CopyPipeFromParent(ParentProcessId, new IntPtr(StdOut), out pipe);
                stdOut = new StreamWriter(new AnonymousPipeClientStream(PipeDirection.Out, pipe.ToString()));
            }
        }

        // Override the loggers error writer with the given pipe handle and the process that owns it
        internal static void SetStdError(Int32 ParentProcessId, Int32 StdError) {
            if (ParentProcessId != 0) {
                IntPtr pipe = IntPtr.Zero;
                CopyPipeFromParent(ParentProcessId, new IntPtr(StdError), out pipe);
                stdErr = new StreamWriter(new AnonymousPipeClientStream(PipeDirection.Out, pipe.ToString()));
            }
        }

        // Write to the logger at the given log level
        internal static void Log(string message, LogLevel level = LogLevel.INFO) {
            // Don't log if it is more granular than our max logging granularity
            if (level > maxLogLevelGranularity) {
                return;
            }

            var writer = stdOut;
            if (level <= LogLevel.ERROR) {
                writer = stdErr;
            }

            writer.WriteLine($"[{level.ToString().PadLeft(5)}] {message}");

            // Immediately flush so that hard-crashes don't lose logs in the buffer
            writer.Flush();
        }

        internal static void Flush() {
            stdOut.Flush();
            stdErr.Flush();
        }

        // Copy the given pipe handle from the parent process so that we can write to it
        private static void CopyPipeFromParent(Int32 parentProcessId, IntPtr parentHandle, out IntPtr childHandle) {
            IntPtr currentProcHandle = NativeBridge.GetCurrentProcess();
            IntPtr parentProcHandle = Process.GetProcessById(parentProcessId).Handle;
            if (!NativeBridge.DuplicateHandle(parentProcHandle,
                                                    parentHandle,
                                                    currentProcHandle,
                                                    out childHandle,
                                                    0,
                                                    false,
                                                    NativeBridge.DuplicateHandleOptions.DUPLICATE_SAME_ACCESS)) {
                throw new Win32Exception((int) NativeBridge.GetLastError(), "Error copying pipe handle from parent process");
            }
        }

    }

}
