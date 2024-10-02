using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Silverton.Core.Log;
using static Silverton.Core.Interop.NativeBridge;

namespace Silverton.Core.Managers {

    // Event Log Manager
    // NOTE: Works on PC, doesn't run on Xbox: OpenEventLog() returns 0x78 (ERROR_CALL_NOT_IMPLEMENTED)
    public class EventLogManager {

        public static void DumpSecurityEvents() {

            IntPtr pEventLogHandle = OpenEventLog(null, "Security");
            if (pEventLogHandle == IntPtr.Zero) {
                throw new Exception($"OpenEventLog() errored: 0x{GetLastError():X}");
            }

            int sizeOfRecord = Marshal.SizeOf<EVENTLOGRECORD>();
            uint bytesRead = 0;
            uint minBufferNeeded = 0;
            int bufferSize = 500 * 10;
            IntPtr pBuffer = Marshal.AllocHGlobal(bufferSize);
            if (!ReadEventLog(pEventLogHandle, READ_EVENTLOG_FLAGS.EVENTLOG_SEQUENTIAL_BACKWARDS, 0, pBuffer, (uint)bufferSize, ref bytesRead, ref minBufferNeeded)) {
                throw new Exception($"ReadEventLog() errored: 0x{GetLastError():X}");
            }

            IntPtr pEvent = pBuffer;
            while (pEvent.ToInt64() - pBuffer.ToInt64() < bytesRead) {
                var Event = Marshal.PtrToStructure<EVENTLOGRECORD>(pEvent);
                Logger.Log($"------------------------------------------");
                Logger.Log($"event.EventID {Event.EventID}");
                Logger.Log($"event.EventType 0x{Event.EventType:X}");
                Logger.Log($"event.EventCategory {Event.EventCategory}");

                Logger.Log($"event.TimeGenerated {DateTimeOffset.FromUnixTimeSeconds(Event.TimeGenerated).DateTime}");
                Logger.Log($"event.TimeWritten {DateTimeOffset.FromUnixTimeSeconds(Event.TimeGenerated).DateTime}");

                IntPtr pExtraInfo = pEvent + sizeOfRecord;
                var sourceName = Marshal.PtrToStringAnsi(pExtraInfo);
                pExtraInfo += sourceName.Length + 1;
                Logger.Log($"event.SourceName {sourceName}");

                var computerName = Marshal.PtrToStringAnsi(pExtraInfo);
                pExtraInfo += computerName.Length + 1;
                Logger.Log($"event.ComputerName {computerName}");

                if (Event.UserSidLength != 0) {
                    var userSid = new SecurityIdentifier(pEvent + Event.UserSidOffset);
                    Logger.Log($"event.UserSID {userSid}");
                }
                pExtraInfo += Marshal.SizeOf<SID_IDENTIFIER_AUTHORITY>();

                IntPtr pString = pEvent + Event.StringOffset;
                string[] replacementStrings = new string[Event.NumStrings];
                for (int i = 0; i < Event.NumStrings; i++) {
                    var value = Marshal.PtrToStringAnsi(pString);
                    pString += value.Length + 1;
                    replacementStrings[i] = value;
                }

                var messageDll = FindMessageDll(sourceName, "EventMessageFile");
                Logger.Log($"event.messageDll: {messageDll}");
                messageDll = System.Environment.ExpandEnvironmentVariables(messageDll);

                var message = FetchMessage(messageDll, Event.EventID, replacementStrings);
                Logger.Log($"event.Message: {message}");

                pEvent += Event.Length;
            }
        }

        private static string FetchMessage(string msgDll, int eventId, string[] replacementStrings) {

            IntPtr msgDllHandle = LoadLibraryEx(msgDll, IntPtr.Zero, 0x00000002 | 0x00000020); // LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE
            if (msgDllHandle == IntPtr.Zero) {
                throw new Exception($"Unable to load DLL for event message: {msgDll}");
            }

            string lpMsgBuf = "";
            IntPtr[] arguments = new IntPtr[replacementStrings.Length];

            try {
                for (int i = 0; i < replacementStrings.Length; i++) {
                    arguments[i] = Marshal.StringToHGlobalAuto(replacementStrings[i]);
                }

                var flags = FormatMessageFlags.FORMAT_MESSAGE_ARGUMENT_ARRAY | FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE | FormatMessageFlags.FORMAT_MESSAGE_ALLOCATE_BUFFER;
                if (FormatMessage(flags, msgDllHandle, (uint)eventId, 0, out lpMsgBuf, 0, arguments) == 0) {
                    if (GetLastError() == 0x13D) {
                        Logger.Log($"Could not find message {eventId} in {msgDll}", Logger.LogLevel.ERROR);
                        return "Could not find message";
                    }
                    throw new Exception($"Error calling FormatMessage: 0x{GetLastError():X}");
                }
                // remove trailing whitespace (CRLF)
                return lpMsgBuf.TrimEnd(null);
            }
            finally {
                // release unmanaged memory allocated for replacement strings
                for (int i = 0; i < arguments.Length; i++) {
                    IntPtr argument = arguments[i];
                    if (argument != IntPtr.Zero)
                        Marshal.FreeHGlobal(argument);
                }
                FreeLibrary(msgDllHandle);
            }
        }
        private static IntPtr HKEY_LOCAL_MACHINE = new IntPtr(0x80000002);
        private static IntPtr HKEY_CURRENT_USER = new IntPtr(0x80000001);

        private static string FindMessageDll(string source, string valueName) {
            if (source == null || source.Length == 0)
                return null;

            IntPtr handle = IntPtr.Zero;
            try {
                handle = OpenSubKey(HKEY_LOCAL_MACHINE, @"SYSTEM\CurrentControlSet\Services\EventLog");

                string[] subKeys = GetSubKeyNames(handle);
                for (int i = 0; i < subKeys.Length; i++) {
                    IntPtr logHandle = OpenSubKey(handle, subKeys[i]);

                    string[] logSubKeys = GetSubKeyNames(logHandle);
                    for (int j = 0; j < logSubKeys.Length; j++) {
                        if (logSubKeys[j] == source) {
                            IntPtr sourceHandle = OpenSubKey(logHandle, source);
                            string value = GetValue(sourceHandle, valueName);
                            RegCloseKey(logHandle);
                            RegCloseKey(sourceHandle);
                            return value;
                        }
                    }
                }
                return null;
            }
            finally {
                RegCloseKey(handle);
            }
        }
        private static string GetValue(IntPtr handle, string keyName) {

            RegistryValueKind type = 0;
            int size = 0;
            IntPtr buffer = IntPtr.Zero;

            // Figure out the type & size
            int result = RegQueryValueEx(handle, keyName, IntPtr.Zero, ref type, buffer, ref size);
            if (result != 0) {
                // 0xEA = ERROR_MORE_DATA
                if (result != 0xEA) {
                    throw new Exception($"Error calling RegQueryValueEx: 0x{result:X} (Error Code: 0x{GetLastError():X})");
                }
            }

            // Get the data
            buffer = Marshal.AllocHGlobal(size);
            result = RegQueryValueEx(handle, keyName, IntPtr.Zero, ref type, buffer, ref size);
            if (result != 0) {
                throw new Exception($"Error calling RegQueryValueEx: 0x{result:X} (Error Code: 0x{GetLastError():X})");
            }

            string value = Marshal.PtrToStringUni(buffer).TrimEnd('\0');

            Marshal.FreeHGlobal(buffer);

            return value;
        }

        private static IntPtr OpenSubKey(IntPtr handle, string keyName) {

            int access = 0x20019; // KEY_READ
            IntPtr subKeyHandle;
            int result = RegOpenKeyEx(handle, keyName, IntPtr.Zero, access, out subKeyHandle);

            if (result != 0) {
                // 0x2 = ERROR_FILE_NOT_FOUND
                throw new Exception($"Error calling RegOpenKeyEx: 0x{result:X} (Error Code: 0x{GetLastError():X})");
            }

            return subKeyHandle;
        }

        public static string[] GetSubKeyNames(IntPtr handle) {

            StringBuilder buffer = new StringBuilder(1024);
            var keys = new List<string>();

            for (int index = 0; true; index++) {
                int result = RegEnumKey(handle, index, buffer, buffer.Capacity);

                if (result == 0) {
                    keys.Add(buffer.ToString());
                    buffer.Length = 0;
                    continue;
                }

                if (result == 0x103) { // ERROR_NO_MORE_ITEMS
                    break;
                }

                throw new Exception($"Error calling RegEnumKey: 0x{result:X} (Error Code: 0x{GetLastError():X})");
            }
            return keys.ToArray();
        }

    }
}
