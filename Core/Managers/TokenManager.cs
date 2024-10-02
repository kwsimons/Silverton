using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Silverton.Core.Log;
using static Silverton.Core.Interop.NativeBridge;

namespace Silverton.Core.Managers {

    // Common functions for managing process & thread tokens
    public class TokenManager {

        // Grant privileges to the current threads token
        public static void GrantThreadTokenPrivilege(AccountPrivilegeConstants privilege) {
            GrantThreadTokenPrivilege(privilege, GetCurrentThread());
        }

        // Grant privileges to the given thread handle
        public static void GrantThreadTokenPrivilege(AccountPrivilegeConstants privilege, IntPtr threadHandle) {

            // Open the thread token with privileges that allow for privilege modification
            IntPtr tokenHandle = IntPtr.Zero;
            if (!OpenThreadToken(threadHandle, TokenPrivileges.TOKEN_ADJUST_PRIVILEGES | TokenPrivileges.TOKEN_READ, false, out tokenHandle)) {
                // 0x3F0 = ERROR_NO_TOKEN
                if (GetLastError() == 0x3F0) {
                    throw new Exception($"Thread does not have it's own token, skipping token grant", new Win32Exception((int)GetLastError()));
                }
                throw new Exception($"Error during OpenThreadToken: 0x{GetLastError():x}", new Win32Exception((int)GetLastError()));
            }
            if (tokenHandle == IntPtr.Zero) {
                throw new Exception($"Process token is null: 0x{GetLastError():x}", new Win32Exception((int)GetLastError()));
            }

            GrantPrivilege(tokenHandle, privilege);
        }

        // Grant privileges to the current processes token
        public static void GrantProcessTokenPrivilege(AccountPrivilegeConstants privilege) {
            GrantProcessTokenPrivilege(privilege, GetCurrentProcess());
        }

        // Grant privileges to the given process handle
        public static void GrantProcessTokenPrivilege(AccountPrivilegeConstants privilege, IntPtr processHandle) {
            IntPtr tokenHandle = GetProcessToken(processHandle);
            GrantPrivilege(tokenHandle, privilege);
        }

        // Retrieve the process token for the given process handle
        private static IntPtr GetProcessToken(IntPtr processHandle) {

            // Open the process token with privileges that allow for privilege modification
            IntPtr tokenHandle;
            if (!OpenProcessToken(processHandle, TokenPrivileges.TOKEN_ADJUST_PRIVILEGES | TokenPrivileges.TOKEN_READ, out tokenHandle)) {
                throw new Exception($"Error during OpenProcessToken: 0x{GetLastError():x}", new Win32Exception((int)GetLastError()));
            }
            if (tokenHandle == IntPtr.Zero) {
                throw new Exception($"Process token is null: 0x{GetLastError():x}", new Win32Exception((int)GetLastError()));
            }

            return tokenHandle;
        }

        // Retrieve the current processes token
        private static IntPtr GetProcessToken() {
            return GetProcessToken(GetCurrentProcess());
        }

        // Grant the given privilege to the given toke handle
        private static void GrantPrivilege(IntPtr tokenHandle, AccountPrivilegeConstants privilege) {
            string privilegeName = privilege.ToString();

            // Retrieve the LUID for the given privilege
            LUID targetLuid = new LUID { };
            if (!LookupPrivilegeValue(null, privilegeName, ref targetLuid)) {
                // 0x6BA = RPC_S_SERVER_UNAVAILABLE
                throw new Exception($"Error during LookupPrivilegeValue: 0x{GetLastError():x}", new Win32Exception((int)GetLastError()));
            }

            // Craft our update token privilege request
            UPDATE_TOKEN_PRIVILEGES tokenPrivileges = new UPDATE_TOKEN_PRIVILEGES {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES[] {
                    new LUID_AND_ATTRIBUTES {
                        Luid = targetLuid,
                        Attributes = LUID_AND_ATTRIBUTES.SE_PRIVILEGE_ENABLED // The function enables the privilege.
                    }
                }
            };

            // Adjust the token privileges
            if (!AdjustTokenPrivileges(tokenHandle, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero)) {
                // 0x514 = ERROR_NOT_ALL_ASSIGNED
                throw new Exception($"AdjustTokenPrivileges failed: 0x{GetLastError():X}", new Win32Exception((int)GetLastError()));
            }

            // Verify that the token privileges took hold
            if (!IsPrivilegeEnabled(tokenHandle, targetLuid)) {
                throw new Win32Exception((int)GetLastError(), $"'{privilegeName}' is NOT enabled!");
            }
            else {
                Logger.Log($"Enabled privilege {privilegeName} (LUID: 0x{targetLuid.ToInt64():X})", Logger.LogLevel.DEBUG);
            }
        }

        // Check if the given token handle has the privilege enabled
        private static bool IsPrivilegeEnabled(IntPtr tokenHandle, LUID privilegeLuid) {

            PRIVILEGE_SET privilegeSet = new PRIVILEGE_SET {
                Control = PRIVILEGE_SET.PRIVILEGE_SET_ALL_NECESSARY,
                PrivilegeCount = 1,
                Privilege = new LUID_AND_ATTRIBUTES[] {
                    new LUID_AND_ATTRIBUTES {
                        Luid = privilegeLuid,
                        Attributes = LUID_AND_ATTRIBUTES.SE_PRIVILEGE_ENABLED
                    }
                },
            };

            bool isPrivilegeEnabled;
            if (!PrivilegeCheck(tokenHandle, ref privilegeSet, out isPrivilegeEnabled)) {
                throw new Exception($"PrivilegeCheck failed: 0x{GetLastError():X}", new Win32Exception((int)GetLastError()));
            }

            return isPrivilegeEnabled;
        }

        // Retrieve token privilege information for a given token handle
        private static TOKEN_PRIVILEGES GetTokenPrivileges(IntPtr tokenHandle) {

            // The size is variable, we must call it first to determine how much memory to alloc
            // NOTE: The call will fail and return ERROR_INSUFFICIENT_BUFFER, this is expected
            GetTokenInformation(tokenHandle, (uint)TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, out uint structSize);

            // Now that we know the size, we can make the call again
            IntPtr pTokenPrivileges = Marshal.AllocHGlobal((int)structSize);
            try {
                if (!GetTokenInformation(tokenHandle, (uint)TOKEN_INFORMATION_CLASS.TokenPrivileges, pTokenPrivileges, structSize, out structSize)) {
                    throw new Exception($"Error during GetTokenPrivileges: 0x{GetLastError():x}", new Win32Exception((int)GetLastError()));
                }

                TOKEN_PRIVILEGES tokenPrivileges = Marshal.PtrToStructure<TOKEN_PRIVILEGES>(pTokenPrivileges);
                return tokenPrivileges;
            }
            finally {
                Marshal.FreeHGlobal(pTokenPrivileges);
            }
        }

        // Print the current process token permissions to the logger
        public static void PrintProcessTokenPermissions() {
            PrintTokenPrivileges(GetProcessToken());
        }

        // Print the given tokens permissions to the logger
        private static TOKEN_PRIVILEGES PrintTokenPrivileges(IntPtr tokenHandle) {

            var tokenPrivileges = GetTokenPrivileges(tokenHandle);

            for (int i = 0; i < tokenPrivileges.PrivilegeCount; i++) {
                LUID_AND_ATTRIBUTES privilege = tokenPrivileges.Privileges[i];
                bool enabled = (privilege.Attributes & LUID_AND_ATTRIBUTES.SE_PRIVILEGE_ENABLED) > 0;

                // NOTE: The call will fail and return ERROR_INSUFFICIENT_BUFFER, this is expected
                int size = 0;
                LookupPrivilegeName(null, ref privilege.Luid, null, ref size);
                StringBuilder lpName = new StringBuilder(size);

                if (!LookupPrivilegeName(null, ref privilege.Luid, lpName, ref size)) {
                    throw new Exception($"Error during LookupPrivilegeName: 0x{GetLastError():x}", new Win32Exception((int)GetLastError()));
                }

                Logger.Log($"Token LUID '{lpName}' (Enabled: {enabled} UID: 0x{privilege.Luid.ToInt64():X})", Logger.LogLevel.DEBUG);
            }

            return tokenPrivileges;
        }
    }
}
