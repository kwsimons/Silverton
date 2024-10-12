using Silverton.Core.Interop;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data.SqlTypes;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using static Silverton.Core.Interop.NativeBridge;

namespace Silverton.Core.Managers {

    // Common functions for managing windows accounts
    public class AccountManager {

        // Add a right to the given account
        public static void AddRightToAccount(SecurityIdentifier securityIdentifier, AccountRightsConstants accountRight) {
            Console.WriteLine($"Adding account right '{accountRight}' ...");
            AddRightToAccount(securityIdentifier, accountRight.ToString());
        }

        // Add a privilege to the given account
        public static void AddPrivilegeToAccount(SecurityIdentifier securityIdentifier, AccountPrivilegeConstants privilege) {
            Console.WriteLine($"Adding account privilege '{privilege}' ...");
            AddRightToAccount(securityIdentifier, privilege.ToString());
        }

        // Add a right or privilege to the given account
        private static void AddRightToAccount(SecurityIdentifier securityIdentifier, string rightOrPrivilegeName) {

            var systemName = new LSA_UNICODE_STRING();
            var objectAttributes = new LSA_OBJECT_ATTRIBUTES();
            var status = LsaOpenPolicy(ref systemName, ref objectAttributes, POLICY_ALL_ACCESS, out var policyHandle);
            var winErrorCode = LsaNtStatusToWinError(status);
            if (winErrorCode != 0) {
                throw new Exception("LsaOpenPolicy failed", new Win32Exception((int)winErrorCode));
            }

            var sid = new byte[securityIdentifier.BinaryLength];
            securityIdentifier.GetBinaryForm(sid, 0);
            var userRights = new[] {
                new LSA_UNICODE_STRING {
                    Buffer = Marshal.StringToHGlobalUni(rightOrPrivilegeName),
                    Length = (ushort)(rightOrPrivilegeName.Length * UnicodeEncoding.CharSize),
                    MaximumLength = (ushort)((rightOrPrivilegeName.Length + 1) * UnicodeEncoding.CharSize)
                }
            };
            var pSid = Marshal.AllocHGlobal(sid.Length);

            try {
                Marshal.Copy(sid, 0, pSid, sid.Length);
                status = LsaAddAccountRights(policyHandle, pSid, userRights, userRights.Length);
                winErrorCode = LsaNtStatusToWinError(status);
                if (winErrorCode == 0x521) { // ERROR_NO_SUCH_PRIVILEGE
                    Console.WriteLine($"Right/privilege '{rightOrPrivilegeName}' does not exist");
                    return;
                } else if (winErrorCode != 0) {
                    throw new Exception($"LsaAddAccountRights failed for '{rightOrPrivilegeName}'", new Win32Exception((int)winErrorCode));
                }
            }
            finally {
                Marshal.FreeHGlobal(pSid);
                Marshal.FreeHGlobal(userRights[0].Buffer);
                LsaClose(policyHandle);
            }

            Console.WriteLine($"Added right/privilege '{rightOrPrivilegeName}' to SID {securityIdentifier}");
        }

        // Delete an account
        public static void DeleteAccount(string userName, string password) {

            int result = NetUserDel(null, userName);
            if (result == 0x8AD) {
                Console.WriteLine($"User '{userName}' does not exist");
            } else if (result != 0) {
                throw new Exception($"NetUserDel failed with error code: 0x{result:X}");
            } else {
                Console.WriteLine($"Existing user '{userName}' deleted");
            }
        }

        // Create an admin account with the given username and password
        public static void CreateAccount(string userName, string password) {

            USER_INFO_1 userInfo = new USER_INFO_1 {
                sUsername = userName,
                sPassword = password,
                uiPasswordAge = 0,
                uiPriv = 1, // USER_PRIV_USER per MSDN: When you call the NetUserAdd function, this member must be USER_PRIV_USER.
                sHome_Dir = null,
                sComment = "xboxacc",
                uiFlags = 0x0040 | 0x0200, // UF_PASSWD_CANT_CHANGE | UF_NORMAL_ACCOUNT
                sScript_Path = null
            };

            int result = NetUserAdd(null, 1, ref userInfo, out _);
            if (result == 0x8B0) {
                Console.WriteLine($"User '{userName}' already exists");
            } else if (result != 0) {
                // 0x89A = ERROR_BAD_USERNAME
                throw new Exception($"NetUserAdd failed with error code: 0x{result:X}");
            } else {
                Console.WriteLine($"User '{userName}' created");
            }
        }

        // Adds a user to a given group
        public static void AddAccountToGroup(string userName, string groupName) {

            LOCALGROUP_MEMBERS_INFO_3 membersInfo = new LOCALGROUP_MEMBERS_INFO_3 {
                lgrmi3_domainandname = Marshal.StringToCoTaskMemUni(userName)
            };

            try {
                // Add them as an admin
                int maxAttempts = 10;
                for(int i=1; i<=maxAttempts; i++) {
                var result = NetLocalGroupAddMembers(null, groupName, 3, ref membersInfo, 1);
                    if (result == 0x562) {
                        Console.WriteLine($"User '{userName}' already in the administrators group");
                        return;
                    } else if (result == 0x56B && i<maxAttempts) { // ERROR_NO_SUCH_MEMBER
                        Console.WriteLine($"User '{userName}' not found, retrying");
                        Thread.Sleep(2500);
                    } else if (result != 0) {
                        throw new Exception($"NetLocalGroupAddMembers failed with error code: 0x{result:X}");
                    } else {
                        Console.WriteLine($"User '{userName}' added to administrators group");
                        return;
                    }
                }
            } finally {
                Marshal.FreeHGlobal(membersInfo.lgrmi3_domainandname);
            }
        }

        // Creates a user profile
        public static void CreateProfile(SecurityIdentifier securityIdentifier, string userName) {
            int MAX_PATH = 260;
            StringBuilder path = new StringBuilder(MAX_PATH);
            uint pathLen = (uint)path.Capacity;
            var result = NativeBridge.CreateProfile(securityIdentifier.Value, userName, path, pathLen);
            if(result != 0) {
                throw new Exception($"Error creating profile: 0x{result:X} (0x{Marshal.GetLastWin32Error():X})");
            }
            Console.WriteLine($"Created user profile {path}");
        }

        // Deletes a user profile
        public static void DeleteProfile(SecurityIdentifier securityIdentifier) {
            if(!NativeBridge.DeleteProfileW(securityIdentifier.Value, null, null)) {
                var error = Marshal.GetLastWin32Error();
                if (error == 0x20) { // ERROR_SHARING_VIOLATION
                    throw new Exception($"Error deleting profile: Another process is holding a file open");
                } else {
                    throw new Exception($"Error deleting profile: 0x{error:X}");
                }
            }
            Console.WriteLine($"Deleted user profile");
        }

        // Retrieve the local users
        public static Dictionary<string, uint> ListLocalUsers() {
            Dictionary<string, uint> userNametoSid = new Dictionary<string, uint>();

            // Call NetUserEnum function
            IntPtr buffer;
            int entriesRead, totalEntries;
            int resumeHandle;

            int result = NetUserEnum(null, 20, FILTER_NORMAL_ACCOUNT, out buffer, -1, out entriesRead, out totalEntries, out resumeHandle);
            try {
                if (result == NERR_Success) {
                    IntPtr iter = buffer;

                    for (int i = 0; i < entriesRead; i++) {
                        USER_INFO_23 userInfo = (USER_INFO_23)Marshal.PtrToStructure(iter, typeof(USER_INFO_23));
                        userNametoSid.Add(userInfo.name, userInfo.sid);
                        iter += Marshal.SizeOf(typeof(USER_INFO_23));
                    }
                }
            }
            finally {
                // Free the memory allocated by NetUserEnum
                NetApiBufferFree(buffer);
            }

            return userNametoSid;
        }
    }
}
