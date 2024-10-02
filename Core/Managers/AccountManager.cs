using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Silverton.Core.Log;
using static Silverton.Core.Interop.NativeBridge;

namespace Silverton.Core.Managers {

    // Common functions for managing windows accounts
    public class AccountManager {

        // Add a right to the given account
        public static void AddRightToAccount(SecurityIdentifier securityIdentifier, AccountRightsConstants accountRight) {
            AddRightToAccount(securityIdentifier, accountRight.ToString());
        }

        // Add a privilege to the given account
        public static void AddPrivilegeToAccount(SecurityIdentifier securityIdentifier, AccountPrivilegeConstants privilege) {
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
                if (winErrorCode != 0) {
                    throw new Exception($"LsaAddAccountRights failed for '{rightOrPrivilegeName}'", new Win32Exception((int)winErrorCode));
                }
            }
            finally {
                Marshal.FreeHGlobal(pSid);
                Marshal.FreeHGlobal(userRights[0].Buffer);
                LsaClose(policyHandle);
            }

            Logger.Log($"Added right/privilege '{rightOrPrivilegeName}' to SID {securityIdentifier}", Logger.LogLevel.DEBUG);
        }

        // Create an admin account with the given username and password
        public static void CreateAccount(string userName, string password) {

            USER_INFO_1 userInfo = new USER_INFO_1 {
                sUsername = userName,
                sPassword = password,
                uiPasswordAge = 0,
                uiPriv = 1, // USER_PRIV_ADMIN (Administrator)
                sHome_Dir = null,
                sComment = "xboxacc",
                uiFlags = 0x0040 | 0x0200, // UF_PASSWD_CANT_CHANGE | UF_NORMAL_ACCOUNT
                sScript_Path = null
            };

            int result = NetUserDel(null, userName);
            if (result == 0x8AD) {
                Logger.Log($"User '{userName}' does not exist", Logger.LogLevel.DEBUG);
            }
            else if (result != 0) {
                throw new Exception($"NetUserDel failed with error code: 0x{result:X}");
            }
            else {
                Logger.Log($"Existing user '{userName}' deleted", Logger.LogLevel.DEBUG);
            }

            result = NetUserAdd(null, 1, ref userInfo, out _);
            if (result == 0x8B0) {
                Logger.Log($"User '{userName}' already exists", Logger.LogLevel.DEBUG);
            }
            else if (result != 0) {
                // 0x89A = ERROR_BAD_USERNAME
                throw new Exception($"NetUserAdd failed with error code: 0x{result:X}");
            }
            else {
                Logger.Log($"User '{userName}' created", Logger.LogLevel.DEBUG);
            }
        }

        // Adds a user to a given group
        public static void AddAccountToGroup(string userName, string groupName) {

            LOCALGROUP_MEMBERS_INFO_3 membersInfo = new LOCALGROUP_MEMBERS_INFO_3 {
                lgrmi3_domainandname = Marshal.StringToCoTaskMemUni(userName)
            };

            try {
                // Add them as an admin
                var result = NetLocalGroupAddMembers(null, groupName, 3, ref membersInfo, 1);
                if (result == 0x562) {
                    Logger.Log($"User '{userName}' already in the administrators group", Logger.LogLevel.DEBUG);
                }
                else if (result != 0) {
                    throw new Exception($"NetLocalGroupAddMembers failed with error code: 0x{result:X}");
                }
                else {
                    Logger.Log($"User '{userName}' added to administrators group", Logger.LogLevel.DEBUG);
                }
            }
            finally {
                Marshal.FreeHGlobal(membersInfo.lgrmi3_domainandname);
            }
        }

        // Retrieve the local users
        public static List<string> ListLocalUsers() {
            List<string> localUsers = new List<string>();

            // Call NetUserEnum function
            IntPtr buffer;
            int entriesRead, totalEntries;
            int resumeHandle;

            int result = NetUserEnum(null, 0, FILTER_NORMAL_ACCOUNT, out buffer, -1, out entriesRead, out totalEntries, out resumeHandle);
            try {
                if (result == NERR_Success) {
                    // Get the array of USER_INFO_0 structures
                    USER_INFO_0[] userInfos = new USER_INFO_0[entriesRead];
                    IntPtr iter = buffer;

                    for (int i = 0; i < entriesRead; i++) {
                        userInfos[i] = (USER_INFO_0)Marshal.PtrToStructure(iter, typeof(USER_INFO_0));
                        iter += Marshal.SizeOf(typeof(USER_INFO_0));
                    }

                    // Add the usernames to the list
                    foreach (USER_INFO_0 userInfo in userInfos) {
                        localUsers.Add(userInfo.name);
                    }
                }
            }
            finally {
                // Free the memory allocated by NetUserEnum
                NetApiBufferFree(buffer);
            }

            return localUsers;
        }
    }
}
