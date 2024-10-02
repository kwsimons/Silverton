using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using Silverton.Core.Log;
using static Silverton.Core.Interop.NativeBridge;

namespace Silverton.Core.Managers {

    // Manage file settings
    public class FileManager {

        public static void RestrictFileAccess(string path, string username) {

            // We need SeRestorePrivilege in order to change file permissions
            TokenManager.GrantProcessTokenPrivilege(AccountPrivilegeConstants.SeRestorePrivilege);

            FileInfo fileInfo = new FileInfo(path);
            NTAccount owner = new NTAccount(username);
            FileSecurity fSecurity;

            Logger.Log($"New Owners Sid = {(SecurityIdentifier)owner.Translate(typeof(SecurityIdentifier))}", Logger.LogLevel.TRACE);

            fSecurity = fileInfo.GetAccessControl();
            Logger.Log($"Adding owner as user '{username}'", Logger.LogLevel.DEBUG);
            fSecurity.SetOwner(owner);
            fileInfo.SetAccessControl(fSecurity);
            Logger.Log($"Updated ownership", Logger.LogLevel.DEBUG);

            Logger.Log($"-----------------", Logger.LogLevel.TRACE);
            Logger.Log($"ACL for {fileInfo.FullName}", Logger.LogLevel.TRACE);
            fSecurity = fileInfo.GetAccessControl();
            Logger.Log($"Owner: {fSecurity.GetOwner(typeof(NTAccount)).Value}", Logger.LogLevel.TRACE);
            Logger.Log($"Group: {fSecurity.GetGroup(typeof(NTAccount)).Value}", Logger.LogLevel.TRACE);

            foreach (FileSystemAccessRule accessRule in fSecurity.GetAccessRules(true, true, typeof(NTAccount))) {
                Logger.Log($"----------------------------------", Logger.LogLevel.TRACE);
                Logger.Log($"AccessControlType: {accessRule.AccessControlType}", Logger.LogLevel.TRACE);
                Logger.Log($"FileSystemRights: {accessRule.FileSystemRights}", Logger.LogLevel.TRACE);
                Logger.Log($"IdentityReference: {accessRule.IdentityReference.Value}", Logger.LogLevel.TRACE);

                if (accessRule.IdentityReference.Value.ToLower() != username.ToLower()) { // && accessRule.IdentityReference.Value.ToLower() != @"XboxOne\Administrators".ToLower()) {
                    Logger.Log($"Removing access", Logger.LogLevel.TRACE);
                    fSecurity.PurgeAccessRules(accessRule.IdentityReference);
                }
            }

            // Do not allow inherited access
            Logger.Log($"Removing all other access", Logger.LogLevel.DEBUG);
            fSecurity.SetAccessRuleProtection(true, false);
            fileInfo.SetAccessControl(fSecurity);
            Logger.Log($"Purged other access", Logger.LogLevel.DEBUG);

            // Add the FileSystemAccessRule to the security settings.
            fSecurity = fileInfo.GetAccessControl();
            Logger.Log($"Adding full control for user '{username}'", Logger.LogLevel.DEBUG);
            fSecurity.AddAccessRule(new FileSystemAccessRule(username, FileSystemRights.FullControl, AccessControlType.Allow));
            fileInfo.SetAccessControl(fSecurity);
            Logger.Log($"Added full control", Logger.LogLevel.DEBUG);

            Logger.Log($"-----------------", Logger.LogLevel.TRACE);

            Logger.Log($"ACL for {fileInfo.FullName}", Logger.LogLevel.TRACE);
            fSecurity = fileInfo.GetAccessControl();
            foreach (FileSystemAccessRule accessRule in fSecurity.GetAccessRules(true, true, typeof(NTAccount))) {
                Logger.Log($"----------------------------------", Logger.LogLevel.TRACE);
                Logger.Log($"AccessControlType: {accessRule.AccessControlType}", Logger.LogLevel.TRACE);
                Logger.Log($"FileSystemRights: {accessRule.FileSystemRights}", Logger.LogLevel.TRACE);
                Logger.Log($"IdentityReference: {accessRule.IdentityReference.Value}", Logger.LogLevel.TRACE);
            }

            Logger.Log($"-----------------", Logger.LogLevel.TRACE);

            Logger.Log($"Ownership & full control set to user '{username}' for file {path}");
        }
    }
}
