using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Silverton.Core.Log;
using static Silverton.Core.Interop.NativeBridge;

namespace Silverton.Core.Managers {

    // Manage Windows Firewall settings
    // Based on https://github.com/exploits-forsale/solstice/blob/main/crates/solstice_daemon/src/firewall.rs
    public class FirewallManager {

        private static Guid FWPM_PROVIDER_GUID = new Guid(0xabad1dea, 0x4141, 0x4141, 0x0, 0x0, 0x0c, 0x0f, 0xfe, 0xe0, 0x00, 0x00);

        public static void DisableFirewalls() {
            Logger.Log($"Disabling the firewall", Logger.LogLevel.DEBUG);

            uint result = CoInitializeEx(IntPtr.Zero, COINIT.COINIT_MULTITHREADED);
            if (result != 0 && result != 1) { // 0 = S_OK, 1 = S_FALSE
                throw new Exception($"CoInitializeEx returned a non-zero result: 0x{result:X} (Error: 0x{GetLastError():X})", new Win32Exception((int)GetLastError()));
            }

            Guid CLSID_HNetCfgFwPolicy2 = new Guid("e2b3c97f-6ae1-41ac-817a-f6f92166d7dd");
            Guid CLSID_INetFwPolicy2 = new Guid("98325047-C671-4174-8D81-DEFCD3F03186");
            IntPtr pINetFwPolicy2 = IntPtr.Zero;
            result = CoCreateInstance(CLSID_HNetCfgFwPolicy2, IntPtr.Zero, CLSCTX.ALL, CLSID_INetFwPolicy2, out pINetFwPolicy2);
            if (result != 0) {
                // 0x80040110 = CLASS_E_NOAGGREGATION
                // 0x80040154 = REGDB_E_CLASSNOTREG
                throw new Exception($"CoCreateInstance returned a non-zero result: 0x{result:X} (Error: 0x{GetLastError():X})", new Win32Exception((int)GetLastError()));
            }
            if (pINetFwPolicy2 == IntPtr.Zero) {
                throw new Exception($"pINetFwPolicy2 is null (Error: 0x{GetLastError():X})", new Win32Exception((int)GetLastError()));
            }
            INetFwPolicy2 iNetFwPolicy2 = (INetFwPolicy2)Marshal.GetObjectForIUnknown(pINetFwPolicy2);

            foreach (NetFwProfileType2 profileType in new NetFwProfileType2[] { NetFwProfileType2.Public, NetFwProfileType2.Private, NetFwProfileType2.Domain }) {
                Logger.Log($"Profile Type: {profileType}", Logger.LogLevel.TRACE);
                try {
                    Logger.Log($"\tFirewallEnabled: {iNetFwPolicy2.get_FirewallEnabled(profileType)}", Logger.LogLevel.TRACE);
                    Logger.Log($"\tBlockAllInboundTraffic: {iNetFwPolicy2.get_BlockAllInboundTraffic(profileType)}", Logger.LogLevel.TRACE);
                    Logger.Log($"\tDefaultInboundAction: {iNetFwPolicy2.get_DefaultInboundAction(profileType)}", Logger.LogLevel.TRACE);
                    Logger.Log($"\tNotificationsDisabled: {iNetFwPolicy2.get_NotificationsDisabled(profileType)}", Logger.LogLevel.TRACE);
                }
                catch (Exception e) {
                    Logger.Log($"{e.Message}", Logger.LogLevel.ERROR);
                }
            }
            Logger.Log($"Updating profiles", Logger.LogLevel.TRACE);

            foreach (NetFwProfileType2 profileType in new NetFwProfileType2[] { NetFwProfileType2.Public, NetFwProfileType2.Private, NetFwProfileType2.Domain }) {
                Logger.Log($"Modifying profile Type: {profileType}", Logger.LogLevel.TRACE);
                iNetFwPolicy2.set_BlockAllInboundTraffic(profileType, false);
                iNetFwPolicy2.set_FirewallEnabled(profileType, false);
                iNetFwPolicy2.set_DefaultInboundAction(profileType, NetFwAction.Allow);
                iNetFwPolicy2.set_NotificationsDisabled(profileType, true);
            }

            Logger.Log($"Verifying profiles", Logger.LogLevel.TRACE);
            foreach (NetFwProfileType2 profileType in new NetFwProfileType2[] { NetFwProfileType2.Public, NetFwProfileType2.Private, NetFwProfileType2.Domain }) {
                Logger.Log($"Profile Type: {profileType}", Logger.LogLevel.TRACE);
                try {
                    Logger.Log($"\tFirewallEnabled: {iNetFwPolicy2.get_FirewallEnabled(profileType)}", Logger.LogLevel.TRACE);
                    Logger.Log($"\tBlockAllInboundTraffic: {iNetFwPolicy2.get_BlockAllInboundTraffic(profileType)}", Logger.LogLevel.TRACE);
                    Logger.Log($"\tDefaultInboundAction: {iNetFwPolicy2.get_DefaultInboundAction(profileType)}", Logger.LogLevel.TRACE);
                    Logger.Log($"\tNotificationsDisabled: {iNetFwPolicy2.get_NotificationsDisabled(profileType)}", Logger.LogLevel.TRACE);
                }
                catch (Exception e) {
                    Logger.Log($"{e.Message}", Logger.LogLevel.ERROR);
                }
            }

            Logger.Log($"Disabled the firewall", Logger.LogLevel.DEBUG);
        }

        // Opens up a port through the firewall
        public static void AllowPortThroughFirewall(string name, ushort port) {
            Logger.Log($"Opening up port {port} ({name}) in the firewall", Logger.LogLevel.DEBUG);

            var engine = OpenFWPSession();
            try {
                InstallFWPMProvider(engine);
                BuildAndAddFWPPortFilter(name, port, FirewallLayerGuids.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, engine);
            }
            finally {
                CloseFWPSession(engine);
            }

            Logger.Log($"Opened up port {port} ({name}) in the firewall", Logger.LogLevel.DEBUG);
        }

        private static IntPtr OpenFWPSession() {
            IntPtr sessionHandle = IntPtr.Zero;
            var result = FwpmEngineOpen0(IntPtr.Zero, (uint)RPC_C_AUTHN_DEFAULT, IntPtr.Zero, IntPtr.Zero, ref sessionHandle);
            if (result != 0) {
                throw new Exception($"FwpmEngineOpen0 returned a non-zero result: 0x{result:X} (Error: 0x{GetLastError():X})", new Win32Exception((int)GetLastError()));
            }
            Logger.Log($"Opened FWPM Engine: 0x{sessionHandle:X}", Logger.LogLevel.TRACE);

            return sessionHandle;
        }

        private static void CloseFWPSession(IntPtr sessionHandle) {
            var result = FwpmEngineClose0(sessionHandle);
            if (result != 0) {
                throw new Exception($"FwpmEngineClose0 returned a non-zero result: 0x{result:X} (Error: 0x{GetLastError():X})", new Win32Exception((int)GetLastError()));
            }
            Logger.Log($"Closed FWPM Engine: 0x{sessionHandle:X}", Logger.LogLevel.TRACE);
        }

        private static void InstallFWPMProvider(IntPtr sessionHandle) {

            var provider = new FWPM_PROVIDER0 {
                providerKey = FWPM_PROVIDER_GUID,
                displayData = new FWPM_DISPLAY_DATA0 {
                    name = "Silverton",
                    description = "Silverton FWPM Provider",
                },
                flags = FirewallProviderFlags.Persistent,
            };

            uint result = FwpmTransactionBegin0(sessionHandle, 0);
            if (result != 0) {
                throw new Exception($"FwpmTransactionBegin0 returned a non-zero result: 0x{result:X} (Error: 0x{GetLastError():X})", new Win32Exception((int)GetLastError()));
            }

            result = FwpmProviderAdd0(sessionHandle, ref provider, IntPtr.Zero);
            if (result == FWP_E_ALREADY_EXISTS) {
                Logger.Log($"FwpmProviderAdd0 already exists: FWP_E_ALREADY_EXISTS", Logger.LogLevel.TRACE);
            }
            else if (result != 0) {
                throw new Exception($"FwpmProviderAdd0 returned a non-zero result: 0x{result:X} (Error: 0x{GetLastError():X})", new Win32Exception((int)GetLastError()));
            }

            result = FwpmTransactionCommit0(sessionHandle); // 0x8032000D = FWP_E_NO_TXN_IN_PROGRESS
            if (result != 0) {
                throw new Exception($"FwpmTransactionCommit0 returned a non-zero result: 0x{result:X} (Error: 0x{GetLastError():X})", new Win32Exception((int)GetLastError()));
            }

            Logger.Log($"Added FWPM Provider", Logger.LogLevel.TRACE);
        }

        private static void BuildAndAddFWPPortFilter(string name, ushort port, Guid layer, IntPtr sessionHandle) {

            IntPtr pProviderKey = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
            IntPtr pConditionArray = IntPtr.Zero;
            try {
                Marshal.StructureToPtr(FWPM_PROVIDER_GUID, pProviderKey, false);

                FWPM_FILTER0 filter = new FWPM_FILTER0 {
                    providerKey = pProviderKey,
                    displayData = new FWPM_DISPLAY_DATA0 {
                        name = $"Silverton: {name}",
                        description = $"Open port {port} for '{name}'",
                    },
                    layerKey = layer,
                    //flags = FirewallFilterFlags.Persistent,
                };
                filter.action.type = FirewallActionType.Permit;

                var conditions = new FWPM_FILTER_CONDITION0[] {
                    new FWPM_FILTER_CONDITION0 {
                        fieldKey = FirewallLayerGuids.FWPM_CONDITION_IP_LOCAL_PORT,
                        matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                        conditionValue = new FWP_CONDITION_VALUE0 { // FWP_VALUE0
                            type = FWP_DATA_TYPE.FWP_UINT16,
                            anonymous = new FWP_CONDITION_VALUE0_UNION { uint16 = port },
                        },
                    },
                };

                pConditionArray = Marshal.AllocHGlobal(conditions.Length * Marshal.SizeOf<FWPM_FILTER_CONDITION0>());
                for (int i = 0; i < conditions.Length; i++) {
                    Marshal.StructureToPtr(conditions[i], pConditionArray + i * Marshal.SizeOf<FWPM_FILTER_CONDITION0>(), false);
                }
                filter.filterCondition = pConditionArray;
                filter.numFilterConditions = conditions.Length;

                IntPtr FilterId = IntPtr.Zero;
                uint result = FwpmFilterAdd0(sessionHandle, ref filter, IntPtr.Zero, ref FilterId);
                if (result != 0) {
                    throw new Exception($"FwpmFilterAdd0 returned a non-zero result: 0x{result:X} (Error: 0x{GetLastError():X})", new Win32Exception((int)GetLastError()));
                }
                Logger.Log($"Created Filter Id 0x{FilterId:X}", Logger.LogLevel.TRACE);

            }
            finally {
                Marshal.FreeHGlobal(pProviderKey);
                if (pConditionArray != IntPtr.Zero) {
                    Marshal.FreeHGlobal(pConditionArray);
                }
            }
        }

    }
}
