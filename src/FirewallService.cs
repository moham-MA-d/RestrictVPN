using System;
using System.Collections;
using System.Collections.Generic;

namespace RestrictVpn
{
    internal enum FwAction { Block = 0, Allow = 1 }
    internal enum FwDirection { Inbound = 1, Outbound = 2 }

    internal class ProfileState
    {
        public string Name;
        public int Id;
        public bool Enabled;
        public FwAction DefaultInbound;
        public FwAction DefaultOutbound;
    }

    internal class RuleSpec
    {
        public string Name;
        public string Description;
        public FwDirection Direction = FwDirection.Outbound;
        public FwAction Action = FwAction.Allow;
        public string[] Interfaces;
        public string ApplicationName;
        public int Protocol;            // 0 = leave unset (any)
        public string LocalPorts;
        public string RemotePorts;
        public string RemoteAddresses;
        public bool Enabled = true;
    }

    internal class RuleInfo
    {
        public string Name;
        public string Description;
        public FwDirection Direction;
        public FwAction Action;
        public string[] Interfaces;
        public string ApplicationName;
    }

    /// <summary>
    /// Thin wrapper over INetFwPolicy2. Writes to the same rule store that
    /// Windows Defender Firewall and the Get-NetFirewallRule cmdlets read.
    /// </summary>
    internal class FirewallService
    {
        public const int ProfileAll = 0x7FFFFFFF;
        public const int ProtocolTcp = 6;
        public const int ProtocolUdp = 17;

        private static readonly int[] ProfileIds = new int[] { 1, 2, 4 };
        private static readonly string[] ProfileNames = new string[] { "Domain", "Private", "Public" };

        private readonly object _policy;

        public FirewallService()
        {
            _policy = Com.Create("HNetCfg.FwPolicy2");
        }

        // ------------------------------------------------------------ profiles

        public List<ProfileState> GetProfiles()
        {
            List<ProfileState> list = new List<ProfileState>();
            for (int i = 0; i < ProfileIds.Length; i++)
            {
                int id = ProfileIds[i];
                ProfileState p = new ProfileState();
                p.Id = id;
                p.Name = ProfileNames[i];
                p.Enabled = Convert.ToBoolean(Com.Get(_policy, "FirewallEnabled", id));
                p.DefaultInbound = (FwAction)Convert.ToInt32(Com.Get(_policy, "DefaultInboundAction", id));
                p.DefaultOutbound = (FwAction)Convert.ToInt32(Com.Get(_policy, "DefaultOutboundAction", id));
                list.Add(p);
            }
            return list;
        }

        public void SetProfileDefaults(int profileId, bool enabled, FwAction inbound, FwAction outbound)
        {
            Com.Set(_policy, "FirewallEnabled", profileId, enabled);
            Com.Set(_policy, "DefaultInboundAction", profileId, (int)inbound);
            Com.Set(_policy, "DefaultOutboundAction", profileId, (int)outbound);
        }

        public void SetAllProfileDefaults(bool enabled, FwAction inbound, FwAction outbound)
        {
            foreach (int id in ProfileIds)
            {
                SetProfileDefaults(id, enabled, inbound, outbound);
            }
        }

        public bool AllProfilesBlockOutbound()
        {
            foreach (ProfileState p in GetProfiles())
            {
                if (p.DefaultOutbound != FwAction.Block) return false;
            }
            return true;
        }

        // --------------------------------------------------------------- rules

        private object Rules
        {
            get { return Com.Get(_policy, "Rules"); }
        }

        public List<RuleInfo> GetRulesInGroup(string group)
        {
            List<RuleInfo> found = new List<RuleInfo>();
            IEnumerable rules = (IEnumerable)Rules;

            foreach (object rule in rules)
            {
                string grouping;
                try { grouping = Com.Get(rule, "Grouping") as string; }
                catch { continue; }   // a malformed third-party rule must not break enumeration

                if (!string.Equals(grouping, group, StringComparison.OrdinalIgnoreCase)) continue;

                RuleInfo info = new RuleInfo();
                try
                {
                    info.Name = Com.Get(rule, "Name") as string;
                    info.Description = Com.Get(rule, "Description") as string;
                    info.Direction = (FwDirection)Convert.ToInt32(Com.Get(rule, "Direction"));
                    info.Action = (FwAction)Convert.ToInt32(Com.Get(rule, "Action"));
                    info.ApplicationName = Com.Get(rule, "ApplicationName") as string;
                    info.Interfaces = ReadInterfaces(rule);
                }
                catch { }
                found.Add(info);
            }
            return found;
        }

        private static string[] ReadInterfaces(object rule)
        {
            object raw;
            try { raw = Com.Get(rule, "Interfaces"); }
            catch { return new string[0]; }

            if (raw == null) return new string[0];

            List<string> names = new List<string>();
            IEnumerable seq = raw as IEnumerable;
            if (seq != null && !(raw is string))
            {
                foreach (object o in seq)
                {
                    if (o != null) names.Add(o.ToString());
                }
            }
            else
            {
                names.Add(raw.ToString());
            }
            return names.ToArray();
        }

        public int RemoveGroup(string group)
        {
            // Snapshot the names first: removing while enumerating the live COM
            // collection invalidates the enumerator.
            List<string> names = new List<string>();
            IEnumerable rules = (IEnumerable)Rules;
            foreach (object rule in rules)
            {
                string grouping;
                string name;
                try
                {
                    grouping = Com.Get(rule, "Grouping") as string;
                    name = Com.Get(rule, "Name") as string;
                }
                catch { continue; }

                if (string.Equals(grouping, group, StringComparison.OrdinalIgnoreCase) && name != null)
                {
                    names.Add(name);
                }
            }

            int removed = 0;
            object collection = Rules;
            foreach (string name in names)
            {
                try
                {
                    Com.Call(collection, "Remove", name);
                    removed++;
                }
                catch { }
            }
            return removed;
        }

        public void AddRule(string group, RuleSpec spec)
        {
            object rule = Com.Create("HNetCfg.FWRule");

            Com.Set(rule, "Name", spec.Name);
            Com.Set(rule, "Description", spec.Description ?? "");
            Com.Set(rule, "Grouping", group);
            Com.Set(rule, "Direction", (int)spec.Direction);
            Com.Set(rule, "Action", (int)spec.Action);
            Com.Set(rule, "Profiles", ProfileAll);
            Com.Set(rule, "Enabled", spec.Enabled);

            if (!string.IsNullOrEmpty(spec.ApplicationName))
            {
                Com.Set(rule, "ApplicationName", spec.ApplicationName);
            }

            // Protocol must be assigned before any port, or the port setters fail.
            if (spec.Protocol != 0)
            {
                Com.Set(rule, "Protocol", spec.Protocol);
                if (!string.IsNullOrEmpty(spec.LocalPorts)) Com.Set(rule, "LocalPorts", spec.LocalPorts);
                if (!string.IsNullOrEmpty(spec.RemotePorts)) Com.Set(rule, "RemotePorts", spec.RemotePorts);
            }

            if (!string.IsNullOrEmpty(spec.RemoteAddresses))
            {
                Com.Set(rule, "RemoteAddresses", spec.RemoteAddresses);
            }

            if (spec.Interfaces != null && spec.Interfaces.Length > 0)
            {
                // Boxed to object so the array travels as one VARIANT argument
                // rather than being spread across the params list.
                object[] variant = new object[spec.Interfaces.Length];
                for (int i = 0; i < spec.Interfaces.Length; i++) variant[i] = spec.Interfaces[i];
                Com.Set(rule, "Interfaces", (object)variant);
            }

            Com.Call(Rules, "Add", rule);
        }
    }
}
