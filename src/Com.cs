using System;
using System.Reflection;

namespace RestrictVpn
{
    /// <summary>
    /// Late-bound access to the Windows Firewall COM objects.
    ///
    /// We go through IDispatch reflection rather than an interop assembly so the
    /// executable has no dependency beyond the .NET Framework that ships with
    /// Windows. It also handles COM parameterized properties (such as
    /// DefaultOutboundAction[profile]) which plain casting cannot express.
    /// </summary>
    internal static class Com
    {
        public static object Create(string progId)
        {
            Type t = Type.GetTypeFromProgID(progId, false);
            if (t == null)
            {
                throw new InvalidOperationException(
                    "Windows Firewall COM component '" + progId + "' is unavailable. " +
                    "The Windows Defender Firewall service (MpsSvc) may be disabled.");
            }
            return Activator.CreateInstance(t);
        }

        public static object Get(object target, string name, params object[] args)
        {
            return target.GetType().InvokeMember(
                name, BindingFlags.GetProperty, null, target, args);
        }

        /// <summary>
        /// Sets a property. For a parameterized property the index arguments come
        /// first and the value last, matching the COM convention.
        ///
        /// Caution: when the value is itself an array it must be boxed to object
        /// by the caller, otherwise it expands into the params list.
        /// </summary>
        public static void Set(object target, string name, params object[] args)
        {
            target.GetType().InvokeMember(
                name, BindingFlags.SetProperty, null, target, args);
        }

        public static object Call(object target, string name, params object[] args)
        {
            return target.GetType().InvokeMember(
                name, BindingFlags.InvokeMethod, null, target, args);
        }
    }
}
