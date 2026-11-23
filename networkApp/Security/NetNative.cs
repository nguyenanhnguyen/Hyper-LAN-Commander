using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace networkApp.Security
{
    public enum ArpEntryType { Other = 1, Invalid = 2, Dynamic = 3, Static = 4 }

    public sealed record ArpEntry(int InterfaceIndex, IPAddress Address, string Mac, ArpEntryType Type)
    {
        public bool IsUsable => Type is ArpEntryType.Dynamic or ArpEntryType.Static && Mac != "00-00-00-00-00-00";
    }

    public sealed record ListeningSocket(string Protocol, IPAddress Address, int Port, int Pid, string ProcessName)
    {
        /// <summary>Lắng nghe trên mọi card mạng (0.0.0.0 / ::) = ai trong mạng cũng chạm tới được.</summary>
        public bool IsExposed => !IPAddress.IsLoopback(Address);
    }

    /// <summary>
    /// Gọi thẳng IP Helper API của Windows (iphlpapi.dll) — cùng nguồn dữ liệu với `arp -a`
    /// và `netstat -ano`, nhưng không phải chạy/parse tiến trình ngoài và KHÔNG cần quyền admin.
    /// </summary>
    public static class NetNative
    {
        private const int AF_INET = 2, AF_INET6 = 23;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int TCP_TABLE_OWNER_PID_LISTENER = 3;
        private const int UDP_TABLE_OWNER_PID = 1;

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder,
                                                      int ulAf, int tableClass, int reserved);

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder,
                                                      int ulAf, int tableClass, int reserved);

        private delegate int TableFn(IntPtr buf, ref int size);

        /// <summary>Gọi một hàm "bảng" của iphlpapi theo mẫu chuẩn: hỏi kích thước → cấp phát → gọi lại.</summary>
        private static T WithTable<T>(TableFn fn, Func<IntPtr, T> parse, T empty)
        {
            int size = 0;
            int rc = fn(IntPtr.Zero, ref size);
            if (rc != ERROR_INSUFFICIENT_BUFFER && rc != 0) return empty;
            for (int attempt = 0; attempt < 4; attempt++)
            {
                size += 4096; // bảng có thể lớn lên giữa 2 lần gọi
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    rc = fn(buf, ref size);
                    if (rc == 0) return parse(buf);
                    if (rc != ERROR_INSUFFICIENT_BUFFER) return empty;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            return empty;
        }

        // ================= ARP =================

        /// <summary>Bảng ARP (IPv4 → MAC) của OS. MIB_IPNETROW = 24 byte.</summary>
        public static List<ArpEntry> GetArpTable()
        {
            return WithTable((IntPtr b, ref int s) => GetIpNetTable(b, ref s, true), buf =>
            {
                var list = new List<ArpEntry>();
                int count = Marshal.ReadInt32(buf);
                IntPtr row = buf + 4;
                var mac = new byte[8];
                for (int i = 0; i < count; i++, row += 24)
                {
                    int index = Marshal.ReadInt32(row);
                    int macLen = Math.Clamp(Marshal.ReadInt32(row + 4), 0, 8);
                    Marshal.Copy(row + 8, mac, 0, 8);
                    uint addr = (uint)Marshal.ReadInt32(row + 16);
                    int type = Marshal.ReadInt32(row + 20);
                    string macStr = macLen == 0 ? "00-00-00-00-00-00"
                        : BitConverter.ToString(mac, 0, macLen);
                    list.Add(new ArpEntry(index, new IPAddress(addr), macStr, (ArpEntryType)type));
                }
                return list;
            }, new List<ArpEntry>());
        }

        // ================= Socket đang lắng nghe + tiến trình =================

        public static List<ListeningSocket> GetListeners()
        {
            var result = new List<ListeningSocket>();
            var names = new Dictionary<int, string>();

            string Proc(int pid)
            {
                if (names.TryGetValue(pid, out var n)) return n;
                try { n = pid == 0 ? "Idle" : pid == 4 ? "System" : Process.GetProcessById(pid).ProcessName; }
                catch { n = "?"; }
                names[pid] = n;
                return n;
            }

            // TCP IPv4: MIB_TCPROW_OWNER_PID = state, localAddr, localPort, remoteAddr, remotePort, pid (6 × 4B)
            result.AddRange(WithTable((IntPtr b, ref int s) => GetExtendedTcpTable(b, ref s, true, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0),
                buf => ParseRows(buf, 24, row => new ListeningSocket("TCP",
                    new IPAddress((uint)Marshal.ReadInt32(row + 4)), Port(Marshal.ReadInt32(row + 8)),
                    Marshal.ReadInt32(row + 20), "")), new List<ListeningSocket>()));

            // TCP IPv6: MIB_TCP6ROW_OWNER_PID = localAddr[16], scope, port, remoteAddr[16], scope, port, state, pid (56B)
            result.AddRange(WithTable((IntPtr b, ref int s) => GetExtendedTcpTable(b, ref s, true, AF_INET6, TCP_TABLE_OWNER_PID_LISTENER, 0),
                buf => ParseRows(buf, 56, row => new ListeningSocket("TCP6",
                    ReadV6(row), Port(Marshal.ReadInt32(row + 20)), Marshal.ReadInt32(row + 52), "")),
                new List<ListeningSocket>()));

            // UDP IPv4: MIB_UDPROW_OWNER_PID = localAddr, localPort, pid (12B)
            result.AddRange(WithTable((IntPtr b, ref int s) => GetExtendedUdpTable(b, ref s, true, AF_INET, UDP_TABLE_OWNER_PID, 0),
                buf => ParseRows(buf, 12, row => new ListeningSocket("UDP",
                    new IPAddress((uint)Marshal.ReadInt32(row)), Port(Marshal.ReadInt32(row + 4)),
                    Marshal.ReadInt32(row + 8), "")), new List<ListeningSocket>()));

            // UDP IPv6: MIB_UDP6ROW_OWNER_PID = localAddr[16], scope, port, pid (28B)
            result.AddRange(WithTable((IntPtr b, ref int s) => GetExtendedUdpTable(b, ref s, true, AF_INET6, UDP_TABLE_OWNER_PID, 0),
                buf => ParseRows(buf, 28, row => new ListeningSocket("UDP6",
                    ReadV6(row), Port(Marshal.ReadInt32(row + 20)), Marshal.ReadInt32(row + 24), "")),
                new List<ListeningSocket>()));

            for (int i = 0; i < result.Count; i++)
                result[i] = result[i] with { ProcessName = Proc(result[i].Pid) };
            return result;
        }

        private static List<ListeningSocket> ParseRows(IntPtr buf, int rowSize, Func<IntPtr, ListeningSocket> read)
        {
            var list = new List<ListeningSocket>();
            int count = Marshal.ReadInt32(buf);
            IntPtr row = buf + 4;
            for (int i = 0; i < count; i++, row += rowSize) list.Add(read(row));
            return list;
        }

        private static IPAddress ReadV6(IntPtr p)
        {
            var b = new byte[16];
            Marshal.Copy(p, b, 0, 16);
            return new IPAddress(b);
        }

        /// <summary>Cổng nằm ở 2 byte thấp theo network byte order.</summary>
        private static int Port(int raw) => ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);
    }
}
