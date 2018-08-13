using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;

namespace LongLinkIOS
{
    class MyFuckSSL
    {
        [DllImport("ecdh.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int DoEcdh(int nid, byte[] szServerPubKey, int nLenServerPub, byte[] szLocalPriKey, int nLenLocalPri, byte[] szShareKey, ref int pLenShareKey);
        public static byte[] SharkEcdhKey(byte[] serverEcdhPubKey, byte[] pri_key)
        {
            byte[] pShareKey = new byte[2024];
            int ShekeLen = 0;
            DoEcdh(713, serverEcdhPubKey, serverEcdhPubKey.Length, pri_key, pri_key.Length, pShareKey, ref ShekeLen);

            return pShareKey.Skip(0).Take(ShekeLen).ToArray();
        }
        [DllImport("ecdh.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool GenEcdh(int nid, byte[] pri, ref int priLen, byte[] pub, ref int pubLen);
        public static bool GenEcdh__(ref byte[]EcdhPubKey,ref byte[] prikey)
        {
            EcdhPubKey = new byte[2024];
            prikey = new byte[2024];
            int PriLen = 0;
            int PubLen = 0;
            bool iRet = GenEcdh(713, prikey,ref PriLen, EcdhPubKey,ref PubLen);
            return iRet;

        }
        [DllImport("CytpoBYDaya.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern void WxAesDecodeComprese(byte[] pack, int inLen, byte[] key,out IntPtr pushStr,int outLen);
        public static byte[] AesDecodeComprese(byte[] pack, int inLen, byte[] key,int OutLen, IntPtr pushStr)
        {
            
            WxAesDecodeComprese(pack, inLen, key, out pushStr,OutLen);
            byte[] strbuf = new byte[OutLen];
            Marshal.Copy(pushStr, strbuf, 0, OutLen);
            WxRelease(pushStr);
            return strbuf;

        }
        [DllImport("CytpoBYDaya.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern void WxAesEncodeComprese(byte[] pack, int inLen, byte[] key, out IntPtr pushStr, ref int outLen);
        public static byte[] AesEncodeComprese(byte[] pack, int inLen, byte[] key,IntPtr pushStr)
        {
            int outLen = 0;
            WxAesEncodeComprese(pack, inLen, key, out pushStr,ref outLen);
            byte[] strbuf = new byte[outLen];
            Marshal.Copy(pushStr, strbuf, 0, outLen);
            WxRelease(pushStr);
            return strbuf;

        }
        [DllImport("CytpoBYDaya.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern void WxRSAheader(long s_dwVersion, int cgiType, int nLenProtobuf, int nLenCompressed, short nLenRsa, out IntPtr pushStr, ref int outLen);
        public static byte[] RSAheader(int cgi, int nLenProto,int LenCompress,int nLenRsa,IntPtr pushStr)
        {
            int outLen = 0;
            WxRSAheader(369493792, cgi, nLenProto, LenCompress, (short)nLenRsa, out  pushStr, ref outLen);
            byte[] retbuf = new byte[outLen];
            Marshal.Copy(pushStr, retbuf, 0, outLen);
            WxRelease(pushStr);
            return retbuf;


        }
        [DllImport("CytpoBYDaya.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern void WxLoginHeader(long s_dwVersion, int cgiType, int nLenProtobuf, int nLenCompressed, out IntPtr pushStr, ref int outLen);
        //u_long s_dwVersion, DWORD cgiType, DWORD nLenProtobuf, DWORD nLenCompressed, char**pushStr, int&outLen
        public static byte[] Loginheader(int cgi, int nLenProto, int LenCompress, IntPtr pushStr)
        {
            int outLen = 0;
            WxLoginHeader(369493792, cgi, nLenProto, LenCompress, out pushStr, ref outLen);
            byte[] retbuf = new byte[outLen];
            Marshal.Copy(pushStr, retbuf, 0, outLen);
            WxRelease(pushStr);
            return retbuf;
        }
        [DllImport("CytpoBYDaya.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern void WxAesHeader(long s_dwVersion,int uin,byte[]cookie,int cookieLen, int cgiType, int nLenProtobuf, int nLenCompressed, out IntPtr pushStr, ref int outLen);
        //u_long s_dwVersion,int Uin,char*cookie,int nLencookie, DWORD cgiType, DWORD nLenProtobuf, DWORD nLenCompressed, char**pushStr, int&outLen
        public static byte[] AesHeader(int uin, byte[] cookie, int cookieLen, int cgi, int nLenProto, int LenCompress, IntPtr pushStr)
        {
           
            int outLen = 0;
            WxAesHeader(369493792, uin, cookie, cookieLen, cgi, nLenProto, LenCompress, out pushStr, ref outLen);
            byte[] retbuf = new byte[outLen];
            Marshal.Copy(pushStr, retbuf, 0, outLen);
            WxRelease(pushStr);
            return retbuf;
        }
        [DllImport("CytpoBYDaya.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern void WxRelease(IntPtr p);
        public static void releasePtr(IntPtr p)
        {
            WxRelease(p);
        }
        public static byte[] AESDecrypt(byte[]AesKey,byte[]src,int DEorEN)
        {
            try
            {

                //判断是否是16位 如果不够补0
                //text = tests(text);
                //16进制数据转换成byte
                byte[] encryptedData = src;  // strToToHexByte(text);
                RijndaelManaged rijndaelCipher = new RijndaelManaged();
                rijndaelCipher.KeySize = 128;
                rijndaelCipher.BlockSize = 128 ;
                rijndaelCipher.Key = AesKey; // Encoding.UTF8.GetBytes(AesKey);
                rijndaelCipher.IV = AesKey;// Encoding.UTF8.GetBytes(AesIV);
                rijndaelCipher.Mode = CipherMode.CBC;
                rijndaelCipher.Padding = PaddingMode.PKCS7;

                ICryptoTransform transform = null;

                if (DEorEN == 2)
                {
                   transform = rijndaelCipher.CreateEncryptor(rijndaelCipher.Key, rijndaelCipher.IV);

                }else if (DEorEN == 1)
                {
                   transform = rijndaelCipher.CreateDecryptor();
                }
                
                byte[] xBuff = null;
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
                    {
                        byte[] xXml = src;

                        cs.Write(xXml, 0, xXml.Length);

                    }

                    xBuff = ms.ToArray();
                }                 
                //byte[] plainText = transform.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
               //string result = Encoding.Default.GetString(plainText);
                //int index = result.LastIndexOf('>');
                //result = result.Remove(index + 1);
                return xBuff;
            }
            catch (Exception ex)
            {
                return null;

            }
        }


        internal static string Utf8BytesToString(IntPtr pNativeData)
        {
            try
            {
                if (pNativeData == IntPtr.Zero)
                    return null;
                int nMaxLength = 5000000;
                int length = 0;//循环查找字符串的长度
                for (int i = 0; i < nMaxLength; i++)
                {
                    byte[] strbuf1 = new byte[1];
                    Marshal.Copy(pNativeData + i, strbuf1, 0, 1);
                    if (strbuf1[0] == 0)
                    {
                        break;
                    }
                    length++;
                }

                byte[] strbuf = new byte[length];
                Marshal.Copy(pNativeData, strbuf, 0, length);
                return System.Text.Encoding.UTF8.GetString(strbuf);
            }
            catch
            {
                return null;
            }
        }
    }
}
