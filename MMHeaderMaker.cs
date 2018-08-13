using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CRYPT;
using HPSocketCS;
using static MMPro.MM;


namespace LongLinkIOS
{
    class MMHeaderMaker
    {

        public static byte[] MakeHeader(MMClient mm,byte[] buff, UInt32 cgi_, int type = 5)
        {
            try
            {
                List<byte> strHeader = new List<byte>();
                int nCur = 0;
                byte SecondByte = 0x2;
                strHeader.Add(SecondByte);
                nCur++;
                //加密算法(前4bits),RSA加密(7)AES(5)
                byte ThirdByte = (byte)(type << 4);

                ThirdByte += 0xf;
                strHeader.Add((byte)ThirdByte);
                nCur++;
                //int dwUin = 0;
                strHeader = strHeader.Concat(mm.ver.ToByteArray(Endian.Big).ToList()).ToList();
                nCur += 4;

                strHeader = strHeader.Concat(mm.m_uid.ToByteArray(Endian.Big).ToList()).ToList();
                nCur += 4;

                //登录包不需要cookie 全0占位即可
                if (mm.cookie == null)
                {
                    strHeader = strHeader.Concat(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }).ToList();
                    nCur += 15;
                }
                else
                {
                    strHeader = strHeader.Concat(mm.cookie.ToList()).ToList();
                    nCur += 15;
                }

                //byte[] szCookie = new byte[15];

                byte[] strcgi = MMClient.Dword2String(cgi_);
                strHeader = strHeader.Concat(strcgi.ToList()).ToList();
                nCur += strcgi.Length;
                byte[] strLenProtobuf = MMClient.Dword2String((UInt32)buff.Length);
                strHeader = strHeader.Concat(strLenProtobuf.ToList()).ToList();
                nCur += strLenProtobuf.Length;
                byte[] strLenCompressed = MMClient.Dword2String((UInt32)buff.Length);
                strHeader = strHeader.Concat(strLenCompressed.ToList()).ToList();
                nCur += strLenCompressed.Length;
                //var rsaVer = Dword2String((UInt32)LOGIN_RSA_VER);
                //strHeader = strHeader.Concat(rsaVer).ToList();
                //nCur += rsaVer.Length;
                strHeader = strHeader.Concat(new byte[] { 0, 0xd }.ToList()).ToList();
                nCur += 2;
                var ___ = buff.ToString(16, 2);
                strHeader = strHeader.Concat(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }).ToList();
                nCur += 15;
                //     byte rsaVer = LOGIN_RSA_VER;
                //     strHeader = strHeader + string((const char*)&rsaVer, 1);
                //    nCur++;

                // byte[2] unkwnow = { 0x01, 0x02 };
                //  strHeader = strHeader + string((const char*)unkwnow, 2);
                // nCur += 2;

                //加密后数据长度
                // string subHeader;
                //short uLenProtobuf = nLenRsa;
                // strHeader = strHeader + string((const char*)&uLenProtobuf, 2);
                //nCur += 2;

                //毫无意义的5个字节(随意填写)
                //char szUnknown[5] = { 0 };
                // strHeader = strHeader + string((const char*)szUnknown, 5);
                // nCur += 5;

                //将包头长度写入第二字节前6bits(包头长度不会超出6bits)
                //SecondByte += (nCur << 2);
              //  var unkwnow = (5 * (1 & code)).ToByteArray(Endian.Little).Copy(2);// "0100".ToByteArray(16, 2);
               // strHeader = strHeader.Concat(unkwnow.ToList()).ToList();
               // nCur += unkwnow.Length;
               // nCur++;
                SecondByte += (byte)(nCur << 2);
                strHeader[1] = SecondByte;

                strHeader.Insert(0, 0xbf);
                return strHeader.ToArray();
            }
            catch (Exception)
            {
                System.Diagnostics.Debug.Print("MakeHead Error");
                return null;
            }
        }


    }
}
