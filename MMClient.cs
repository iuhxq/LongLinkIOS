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
    class MMClient
    {

       
  
 
        
        public struct __STNetMsgXpHeader
        {
            public UInt32 pack_length;       /* 4字节封包长度(含包头)，可变 */
            public ushort head_length;        /* 2字节表示头部长度,固定值，0x10*/
            public ushort client_version;     /* 2字节表示协议版本，固定值，0x01*/
            public UInt32 cmdid;             /* 4字节cmdid，可变*/
            public UInt32 seq;               /* 4字节封包编号，可变*/
        };
        public  struct NetMsgXpPack
        {
            public __STNetMsgXpHeader head;
            public byte[] body;
        }
        /*长连接相关*/
        TcpClient m_client = new TcpClient();
        System.Threading.Timer heartbeat_ { set; get; }
        public bool isconnected { set; get; }     
        public NetMsgXpPack UnLongLinkPack(byte[] data)
        {
            List<byte> msg = data.ToList();
            byte[] body = null;
            __STNetMsgXpHeader head = new __STNetMsgXpHeader();
            NetMsgXpPack pack = new NetMsgXpPack();
            head.pack_length = (uint)System.Net.IPAddress.HostToNetworkOrder(BitConverter.ToInt32(data.Copy(0, 4),0));

            head.head_length =(ushort)( BitConverter.ToUInt16(data.Copy(4, 2), 0) >> 8);
            if (head.head_length == 16)
            {
                head.client_version = (ushort)(BitConverter.ToUInt16(data.Copy(6, 2),0) >> 8);
                head.cmdid = (uint)System.Net.IPAddress.HostToNetworkOrder(BitConverter.ToInt32(data.Copy(8, 4),0));

                head.seq = (uint)System.Net.IPAddress.HostToNetworkOrder(BitConverter.ToInt32(data.Copy(12, 4),0));

                if (head.pack_length > data.Length)
                {
                    //包未收完
                    tempdata.head = head;
                    tempdata.body = data.Copy(16, data.Length - 16);
                }
                else if (head.pack_length == data.Length)
                    body = data.Copy(16, head.pack_length - 16);
                else
                {
                    body = data.Copy(16, head.pack_length - 16);
                    //UnLongLinkPack(data.Copy(head.pack_length, data.Length));
                }
            }
            else
            {
                head = tempdata.head;
                tempdata.body = tempdata.body.Concat(data).ToArray();
                if (tempdata.body.Length == tempdata.head.pack_length - 16)
                    body = tempdata.body;
            }
            pack.body = body; pack.head = head;
            return pack;
        }
        NetMsgXpPack tempdata = new NetMsgXpPack();
        public PACKINFO UnPackHeader(byte[] pack)
        {
            PACKINFO pACKINFO = new PACKINFO();
            byte[] body = new byte[] { };
            pACKINFO.body = body;
            if (pack.Length < 0x20) return pACKINFO;
            int nCur = 0;
            if (0xbf == pack[nCur])
            {
                nCur++;
            }
            //解析包头长度(前6bits)
            int nHeadLen = pack[nCur] >> 2;

            //是否使用压缩(后2bits)
            pACKINFO.m_bCompressed = (1 == (pack[nCur] & 0x3)) ? true : false;

            nCur++;

            //解密算法(前4 bits)(05:aes / 07:rsa)(仅握手阶段的发包使用rsa公钥加密,由于没有私钥收包一律aes解密)
            pACKINFO.m_nDecryptType = pack[nCur] >> 4;

            //cookie长度(后4 bits)
            int nCookieLen = pack[nCur] & 0xF;

            nCur++;

            //服务器版本,无视(4字节)
            nCur += 4;

            //登录包 保存uin
            //int dwUin;
            m_uid = (int)pack.Copy(nCur, 4).GetUInt32(Endian.Big);
            //memcpy(&dwUin, &(pack[nCur]), 4);
            //s_dwUin = ntohl(dwUin);
            nCur += 4;
            //刷新cookie(超过15字节说明协议头已更新)
            if (nCookieLen > 0 && nCookieLen <= 0xf)
            {
                byte[] s_cookie = pack.Copy(nCur, nCookieLen);
                //pAuthInfo->m_cookie = s_cookie;
                cookie = s_cookie;
                nCur += nCookieLen;
            }
            else if (nCookieLen > 0xf)
            {
                return null;
            }

            //cgi type,变长整数,无视

            int dwLen = DecodeVByte32(ref pACKINFO.CGI, pack.Copy(nCur, 5), 0);
            //pACKINFO. CGI = String2Dword(pack.Copy(nCur, 5));
            nCur += dwLen;

            //解压后protobuf长度，变长整数
           // int m_nLenRespProtobuf = 0;//String2Dword(pack.Copy(nCur, 5));
            dwLen = DecodeVByte32(ref pACKINFO.m_LenrespProtobuf, pack.Copy(nCur, 5), 0);
            nCur += dwLen;

            //压缩后(加密前)的protobuf长度，变长整数
            //int m_nLenRespCompressed = 0;//String2Dword(pack.Copy(nCur, 5));
            dwLen = DecodeVByte32(ref pACKINFO.m_LenCompressed, pack.Copy(nCur, 5), 0);
            nCur += dwLen;

            //后面数据无视

            //解包完毕,取包体
            if (nHeadLen < pack.Length)
            {
                body = pack.Copy(nHeadLen, pack.Length - nHeadLen);
            }
            pACKINFO.body = body;
            return pACKINFO;
        }
        public class PACKINFO
        {
            public bool m_bCompressed;
            public int m_nDecryptType;
            public int m_LenrespProtobuf;
            public int m_LenCompressed;
            public int CGI;
            public byte[] body;
        }
        public byte[] LongLinkPack(LongLinkCmdId cmdid, int seq, int bodyLen)
        {
            List<byte> msg = new List<byte>();

            __STNetMsgXpHeader head = new __STNetMsgXpHeader();

            head.pack_length = (uint)bodyLen + 16;
            //if (cmdid == LongLinkCmdId.SEND_NOOP_CMDID)
            //    head.client_version = (0);
            //else
            head.client_version = (1);
            head.cmdid = (uint)cmdid;
            head.seq = (uint)seq;
            head.head_length = 16;
            msg.AddRange(head.pack_length.ToByteArray(Endian.Big));
            msg.AddRange(head.head_length.ToByteArray(Endian.Big));
            msg.AddRange(head.client_version.ToByteArray(Endian.Big));
            msg.AddRange(head.cmdid.ToByteArray(Endian.Big));
            msg.AddRange(head.seq.ToByteArray(Endian.Big));
            var cv = msg.ToArray().ToString(16, 2);
            Console.WriteLine("LongLinkPack:"+ChangeType.ToHexString(msg.ToArray()));
            return msg.ToArray();
        }
        public byte[] LongLinkPack(LongLinkCmdId cmdid, CGI_TYPE cgi,byte[] body,Int32 etype=5)
        {
           
           
            if (etype==7)
            {
                var head = MakeAESHead(body, cgi,7,7);
                var pbody = head.Concat(nocompress_rsa(body)).ToArray();
                var lhead = LongLinkPack(cmdid, seq++, pbody.Length);
                pbody = lhead.Concat(pbody).ToArray();
                return pbody;
            }
            else if (etype == 1)
            {
                var head = MakeRSAHead((int) cgi, body.Length,1, false);
                var pbody = head.Concat(nocompress_rsa(body)).ToArray();
                var lhead = LongLinkPack(cmdid, seq++, pbody.Length);
                pbody = lhead.Concat(pbody).ToArray();
                return pbody;
            }
            else
            {
                var head = MakeAESHead(body, cgi);
                var pbody = head.Concat(nocompress_aes(body, AESKey.ToByteArray(16, 2))).ToArray();
                var lhead = LongLinkPack(cmdid, seq++, pbody.Length);
                pbody = lhead.Concat(pbody).ToArray();
                return pbody;
            }
      
        }
        public byte[] ShortLinkPack(CGI_TYPE cgi, byte[] body, Int32 etype = 5)
        {


            if (etype == 7)
            {
                var head = MakeAESHead(body, cgi, 7, 7);
                var pbody = head.Concat(nocompress_rsa(body)).ToArray();
                
               
                return pbody;
            }
            else if (etype == 1)
            {
                var head = MakeRSAHead((int)cgi, body.Length, 1, false);
                var pbody = head.Concat(nocompress_rsa(body)).ToArray();
                           
                return pbody;
            }
            else
            {
                var head = MakeAESHead(body, cgi);
                var pbody = head.Concat(nocompress_aes(body, AESKey.ToByteArray(16, 2))).ToArray();
               
                return pbody;
            }

        }
        public MMClient()
        {
           

            

        }


        public void BeginLongLink()
        {

            m_client.OnReceive += M_client_OnReceive;
            CheckEcdh = "";
            Console.WriteLine(longLink);
            if (m_client.Connect(longLink, 443))
            {

                isconnected = true;
                var d = LongLinkPack(LongLinkCmdId.SEND_NOOP_CMDID, -1, 0);

                heartbeat_ = new System.Threading.Timer(heartbeat, null, 0, 10 * 1000);
            }
        }
        public bool ReConnect(string ip)
        {

            isconnected = false;
            m_client.Stop();
         
            if (m_client.Connect(ip, 80))
            {

                isconnected = true;
                do
                {
                    System.Threading.Thread.Sleep(1000);
                } while (!m_client.IsStarted);
                var d = LongLinkPack(LongLinkCmdId.SEND_NOOP_CMDID, -1, 0);
                m_client.Send(d, d.Length);
                return true;
            }
            return false;
        }
        /*长连接相关*/


        /*加解密*/
        public byte[] compress_rsa(byte[] data)
        {

            using (RSA rsa = RSA.Create())
            {
                byte[] strOut = new byte[] { };
                rsa.ImportParameters(new RSAParameters() { Exponent = "010001".ToByteArray(16, 2), Modulus = "A69E974E15B895D5530CFF97EAD82B12D4B86D7926D7EB3D17357037BFFD0DBAA1CE100DBE462A1F68D2A12C967C14F5224C32B06E67A34DDD9C20F9A2306D0AE4768A2F24D4E2553AA05B67B9327737B4163C9F4B4AB02D840401AEB93EB617EBC8CA549628A9CC82ED5E0C78267170D18B254214B477280C52F72D1F2710170014F7FFE6C104CF2A540C7331855F6A1ACD5F50661BEC228D107532FF8AB7CEB9C15AD7EDB84D88097C92C71FCF043513DCC1C64AA004B8EBFD6CE139E0F55601C715366CFB8045EA7C9831E1AA9E5B125D41C138BF809841E703836FA9D227D0C5C4F88C4B7387B00BBFD4B90C12F793CA750EA5ED32ABBED70B82A890F7C7".ToByteArray(16, 2) });
                var rsa_len = rsa.KeySize;
                rsa_len = rsa_len / 8;
                data = ZipUtils.compressBytes(data);
                if (data.Length > rsa_len - 12)
                {
                    int blockCnt = (data.Length / (rsa_len - 12)) + (((data.Length % (rsa_len - 12)) == 0) ? 0 : 1);
                    //strOut.resize(blockCnt * rsa_len);

                    for (int i = 0; i < blockCnt; ++i)
                    {
                        int blockSize = rsa_len - 12;
                        if (i == blockCnt - 1) blockSize = data.Length - i * blockSize;
                        var temp = data.Copy(i * (rsa_len - 12), blockSize);
                        strOut = strOut.Concat(rsa.Encrypt(temp, RSAEncryptionPadding.Pkcs1)).ToArray();
                    }
                    return strOut;
                }
                else
                {
                    //strOut.resize(rsa_len);
                    return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                }
            }

        }
        public byte[] nocompress_rsa(byte[] data)
        {
            RSA rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters() { Exponent = "010001".ToByteArray(16, 2), Modulus = "A69E974E15B895D5530CFF97EAD82B12D4B86D7926D7EB3D17357037BFFD0DBAA1CE100DBE462A1F68D2A12C967C14F5224C32B06E67A34DDD9C20F9A2306D0AE4768A2F24D4E2553AA05B67B9327737B4163C9F4B4AB02D840401AEB93EB617EBC8CA549628A9CC82ED5E0C78267170D18B254214B477280C52F72D1F2710170014F7FFE6C104CF2A540C7331855F6A1ACD5F50661BEC228D107532FF8AB7CEB9C15AD7EDB84D88097C92C71FCF043513DCC1C64AA004B8EBFD6CE139E0F55601C715366CFB8045EA7C9831E1AA9E5B125D41C138BF809841E703836FA9D227D0C5C4F88C4B7387B00BBFD4B90C12F793CA750EA5ED32ABBED70B82A890F7C7".ToByteArray(16, 2) });
       
            return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
        }
        public static byte[] nocompress_aes(byte[] data, byte[] key)
        {
            return AES.AESEncrypt(data, key);
        }
        public byte[] compress_aes(byte[] data, byte[] key)
        {
            data = ZipUtils.compressBytes(data);

            return AES.AESEncrypt(data, key);
        }
        public byte[] getcookie()
        {
            return cookie;
            
            }
        public byte[] uncompress_aes(byte[] data, byte[] key)
        {
            data = AES.AESDecrypt(data, key);
            data = ZipUtils.deCompressBytes(data);
            return data;
        }
        public byte[] nouncompress_aes(byte[] data, byte[] key)
        {
            data = AES.AESDecrypt(data, key);
            //data = ZipUtils.deCompressBytes(data);
            return data;
        }
        public static byte[] Dword2String(UInt32 dw)
        {
            List<byte> apcBuffer = new List<byte>();

            while (dw >= 0x80)
            {

                apcBuffer.Add((byte)(0x80 + (dw & 0x7f)));
                dw = dw >> 7;
            }
            apcBuffer.Add((byte)dw);
            return apcBuffer.ToArray();
            //Int32 dwData = dw;
            //Int32 dwData2 = 0x80 * 0x80 * 0x80 * 0x80;
            //int nLen = 4;
            //byte[] hex = new byte[5];
            //Int32 dwOutLen = 0;

            //while (nLen > 0)
            //{
            //    if (dwData > dwData2)
            //    {
            //        hex[nLen] = (byte)(dwData / dwData2);
            //        dwData = dwData % dwData2;
            //        dwOutLen++;
            //    }

            //    dwData2 /= 0x80;
            //    nLen--;
            //}

            //hex[0] = (byte)dwData;
            //dwOutLen++;

            //for (int i = 0; i < (int)(dwOutLen - 1); i++)
            //{
            //    hex[i] += 0x80;
            //}

            //return hex;
        }
        public static int DecodeVByte32(ref int apuValue, byte[] apcBuffer, int off)
        {
            int dwLen = apcBuffer.Length;

            apuValue = 0;
            int dwTemp = 1;
            int nLen = 0;
            while (nLen < 5 && nLen < dwLen)
            {
                byte c = apcBuffer[nLen];

                if ((c >> 7) == 0)
                {
                    apuValue += c * dwTemp;
                    nLen++;
                    break;
                }
                else
                {
                    apuValue += (c & 0x7f) * dwTemp;
                    dwTemp *= 0x80;
                    nLen++;
                }
            }

            int dwOutLen = nLen;

            return dwOutLen;
        }

        /*加解密*/



        public T Deserialize<T>(byte[] data)
        {
            return ProtoBuf.Serializer.Deserialize<T>(new MemoryStream(data));
        }
        public byte[] Serialize<T>(T data)
        {
            MemoryStream memoryStream = new MemoryStream();
            ProtoBuf.Serializer.Serialize(memoryStream, data);
            return memoryStream.ToArray();
        }
        public static long CurrentTime_()
        {
            return (DateTime.Now.ToUniversalTime().Ticks - 621355968000000000) / 10000000;
        }
        public static string currentTimeMillis()
        {
            System.DateTime startTime = TimeZone.CurrentTimeZone.ToLocalTime(new System.DateTime(1970, 1, 1, 0, 0, 0, 0));
            long t = (DateTime.Now.Ticks - startTime.Ticks) / 10;   //除10000调整为13位        
            return t.ToString();
        }
        public static string CurrentTime()
        {
            System.DateTime startTime = TimeZone.CurrentTimeZone.ToLocalTime(new System.DateTime(1970, 1, 1, 0, 0, 0, 0));
            long t = (DateTime.Now.Ticks - startTime.Ticks) / 10000;   //除10000调整为13位        
            return t.ToString();

        }




        byte[] MakeRSAHead(int cgi, int nLenProtobuf, byte encodetypr = 7, bool iscookie = false, bool isuin = false)
        {
           
            List<byte> strHeader = new List<byte>();
            int nCur = 0;
            byte SecondByte = 0x2;
            strHeader.Add(SecondByte);
            nCur++;
            //加密算法(前4bits),RSA加密(7)AES(5)
            byte ThirdByte = (byte)(encodetypr << 4);
            if (iscookie)
                ThirdByte += 0xf;
            strHeader.Add((byte)ThirdByte);
            nCur++;
            int dwUin = 0;
            if (isuin)
                dwUin = m_uid;
            strHeader = strHeader.Concat(ver.ToByteArray(Endian.Big).ToList()).ToList();
            nCur += 4;

            strHeader = strHeader.Concat(dwUin.ToByteArray(Endian.Big).ToList()).ToList();
            nCur += 4;

            if (iscookie)
            {
                //登录包不需要cookie 全0占位即可
                if (cookie == null || cookie.Length < 0xf)
                {
                    strHeader = strHeader.Concat(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }).ToList();
                    nCur += 15;
                }
                else
                {
                    strHeader = strHeader.Concat(cookie.ToList()).ToList();
                    nCur += 15;
                }
            }
            byte[] strcgi = Dword2String((UInt32)cgi);
            strHeader = strHeader.Concat(strcgi.ToList()).ToList();
            nCur += strcgi.Length;
            byte[] strLenProtobuf = Dword2String((UInt32)nLenProtobuf);
            strHeader = strHeader.Concat(strLenProtobuf.ToList()).ToList();
            nCur += strLenProtobuf.Length;
            byte[] strLenCompressed = Dword2String((UInt32)nLenProtobuf);
            strHeader = strHeader.Concat(strLenCompressed.ToList()).ToList();
            nCur += strLenCompressed.Length;
            var rsaVer = Dword2String((UInt32)LOGIN_RSA_VER);
            strHeader = strHeader.Concat(rsaVer).ToList();
            nCur += rsaVer.Length;
            strHeader = strHeader.Concat(new byte[] { 0xd, 0 }.ToList()).ToList();
            nCur += 2;

            var unkwnow = (9).ToByteArray(Endian.Little).Copy(2);// "0100".ToByteArray(16, 2);
            strHeader = strHeader.Concat(unkwnow.ToList()).ToList();
            nCur += unkwnow.Length;
            nCur++;
            SecondByte += (byte)(nCur << 2);
            strHeader[0] = SecondByte;

            strHeader.Insert(0, 0xbf);
            return strHeader.ToArray();


        }
        public static byte[] SetMD5(byte[] src)
        {
            System.Security.Cryptography.MD5CryptoServiceProvider MD5CSP = new System.Security.Cryptography.MD5CryptoServiceProvider();

            return MD5CSP.ComputeHash(src);
        }
       // byte[] EcdhCheck(int uid, byte[] ecdkcheck, byte[] body)
      //  {

     //   }
        public byte[] MakeAESHead(byte[] buff, CGI_TYPE cgi_, int code = 7, int type = 5)
        {
            try
            {
                List<byte> strHeader = new List<byte>();
                
                int nCur = 0;
                byte SecondByte = 0x2;
                strHeader.Add(SecondByte);
                nCur++;
                //加密算法(前4bits),RSA加密(7)AES(5)
                byte ThirdByte = (byte)(0x5 << 4);

                ThirdByte += 0xf;
                strHeader.Add((byte)ThirdByte);
                nCur++;
                //int dwUin = 0;
                strHeader = strHeader.Concat(ver.ToByteArray(Endian.Big).ToList()).ToList();
                nCur += 4;

                strHeader = strHeader.Concat(uin.ToByteArray(Endian.Big).ToList()).ToList();
                nCur += 4;

                //写入cookie

                strHeader = strHeader.Concat(cookie.ToList()).ToList();
                nCur += 15;
              

                //byte[] szCookie = new byte[15];

                byte[] strcgi = Dword2String((UInt32)cgi_);
                strHeader = strHeader.Concat(strcgi.ToList()).ToList();
                nCur += strcgi.Length;
                byte[] strLenProtobuf = Dword2String((UInt32)buff.Length);
                strHeader = strHeader.Concat(strLenProtobuf.ToList()).ToList();
                nCur += strLenProtobuf.Length;
                byte[] strLenCompressed = Dword2String((UInt32)buff.Length);
                strHeader = strHeader.Concat(strLenCompressed.ToList()).ToList();
                nCur += strLenCompressed.Length;
                //var rsaVer = Dword2String((UInt32)LOGIN_RSA_VER);
                //strHeader = strHeader.Concat(rsaVer).ToList();
                //nCur += rsaVer.Length;
                //strHeader = strHeader.Concat(new byte[] { 0, 0xd }.ToList()).ToList();
              //  nCur += 2;
                //var ___ = buff.ToString(16, 2);
            
                // MMTLS验证.15个字节跳过
                strHeader = strHeader.Concat(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }).ToList();
                nCur += 15;
             
                SecondByte += (byte)(nCur << 2);
                strHeader[0] = SecondByte;

                strHeader.Insert(0, 0xbf);
                return strHeader.ToArray();
                /*
                nCur += unkwnow.Length;
                nCur++;
                SecondByte += (byte)(nCur << 2);
                strHeader[0] = SecondByte;

                strHeader.Insert(0, 0xbf);
                */
            }
            catch (Exception)
            {
                System.Diagnostics.Debug.Print("MakeHead Error");
                return null;
            }
        }
        private void bytes_add(ref byte[] src, byte[] b)
        {
            if (src == null) { src = b; return; }
            else
            {
                Array.Resize(ref src, src.Length + b.Length);
                b.CopyTo(src, src.Length - b.Length);
                
            }
        }

        byte[] NewSyncEcode(int scane)
        {
            //0a020800108780101a8a02088402128402081f1208080110aaa092ba021208080210a9a092ba0212080803109aa092ba021208080410f28292ba021208080510f28292ba021208080710f28292ba02120408081000120808091099a092ba021204080a10001208080b10839f92ba021204080d10001208080e10f28292ba021208081010f28292ba021204086510001204086610001204086710001204086810001204086910001204086b10001204086d10001204086f1000120408701000120408721000120908c90110f5d7fbd705120908cb0110c6bcf3d705120508cc011000120508cd011000120908e80710fdd0fad705120908e90710ba92fad705120908ea07109bf1c9d705120908d10f10d1b9f0d70520032a0a616e64726f69642d31393001
            MemoryStream memoryStream = new MemoryStream();
            NewSyncRequest request = new NewSyncRequest()
            {
                continueflag = new FLAG() { flag = 0 },
                device = "iPad iPhone OS8.4",
                scene = scane,
                selector = 262151,//3
                syncmsgdigest = 3,
                tagmsgkey = new syncMsgKey()
                {
                    msgkey = new Synckey()
                    {
                        size = 32
                    }
                }
            };

            if (synckey.Count() < 100)
            {
                request.tagmsgkey.msgkey.type = new List<Synckey.Synckey_>() {
                new Synckey.Synckey_(){type=1,synckey=0},
                new Synckey.Synckey_(){type=2,synckey=0},
                new Synckey.Synckey_(){type=3,synckey=0},
                new Synckey.Synckey_(){type=4,synckey=0},
                new Synckey.Synckey_(){type=5,synckey=0},
                new Synckey.Synckey_(){type=7,synckey=0},
                new Synckey.Synckey_(){type=8,synckey=0},
                new Synckey.Synckey_(){type=9,synckey=0},
                new Synckey.Synckey_(){type=10,synckey=0},
                new Synckey.Synckey_(){type=11,synckey=0},
                new Synckey.Synckey_(){type=13,synckey=0},
                new Synckey.Synckey_(){type=14,synckey=0},
                new Synckey.Synckey_(){type=16,synckey=0},
                new Synckey.Synckey_(){type=17,synckey=0},
                new Synckey.Synckey_(){type=101,synckey=0},
                new Synckey.Synckey_(){type=102,synckey=0},
                new Synckey.Synckey_(){type=103,synckey=0},
                new Synckey.Synckey_(){type=104,synckey=0},
                new Synckey.Synckey_(){type=105,synckey=0},
                new Synckey.Synckey_(){type=107,synckey=0},
                new Synckey.Synckey_(){type=109,synckey=0},
                new Synckey.Synckey_(){type=111,synckey=0},
                new Synckey.Synckey_(){type=112,synckey=0},
                new Synckey.Synckey_(){type=114,synckey=0},
                new Synckey.Synckey_(){type=201,synckey=0},
                new Synckey.Synckey_(){type=203,synckey=0},
                new Synckey.Synckey_(){type=204,synckey=0},
                new Synckey.Synckey_(){type=205,synckey=0},
                new Synckey.Synckey_(){type=1000,synckey=0},
                new Synckey.Synckey_(){type=1001,synckey=0},
                new Synckey.Synckey_(){type=1002,synckey=0},
                new Synckey.Synckey_(){type=2001,synckey=0},
            }.ToArray();
                ProtoBuf.Serializer.Serialize(memoryStream, request.tagmsgkey.msgkey);
                request.tagmsgkey.len = memoryStream.ToArray().Length;
            }
            else
            {
                request.tagmsgkey = Deserialize<syncMsgKey>(synckey.ToByteArray(16, 2));
            }

            memoryStream = new MemoryStream(memoryStream.Capacity);
            ProtoBuf.Serializer.Serialize(memoryStream, request);
            var _ = memoryStream.ToArray().ToString(16, 2);
            var data = "0a00108780101a840208fe0112fe0108201208080110d0ab89c7021208080210a7ad89c7021208080310edac89c70212040804100012040805100012040807100012040808100012080809108dad89c7021204080a10001208080b108cab89c7021204080d10001208080e10b19786c7021208081010b19786c7021204081110001204086510001204086610001204086710001204086810001204086910001204086b10001204086d10001204086f1000120408701000120408721000120908c901108fe5c2d905120908cb0110eedbc1d905120508cc011000120508cd011000120908e80710e2ccc2d905120908e90710e9cdc2d905120908ea0710849c9cd905120908d10f10cf87a8d90520042a1169506164206950686f6e65204f53382e343001".ToByteArray(16, 2);
            //var asd = AES.AESEncrypt(memoryStream.ToArray(), AESKey.ToByteArray(16, 2));
            var asd = AES.AESEncrypt(data, AESKey.ToByteArray(16, 2));
            //var head = MakeHead(memoryStream.ToArray(), CGI_TYPE.CGI_TYPE_NEWSYNC);
            var head = MakeAESHead(data, CGI_TYPE.CGI_TYPE_NEWSYNC);
            _ = head.ToString(16, 2);
            head = head.Concat(asd).ToArray();
            return head;
        }

        private HandleResult M_client_OnReceive(TcpClient sender, byte[] bytes)
        {
            var data = bytes;
          
            var r = UnLongLinkPack(data);
            data = r.body;
   
            if (data != null && data.Length > 0)
            {
                Console.WriteLine("长度:{0} , CMD:{1} \n", r.body.Length, r.head.cmdid);
                if (data.Length < 0x20)
                {
                    switch ((LongLinkCmdId)r.head.cmdid)
                    {
                        case LongLinkCmdId.RECV_PUSH_CMDID:
                            {
                                var body = NewSyncEcode(4);
                                var head = LongLinkPack(LongLinkCmdId.SEND_NEWSYNC_CMDID, seq++, body.Length);
                                body = head.Concat(body).ToArray();
                                m_client.Send(body, body.Length);
                                //NewSync();
                            }
                            break;
                        case LongLinkCmdId.RECV_NOOP_CMDID:
                            break;
                        case LongLinkCmdId.SEND_NEWSYNC_CMDID:
                            break;
                        case LongLinkCmdId.LONGLINK_IDENTIFY_REQ:
                            break;
                        case LongLinkCmdId.LONGLINK_IDENTIFY_RESP:
                            break;
                        case LongLinkCmdId.PUSH_DATA_CMDID:
                            break;
                        case LongLinkCmdId.SEND_SYNC_SUCCESS:
                            break;
                        case LongLinkCmdId.SIGNALKEEP_CMDID:
                            break;
                        case LongLinkCmdId.NEWSENDMSG:
                            break;
                        case LongLinkCmdId.SEND_MANUALAUTH_CMDID:
                            break;
                        default:
                            break;
                    }
                }
                else
                {
                    var packinfo = UnPackHeader(data);
                    byte[] RespProtobuf = new byte[] { };
                    if (packinfo.m_bCompressed)
                        RespProtobuf = uncompress_aes(packinfo.body, AESKey.ToByteArray(16, 2));
                    else
                        RespProtobuf = nouncompress_aes(packinfo.body, AESKey.ToByteArray(16, 2));
                    if (RespProtobuf == null || RespProtobuf.Length == 0) return HandleResult.Ok;
                    switch ((CGI_TYPE)packinfo.CGI)
                    {
                        case CGI_TYPE.CGI_TYPE_GETLOGINQRCODE:
                            {
                                GetLoginQRCodeResponse getLoginQRCodeResponse = Deserialize<GetLoginQRCodeResponse>(RespProtobuf);

                                _pfn(getLoginQRCodeResponse);

                                break;
                            }
                        case CGI_TYPE.CGI_TYPE_CHECKLOGINQRCODE:
                            {
                                var o = Deserialize<CheckLoginQRCodeResponse>(RespProtobuf);
                                _checkloginqrcodepfn(o);
                                //if (o.baseResponse.ret == 0)
                                //{
                                //    var asd = o.data.notifyData.buffer.ToString(16, 2);
                                //    var __ = nouncompress_aes(o.data.notifyData.buffer, aeskey);
                                //    return Deserialize<MM.LoginQRCodeNotify>(__);
                                //}
                                //Debug.Print(o.baseResponse.ret.ToString());
                                //return new MM.LoginQRCodeNotify() { };
                                break;
                            }

                        case CGI_TYPE.CGI_TYPE_NEWSENDMSG:
                            break;
                        case CGI_TYPE.CGI_TYPE_GETEMOTIONDESC:
                            break;
                        case CGI_TYPE.CGI_TYPE_SENDEMOJI:
                            break;
                        case CGI_TYPE.CGI_TYPE_NEWSYNC:
                            {
                                NewSyncResponse p = Deserialize<NewSyncResponse>(RespProtobuf);
                                Console.WriteLine("InTaTal--->>>>{0} \n",p.cmdList.count);
                                var synckey = Deserialize<syncMsgKey>(p.sync_key);
                                var synckey_ = Serialize(synckey.msgkey);
                                var body = LongLinkPack(LongLinkCmdId.SEND_SYNC_SUCCESS, seq++, synckey_.Length + 8);


                                body = body.Concat(ReportSyncKV(synckey_)).ToArray();
                                m_client.Send(body, body.Length);
                            }
                            break;
                        case CGI_TYPE.CGI_TYPE_MANUALAUTH:
                            {

                                if (RespProtobuf == null) break;
       
                                mm.command.NewAuthResponse niReceive = mm.command.NewAuthResponse.ParseFrom(RespProtobuf);
                                _manualAuthCallBack(niReceive);

                                //cdn = GetCdnDNS();
                            }
                            break;
                        case CGI_TYPE.CGI_TYPE_UPLOADIMAGE:
                            break;
                        case CGI_TYPE.CGI_TYPE_FAVSYNC:
                            break;
                        case CGI_TYPE.CGI_TYPE_ADDFAVITEM:
                            break;
                        case CGI_TYPE.CGI_TYPE_BATCHGETFAVITEM:
                            break;
                        case CGI_TYPE.CGI_TYPE_GETFAVINFO:
                            break;
                        case CGI_TYPE.CGI_TYPE_GETCONTACTLABELLIST:
                            break;
                        case CGI_TYPE.CGI_TYPE_UPLOADVOICE:
                            break;
                        case CGI_TYPE.CGI_TYPE_SENDAPPMSG:
                            break;
                        case CGI_TYPE.CGI_TYPE_UPLOADVIDEO:
                            break;
                        default:
                            break;
                    }
                }

            }
            return HandleResult.Ok;
        }

        public byte[] shortUnPack(byte[] data)
        {

            var packinfo = UnPackHeader(data);
            byte[] RespProtobuf = new byte[] { };
            IntPtr pushstr = IntPtr.Zero;
            Console.WriteLine("随机AESKEY:" + ChangeType.ToHexString(AESKey.ToByteArray(16, 2)));
            if (packinfo.m_bCompressed)                
                RespProtobuf = MyFuckSSL.AesDecodeComprese(packinfo.body,packinfo.body.Length ,AESKey.ToByteArray(16,2),packinfo.m_LenrespProtobuf, pushstr);
               // RespProtobuf = uncompress_aes(packinfo.body, AESKey.ToByteArray(16, 2));
            else
                RespProtobuf = nouncompress_aes(packinfo.body, AESKey.ToByteArray(16, 2));


         return RespProtobuf;
       
        }

    
        //回复消费
        public byte[] ReportSyncKV(byte[] sync_key)
        {
            //包头固定8字节,前4字节为时间差(newsync utc与当前本地utc时间差？不关心,可任意填写;大端,单位us)
            //后4字节大端包体长度
            byte[] strHeader = 0x223.ToByteArray(Endian.Big);

            var dwLen = System.Net.IPAddress.HostToNetworkOrder(sync_key.Length);

            strHeader = strHeader.Concat(dwLen.ToByteArray(Endian.Little)).ToArray();
            strHeader = strHeader.Concat(sync_key).ToArray();
            return strHeader;
        }

        //心跳
        void heartbeat(object o)
        {
            if (isconnected)
            {
                var d = LongLinkPack(LongLinkCmdId.SEND_NOOP_CMDID, -1, 0);
                m_client.Send(d, d.Length);
            }
         
        }
      
        
        
        #region MMAPI
        BaseRequest baseRequest { set; get; }
        public Int32 seq { set; get; }
        public byte[] pri_key_buf = new byte[] { };
        public byte[] pub_key_buf = new byte[] { };
        public string AESKey { set; get; }
        public string wxid { set; get; }
        public byte[] cookie { set; get; }
        public Int32 m_uid { set; get; }
        public string synckey = "";
        public byte[] initSyncKey { set; get; }
        public byte[] maxSyncKey { set; get; }
        public string CheckEcdh { set; get; }
        public int ver = 0x16070124;
        public UInt32 LOGIN_RSA_VER = 172;
        public byte[] deviceID { set; get; }
        public string devicetype { set; get; }
        public byte[] ecPubKey { set; get; }
        public byte[] ecPriKey { set; get; }
        public byte[] ShakeKey { set; get; }
      
        public byte[] notifykey { set; get; }
        public string username { set; get; }
        public string password { set; get; }
        public uint uin { set; get; }
        public string shortLink = "http://short.weixin.qq.com";
        public string longLink = "long.weixin.qq.com";

        public BaseRequest GetBaseRequest(int scene = 0)
        {

            if (baseRequest == null)
            {
                MemoryStream memoryStream = new MemoryStream();
                baseRequest = new BaseRequest()
                {
                    clientVersion = (int)ver,

                    devicelId = "49aa7db2f4a3ffe0e96218f6b92cde32".ToByteArray(16, 2),
                    scene = scene,
                    sessionKey = AESKey.ToByteArray(16, 2),
                    osType = "iPad iPhone OS8.4",
                    uin = m_uid
                };
            }
            else
            {

               
                baseRequest.scene = scene;
            }
            return baseRequest;
        }
        public delegate void GetLoginQRCodeCallBack(GetLoginQRCodeResponse message);
        GetLoginQRCodeCallBack _pfn;
        public bool GetLoginQRCode(GetLoginQRCodeCallBack pfn)
        {
            if (!isconnected) return false;
            _pfn = pfn;
            AESKey = (new Random()).NextBytes(16).ToString(16,2);
            GetLoginQRCodeRequest getLoginQRCodeRequest = new GetLoginQRCodeRequest()
            {
                aes = new AesKey()
                {
                    key = AESKey.ToByteArray(16, 2),
                    len = 16
                },
                baseRequest = GetBaseRequest(0),

                opcode = 0
            };

            getLoginQRCodeRequest.aes = new AesKey()
            {
                key = AESKey.ToByteArray(16, 2),
                len = 16
            };

            var src = Serialize(getLoginQRCodeRequest);
            int bufferlen = src.Length;

            src=LongLinkPack(LongLinkCmdId.SEND_GETLOGINQRCODE, CGI_TYPE.CGI_TYPE_GETLOGINQRCODE, src,1);
            Console.WriteLine(ChangeType.ToHexString(src));
            return m_client.Send(src, src.Length);          
        }
        public delegate void CheckLoginQRCodeCallBack(CheckLoginQRCodeResponse message);
        CheckLoginQRCodeCallBack _checkloginqrcodepfn;
        public bool CheckLoginQRCode(string qrname, CheckLoginQRCodeCallBack _)
        {
            if (!isconnected) return false;
            _checkloginqrcodepfn = _;
            CheckLoginQRCodeRequest checkLoginQRCodeRequest = new CheckLoginQRCodeRequest()
            {
                aes = new AesKey()
                {
                    key = AESKey.ToByteArray(16, 2),
                    len = 16
                },
                baseRequest = GetBaseRequest(0),
                uuid = qrname,
                timeStamp = (uint)CurrentTime_(),
                opcode = 0
            };
            var src = Serialize(checkLoginQRCodeRequest);

            src = LongLinkPack(LongLinkCmdId.SEND_CHECKLOGINQRCODE_CMDID, CGI_TYPE.CGI_TYPE_CHECKLOGINQRCODE, src, 1);

            return m_client.Send(src, src.Length);

        }
        public delegate void ManualAuthCallBack(mm.command.NewAuthResponse message);
        ManualAuthCallBack _manualAuthCallBack;
        public void SetManualAuthCallBack(ManualAuthCallBack manualAuthCallBack)
        {
            _manualAuthCallBack = manualAuthCallBack;
        }
        public bool ManualAuth(string wxnewpass, string wxid)
        {
            if (!isconnected) return false;
            //_checkloginqrcodepfn = _;
            MyFuckSSL.GenEcdh__(ref pub_key_buf, ref pri_key_buf);
            ManualAuthAccountRequest manualAuthAccountRequest = new ManualAuthAccountRequest()
            {
                aes = new AesKey()
                {
                    len = 16,
                    key = AESKey.ToByteArray(16, 2)
                },
                ecdh = new Ecdh()
                {
                    ecdhkey = new EcdhKey()
                    {
                        key = pub_key_buf,
                        len = 57
                    },
                    nid = 713
                },

                password1 = wxnewpass,
                password2 = null,
                userName = wxid
            };
            ManualAuthDeviceRequest manualAuthDeviceRequest = new ManualAuthDeviceRequest();
            manualAuthDeviceRequest = Deserialize<ManualAuthDeviceRequest>("0A310A0010001A1049AA7DB2F4A3FFE0E96218F6B92CDE3220A08E98B0012A1169506164206950686F6E65204F53382E34300112023A001A203363616137646232663461336666653065393632313866366239326364653332228D023C736F6674747970653E3C6B333E382E343C2F6B333E3C6B393E695061643C2F6B393E3C6B31303E323C2F6B31303E3C6B31393E45313841454344332D453630422D344635332D423838372D4339343436344437303836393C2F6B31393E3C6B32303E3C2F6B32303E3C6B32313E313030333C2F6B32313E3C6B32323E286E756C6C293C2F6B32323E3C6B32343E62383A66383A38333A33393A61643A62393C2F6B32343E3C6B33333EE5BEAEE4BFA13C2F6B33333E3C6B34373E313C2F6B34373E3C6B35303E313C2F6B35303E3C6B35313E6461697669732E495041443C2F6B35313E3C6B35343E69506164322C353C2F6B35343E3C6B36313E323C2F6B36313E3C2F736F6674747970653E2800322B33636161376462326634613366666530653936323138663662393263646533322D313532383535343230314204695061644A046950616452057A685F434E5A04382E3030680070AFC6EFD8057A054170706C65920102434E9A010B6461697669732E49504144AA010769506164322C35B00102BA01D50608CF0612CF060A08303030303030303310011AC0068A8DCEEE5AB9F4E16054EDA0545F7288B7951621A41446C1AEC0621B3CFE6926737F8298D0B52F467FDFC5EC936D512D332A1AC664E7DFEE734A5E403A72225F852734BF32F6FD623B95D17B64DC8D18FBB2CA2015113CD17518274BED4687D26F5D9E270687745541FA84921A16B50CFE487B1A88C3A91D838A2520AF8757F0E5ACE55BA599B9FCDF1595C3DAAD8E3A34C28BA39951D7A4CF9075CCC28721BA61E48C2DA1B853F3BE0D79AC63F47F2E3C4FF10D4D1CCC1D3002B6F63C228641C1EEB24686BA300853C355C268057D733B7898D20E6B43621419D8BCFCAED82C45377653234B7421238D00B25089670DDEBB03274B1D0D8C45D5A0EA7ECA9086254CCEAA8674ADE4DF905914437BC73D4C9D50CEC9ABCB927590D068DC10A810D376DAFB17A31F947765FF6A7F3B191EC40EEC4AA86FF8771CD2D717D25EE2B7555179AF4C611B9C6AD802B8FDAEAE36CA3497C438E8D4A06B1A7A570D74AAF6C244E8D23BA635FF0F27DCFCF5F6C4754A0049A620AE99012EB4936D34BAD267EAFDB12B67D5274272D3BC795B6454B4C2B768929007D0993F742A519D567ACD0369FCC9196D3CC04578F795026C336F2A29A012608C66E2068F5994210173C5A3B2720A4D040A6D2C3E873D56CE88F85CEFE4847743DEF1102653D42FBC3A31CA5BFE2E666D3542E6E1C5BCCE54D99EC934B183EED69FEA87D975666065E5903F366EFFE04627603FD64861C142A5A19EBD344BF194DE427FB4B70AA0D3CD972AC0A11EA6913E17366CA48966090E10B246BABABA553DBF89BEA4F55004C37E546ABABB8AA20E80B2A0ED21B6700F89699FD01983EDA71ACE6A44B6397605D30E88683BA4BB92A50DC7AFFB820089F157B8C83F7B5DCD35BABCC90501E2E6BDF83327A1059908C72EAF1B5A07CA6565A0888883966D26386C69293649BEC0913FE12C1ABA7B0B16261176E2F7D109FCF68A46B7C3AF7126E77224AA36891B703655CFEA2AAA8B5E095D8B204308133E63D0F0309E8B1CB5A21E9C8B27090859139C076723DE4C74578F6584888220A11A45CDDEC43A1F542552604C96FFE3A01006946086A864C182361B3659C1BDE9ECEA5236F5F38BA98A4C7E8C81A39D5CBA39B7A0F9FFA75AC59BB956595B58DAED58A0851D48B0B7A7407FA576E4956C".ToByteArray(16, 2));
            manualAuthDeviceRequest.Timestamp = (int)CurrentTime_();
            manualAuthDeviceRequest.Clientcheckdat = new SKBuiltinString_() { buffer = new byte[] { }, iLen = 0 };
            manualAuthDeviceRequest.imei = Encoding.UTF8.GetBytes("863114007939056");
            manualAuthDeviceRequest.clientSeqID = manualAuthDeviceRequest.imei + "-" + ((int)CurrentTime_()).ToString();
            manualAuthDeviceRequest.baseRequest = GetBaseRequest(0);
            var account = Serialize(manualAuthAccountRequest);
            byte[] device = Serialize(manualAuthDeviceRequest);
            byte[] subHeader = new byte[] { };
            int dwLenAccountProtobuf = account.Length;
            subHeader = subHeader.Concat(dwLenAccountProtobuf.ToByteArray(Endian.Big)).ToArray();
            int dwLenDeviceProtobuf = device.Length;
            subHeader = subHeader.Concat(dwLenDeviceProtobuf.ToByteArray(Endian.Big)).ToArray();

            if (subHeader.Length > 0 && account.Length > 0 && device.Length > 0)
            {
                var cdata = compress_rsa(account);
                int dwLenAccountRsa = cdata.Length;
                subHeader = subHeader.Concat(dwLenAccountRsa.ToByteArray(Endian.Big)).ToArray();
                byte[] body = subHeader;
                ManualAuthDeviceRequest m_ManualAuthDeviceRequest = Deserialize<ManualAuthDeviceRequest>(device);
                //var t2=m_ManualAuthDeviceRequest.tag2.ToString(16, 2);

                var memoryStream = Serialize(m_ManualAuthDeviceRequest);

                body = body.Concat(cdata).ToArray();

                body = body.Concat(compress_aes(device, AESKey.ToByteArray(16, 2))).ToArray();
                //var head = MakeHead( body, MM.CGI_TYPE.CGI_TYPE_MANUALAUTH, 7);
                var head = MakeRSAHead((int)CGI_TYPE.CGI_TYPE_MANUALAUTH, body.Length, 7, false);

                head = head.Concat(body).ToArray();
               

                //var ret = HttpPost(@short + MM.URL.CGI_MANUALAUTH, head, null);
                var lhead = LongLinkPack(LongLinkCmdId.SEND_MANUALAUTH_CMDID,seq++,head.Length);
                body = lhead.Concat(head).ToArray();
                return m_client.Send(body, body.Length);
            }
            else
                return false;
            //return null;

        }
        public static string EncryptWithMD5(string source)
        {
            byte[] sor = Encoding.UTF8.GetBytes(source);
            MD5 md5 = MD5.Create();
            byte[] result = md5.ComputeHash(sor);
            StringBuilder strbul = new StringBuilder(40);
            for (int i = 0; i < result.Length; i++)
            {
                strbul.Append(result[i].ToString("x2"));//加密结果"x2"结果为32位,"x3"结果为48位,"x4"结果为64位

            }
            return strbul.ToString();
        }
        public byte[]LoginTest(string username,string password)
        {
            MyFuckSSL.GenEcdh__(ref pub_key_buf, ref pri_key_buf);
            AESKey = "9AA7DB2F4A3FFE0E9AA7DB2F4A3FFE0E";
             ManualAuthAccountRequest manualAuthAccountRequest = new ManualAuthAccountRequest()
            {
                aes = new AesKey()
                {
                    len = 16,
                    key = AESKey.ToByteArray(16, 2)
                },
                ecdh = new Ecdh()
                {
                    ecdhkey = new EcdhKey()
                    {
                        key = pub_key_buf,
                        len = 57
                    },
                    nid = 713
                },

                password1 = EncryptWithMD5(password),
                password2 = EncryptWithMD5(password),
                userName = username
            };
            Console.WriteLine(EncryptWithMD5(password));
            ManualAuthDeviceRequest manualAuthDeviceRequest = new ManualAuthDeviceRequest();
            manualAuthDeviceRequest = Deserialize<ManualAuthDeviceRequest>("0A310A0010001A1049AA7DB2F4A3FFE0E96218F6B92CDE3220A08E98B0012A1169506164206950686F6E65204F53382E34300112023A001A203363616137646232663461336666653065393632313866366239326364653332228D023C736F6674747970653E3C6B333E382E343C2F6B333E3C6B393E695061643C2F6B393E3C6B31303E323C2F6B31303E3C6B31393E45313841454344332D453630422D344635332D423838372D4339343436344437303836393C2F6B31393E3C6B32303E3C2F6B32303E3C6B32313E313030333C2F6B32313E3C6B32323E286E756C6C293C2F6B32323E3C6B32343E62383A66383A38333A33393A61643A62393C2F6B32343E3C6B33333EE5BEAEE4BFA13C2F6B33333E3C6B34373E313C2F6B34373E3C6B35303E313C2F6B35303E3C6B35313E6461697669732E495041443C2F6B35313E3C6B35343E69506164322C353C2F6B35343E3C6B36313E323C2F6B36313E3C2F736F6674747970653E2800322B33636161376462326634613366666530653936323138663662393263646533322D313532383535343230314204695061644A046950616452057A685F434E5A04382E3030680070AFC6EFD8057A054170706C65920102434E9A010B6461697669732E49504144AA010769506164322C35B00102BA01D50608CF0612CF060A08303030303030303310011AC0068A8DCEEE5AB9F4E16054EDA0545F7288B7951621A41446C1AEC0621B3CFE6926737F8298D0B52F467FDFC5EC936D512D332A1AC664E7DFEE734A5E403A72225F852734BF32F6FD623B95D17B64DC8D18FBB2CA2015113CD17518274BED4687D26F5D9E270687745541FA84921A16B50CFE487B1A88C3A91D838A2520AF8757F0E5ACE55BA599B9FCDF1595C3DAAD8E3A34C28BA39951D7A4CF9075CCC28721BA61E48C2DA1B853F3BE0D79AC63F47F2E3C4FF10D4D1CCC1D3002B6F63C228641C1EEB24686BA300853C355C268057D733B7898D20E6B43621419D8BCFCAED82C45377653234B7421238D00B25089670DDEBB03274B1D0D8C45D5A0EA7ECA9086254CCEAA8674ADE4DF905914437BC73D4C9D50CEC9ABCB927590D068DC10A810D376DAFB17A31F947765FF6A7F3B191EC40EEC4AA86FF8771CD2D717D25EE2B7555179AF4C611B9C6AD802B8FDAEAE36CA3497C438E8D4A06B1A7A570D74AAF6C244E8D23BA635FF0F27DCFCF5F6C4754A0049A620AE99012EB4936D34BAD267EAFDB12B67D5274272D3BC795B6454B4C2B768929007D0993F742A519D567ACD0369FCC9196D3CC04578F795026C336F2A29A012608C66E2068F5994210173C5A3B2720A4D040A6D2C3E873D56CE88F85CEFE4847743DEF1102653D42FBC3A31CA5BFE2E666D3542E6E1C5BCCE54D99EC934B183EED69FEA87D975666065E5903F366EFFE04627603FD64861C142A5A19EBD344BF194DE427FB4B70AA0D3CD972AC0A11EA6913E17366CA48966090E10B246BABABA553DBF89BEA4F55004C37E546ABABB8AA20E80B2A0ED21B6700F89699FD01983EDA71ACE6A44B6397605D30E88683BA4BB92A50DC7AFFB820089F157B8C83F7B5DCD35BABCC90501E2E6BDF83327A1059908C72EAF1B5A07CA6565A0888883966D26386C69293649BEC0913FE12C1ABA7B0B16261176E2F7D109FCF68A46B7C3AF7126E77224AA36891B703655CFEA2AAA8B5E095D8B204308133E63D0F0309E8B1CB5A21E9C8B27090859139C076723DE4C74578F6584888220A11A45CDDEC43A1F542552604C96FFE3A01006946086A864C182361B3659C1BDE9ECEA5236F5F38BA98A4C7E8C81A39D5CBA39B7A0F9FFA75AC59BB956595B58DAED58A0851D48B0B7A7407FA576E4956C".ToByteArray(16, 2));
            manualAuthDeviceRequest.Timestamp = (int)CurrentTime_();
            manualAuthDeviceRequest.Clientcheckdat = new SKBuiltinString_() { buffer = new byte[] { }, iLen = 0 };
            manualAuthDeviceRequest.imei = Encoding.UTF8.GetBytes("863114007939056");
            manualAuthDeviceRequest.clientSeqID = manualAuthDeviceRequest.imei + "-" + ((int)CurrentTime_()).ToString();
            manualAuthDeviceRequest.baseRequest = GetBaseRequest(0);
            var account = Serialize(manualAuthAccountRequest);
            byte[] device = Serialize(manualAuthDeviceRequest);
            byte[] subHeader = new byte[] { };
            int dwLenAccountProtobuf = account.Length;
            subHeader = subHeader.Concat(dwLenAccountProtobuf.ToByteArray(Endian.Big)).ToArray();
            int dwLenDeviceProtobuf = device.Length;
            subHeader = subHeader.Concat(dwLenDeviceProtobuf.ToByteArray(Endian.Big)).ToArray();

            if (subHeader.Length > 0 && account.Length > 0 && device.Length > 0)
            {
                var cdata = compress_rsa(account);
                int dwLenAccountRsa = cdata.Length;
                subHeader = subHeader.Concat(dwLenAccountRsa.ToByteArray(Endian.Big)).ToArray();
                byte[] body = subHeader;
                ManualAuthDeviceRequest m_ManualAuthDeviceRequest = Deserialize<ManualAuthDeviceRequest>(device);
                //var t2=m_ManualAuthDeviceRequest.tag2.ToString(16, 2);

                var memoryStream = Serialize(m_ManualAuthDeviceRequest);

                body = body.Concat(cdata).ToArray();

                body = body.Concat(compress_aes(device, AESKey.ToByteArray(16, 2))).ToArray();
                //var head = MakeHead( body, MM.CGI_TYPE.CGI_TYPE_MANUALAUTH, 7);
                var head = MakeRSAHead((int)CGI_TYPE.CGI_TYPE_MANUALAUTH, body.Length, 7, false);

                head = head.Concat(body).ToArray();


                //var ret = HttpPost(@short + MM.URL.CGI_MANUALAUTH, head, null);
                //var lhead = LongLinkPack(LongLinkCmdId.SEND_MANUALAUTH_CMDID, seq++, head.Length);
                //body = lhead.Concat(head).ToArray();
                return head;
            }
            else
                return null;
        }
        public bool SendNewMsg(string to,string content)
        {
            byte[] Msg = "080112270a0c0a0a66696c6568656c706572120454797975180120a686f9d7052884ed87fbfaffffffff01".ToByteArray(16, 2);
            var asd = new byte[] { };
            var sda = ProtoBuf.Serializer.Deserialize<NewSendMsgRequest>(new MemoryStream(Msg));
            byte[] apc = new byte[] { };
           
            sda.info.clientMsgId = (ulong)CurrentTime_();
            sda.info.toid.@string = to;
            sda.info.content = content;
            sda.info.utc = CurrentTime_();
         
            MemoryStream memoryStream = new MemoryStream();
            ProtoBuf.Serializer.Serialize(memoryStream, sda);

            var body=LongLinkPack(LongLinkCmdId.NEWSENDMSG,CGI_TYPE.CGI_TYPE_NEWSENDMSG, memoryStream.ToArray());
            return  m_client.Send(body, body.Length);
        }
        #endregion
    }
}
