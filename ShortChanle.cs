using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;
using System.IO;
using Google.ProtocolBuffers;
using mm.command;
namespace LongLinkIOS
{
    class ShortChanle
    {
        public static void WeChatPost(string url, byte[] packet, ref byte[] recvPack)
        {

            HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(url);

            httpWebRequest.ContentType = "application/octet-stream";
            httpWebRequest.UserAgent = "MicroMessenger Client";

            httpWebRequest.Method = "POST";
            httpWebRequest.Timeout = 5000;  //5000

            httpWebRequest.ContentLength = packet.Length;
            httpWebRequest.GetRequestStream().Write(packet, 0, packet.Length);

            HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            string cl = httpWebResponse.Headers["Content-Length"];
            int conLen = int.Parse(cl);

            Stream streamReader = httpWebResponse.GetResponseStream();
            recvPack = new byte[conLen];

            int readed = streamReader.Read(recvPack, 0, conLen);


            streamReader.Close();
            httpWebRequest.Abort();
            httpWebResponse.Close();
        }


        public static  byte[] GetLoginQRCode(MMClient mm)
        {


            mm.AESKey = (new Random()).NextBytes(16).ToString(16, 2);
            Console.WriteLine("随机AESKEY:" + ChangeType.ToHexString(mm.AESKey.ToByteArray(16, 2)));
            GetLoginQRCodeRequest.Builder qrcode = new GetLoginQRCodeRequest.Builder();
            SKBuiltinBuffer_t.Builder aes = new SKBuiltinBuffer_t.Builder();
            //GetLoginQRCodeRequest getLoginQRCodeRequest = new GetLoginQRCodeRequest()


            aes.SetBuffer(ByteString.CopyFrom(mm.AESKey.ToByteArray(16, 2)));
            aes.SetILen(16);
            SKBuiltinBuffer_t randomAes = aes.Build();
            byte[] session = new byte[0];
            qrcode.SetBase(GetBasePack(session, 0, 0));
            qrcode.SetOpcode(0);
            qrcode.SetDeviceName("daivis.IPAD");

            qrcode.SetRandomEncryKey(randomAes);
            GetLoginQRCodeRequest pack = qrcode.Build();

            Console.WriteLine( pack.ToString());
            var src = pack.ToByteArray();
            int bufferlen = src.Length;
            


            var senddata = mm.ShortLinkPack(MMPro.MM.CGI_TYPE.CGI_TYPE_GETLOGINQRCODE, src, 1);
            byte[] retbuf = null;
            WeChatPost(mm.shortLink + "/cgi-bin/micromsg-bin/getloginqrcode", senddata, ref retbuf);

            Console.WriteLine(ChangeType.ToHexString(retbuf));

            return mm.shortUnPack(retbuf);
        }

        public static void NewInit(MMClient mm)
        {

            NewInitRequest.Builder init = new NewInitRequest.Builder();
            byte[] sessionKey = mm.AESKey.ToByteArray(16,2);




            SKBuiltinBuffer_t.Builder Bmaxsync = new SKBuiltinBuffer_t.Builder();
            Bmaxsync.SetBuffer(ByteString.CopyFrom(new byte[0]));
            Bmaxsync.SetILen(0);
            SKBuiltinBuffer_t maxsynckey = Bmaxsync.Build();
            SKBuiltinBuffer_t.Builder sync = new SKBuiltinBuffer_t.Builder();
            sync.SetBuffer(ByteString.CopyFrom(new byte[0]));
            sync.SetILen(0);
            SKBuiltinBuffer_t synckey = sync.Build();

            BaseRequest bBase = GetBasePack(sessionKey, mm.uin, 3);
            init.SetBase(bBase);
            init.SetLanguage("zh_CN");
            init.SetUserName(mm.wxid);
            init.SetMaxSynckey(maxsynckey);
            init.SetCurrentSynckey(synckey);
            NewInitRequest initPack = init.Build();

           // byte[] buf = initPack.ToByteArray();
           // Console.WriteLine(initPack.ToString());
            // byte[]senddata =  mm.ShortLinkPack((MMPro.MM.CGI_TYPE)139, buf);
           // IntPtr AESpushstr = IntPtr.Zero;
           // byte[]afterC =  MyFuckSSL.AesEncodeComprese(buf, buf.Length, sessionKey, AESpushstr);
         //   IntPtr pushstr = IntPtr.Zero;
           // byte[]head = MyFuckSSL.AesHeader((int)mm.uin, mm.cookie, mm.cookie.Length, 139, buf.Length, afterC.Length,pushstr);
         //   var senddata = head.Concat(afterC).ToArray();
            byte[]  senddata = null;
            senddata = mm.MakeAESHead(initPack.ToByteArray(), (MMPro.MM.CGI_TYPE)139);
            ChangeType.Add4Bytes(ref senddata,initPack.ToByteArray());
            Console.WriteLine(ChangeType.ToHexString(senddata));
            byte[] retbuf = null;
            WeChatPost(mm.shortLink + "/cgi-bin/micromsg-bin/newinit", senddata, ref retbuf);
            Console.WriteLine("初始化包已发送");
            Console.WriteLine(ChangeType.ToHexString(retbuf));
        }
        //初始化首次登陆

        public static byte[] MsgSync(byte[]pack)
        {
            byte[] retbuf = null;
            WeChatPost("http://short.weixin.qq.com/cgi-bin/micromsg-bin/newsync", pack, ref retbuf);
            return retbuf;
        }
        public static BaseRequest GetBasePack(byte[] sessionKey, long uin = 0, int Scene=0)
        {
            BaseRequest.Builder pack = new BaseRequest.Builder();        
            byte[] deviceid = "49aa7db2f4a3ffe0e96218f6b92cde32".ToByteArray(16, 2);          
            pack.SetDeviceID(ByteString.CopyFrom(deviceid));
            pack.SetDeviceType(ByteString.CopyFromUtf8("iPad iPhone OS8.4"));
            pack.SetScene(Scene);
            pack.SetSessionKey(ByteString.CopyFrom(sessionKey));
            Console.WriteLine(uin);
            Console.WriteLine((uint)uin);
            pack.SetUin((uint)uin);
            pack.SetClientVersion(0x16070124);
            return pack.Build();
        }

    }
}
