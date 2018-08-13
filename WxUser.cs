using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static MMPro.MM;

namespace LongLinkIOS
{
    class WxUser
    {
        public struct fucker
        {
            public static device DeviceInfo;
            public static key keys;
            public static UserInfo Info;
            public static BaseRequest BasePack;

        }
        public struct device
        {
            public static string deviceId;
        }
        public struct key
        {
            public static byte[] ecPubKey;
            public static byte[] ecPriKey;
            public static byte[] ShakeKey;
            public static byte[] aeskey;
            public static byte[] sync_key_cur;
            public static byte[] sync_key_max;
            public static byte[] notifykey;
        }
        public struct UserInfo
        {
            public static string username;
            public static string password;
            public static int uin;
            public static string shortLink;
            public static string longLink;


        }
        public WxUser()
        {
          
            WxUser.UserInfo.longLink = "szlong.weixin.qq.com";
           
        }
    }
}
