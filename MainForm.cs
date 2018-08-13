using CRYPT;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using static MMPro.MM;

namespace LongLinkIOS
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();
        }
        MMClient mMClient = null;
        private void Form1_Load(object sender, EventArgs e)
        {
            mMClient = new MMClient();
            mMClient.deviceID = "49aa7db2f4a3ffe0e96218f6b92cde32".ToByteArray(16, 2);
            Console.WriteLine(ChangeType.ToHexString(mMClient.deviceID));
        }
  
        void CheckLoginQRCodeCallBack(CheckLoginQRCodeResponse o)
        {
            if (o.baseResponse.ret == 0)
            {
                var asd = o.data.notifyData.buffer.ToString(16, 2);
                var __ = mMClient.nouncompress_aes(o.data.notifyData.buffer, key);
                var r = mMClient.Deserialize<LoginQRCodeNotify>(__);
              
                if (r.headImgUrl != null)
                    pictureBox1.Load(r.headImgUrl);
           
                textBox1.Invoke(new Action( () => textBox1.Text = "剩余时间:  " + r.EffectiveTime.ToString()));
                if (r.wxnewpass != null && r.wxnewpass != "")
                {
                    mMClient.ManualAuth(r.wxnewpass,r.wxid);

                }
                System.Threading.Thread.Sleep(1000);
                if (r.state==1 || r.state==0)
                {
                    if (r.EffectiveTime > 0)
                    {

                        mMClient.CheckLoginQRCode(uuid, CheckLoginQRCodeCallBack);
                    }
                }
                

            }
        }
        void ManualAuthCallBack(mm.command.NewAuthResponse message)
        {
            
            if (message.Base.Ret ==- 301)
            {
                var dns = message.Server.NewHostList;
                if (dns.ListList.Count > 0)
                {

                    string ip = dns.ListList[0].Substitute;
                  
                    mMClient.shortLink ="http://"+ dns.ListList[1].Substitute;
                    Console.WriteLine("shortLink:" + mMClient.shortLink + "\n");
                    mMClient. ReConnect(ip);
                    mMClient.CheckLoginQRCode(uuid, CheckLoginQRCodeCallBack);
                }
            }
            else if (message.Base.Ret == 0)
            {
             
  
                byte[] strECServrPubKey = message.Auth.SvrPubECDHKey.Key.Buffer.ToByteArray();
                var aesKey = MyFuckSSL.SharkEcdhKey(strECServrPubKey, mMClient.pri_key_buf);
                mMClient.CheckEcdh = aesKey.ToString(16, 2);
                mMClient.AESKey = AES.AESDecrypt(message.Auth.SessionKey.Buffer.ToByteArray(), aesKey).ToString(16, 2);
                mMClient.wxid = message.User.UserName;
                Console.WriteLine("当前微信号:" + mMClient.wxid+"\n");
                mMClient.uin = message.Auth.Uin;
                Console.WriteLine("uin:" + mMClient.uin + "\n");
                mMClient.cookie = mMClient.getcookie();

                mMClient.deviceID = "49aa7db2f4a3ffe0e96218f6b92cde32".ToByteArray(16,2);
                Console.WriteLine(ChangeType.ToHexString(mMClient.deviceID));
                mMClient.devicetype = "iPad iPhone OS8.4";
                ShortChanle.NewInit(mMClient);




            }
        }
        byte[] key = new byte[] { };
        string uuid = "";

        public void pushShortInit()
        {
            ShortChanle.NewInit(mMClient);
        }
        private void button1_Click(object sender, EventArgs e)
        {
            mMClient.SetManualAuthCallBack(ManualAuthCallBack);
            mMClient.GetLoginQRCode((GetLoginQRCodeResponse message) => {
                uuid = message.uuid;
                key = message.AESKey.key;
                if (message.baseResponse.ret == 0)
                {
                    Bitmap bitmap = new Bitmap(new MemoryStream(message.qRCode.src));
                    pictureBox1.Image = bitmap;
            
                    mMClient.CheckLoginQRCode(uuid, CheckLoginQRCodeCallBack);
                    
           
                }
         
            });
        }

        private void button2_Click(object sender, EventArgs e)
        {
            mMClient.SendNewMsg("filehelper","ipad消息");
        }

        private void buttonX1_Click(object sender, EventArgs e)
        {

            /*
            mMClient.SetManualAuthCallBack(ManualAuthCallBack);
            mMClient.GetLoginQRCode((GetLoginQRCodeResponse message) => {
                uuid = message.uuid;
                key = message.AESKey.key;
                if (message.baseResponse.ret == 0)
                {
                    Bitmap bitmap = new Bitmap(new MemoryStream(message.qRCode.src));
                    pictureBox1.Image = bitmap;

                    mMClient.CheckLoginQRCode(uuid, CheckLoginQRCodeCallBack);


                }

            });*/
          //  byte[] key = new byte[] { };
          //  string uuid = "";

            //ystem.Threading.Thread getqr = new System.Threading.Thread();
            Thread getqrcode = new Thread(threadqrcode);
            getqrcode.Start();
        }
        public void threadqrcode()
        {
           var bProtobuf =  ShortChanle.GetLoginQRCode(mMClient);
            Console.WriteLine(ChangeType.ToHexString(bProtobuf));

            MMPro.MM.GetLoginQRCodeResponse getLoginQRCodeResponse = mMClient.Deserialize<GetLoginQRCodeResponse>(bProtobuf);
            //mm.command.GetLoginQRCodeResponse pb = mm.command.GetLoginQRCodeResponse.ParseFrom(bProtobuf);
           
            Bitmap bitmap = new Bitmap(new MemoryStream(getLoginQRCodeResponse.qRCode.src));
    
            ShortQRcode.Image = bitmap;

        }

        private void LongLinkc_Click(object sender, EventArgs e)
        {
            mMClient.BeginLongLink();

        }

        private void button3_Click(object sender, EventArgs e)
        {
            Console.WriteLine("InTaTal--->>>>{0} \n",64353);
//
        }

        private void button4_Click(object sender, EventArgs e)
        {
           // byte[] fb = mMClient.NewSyncEcode();
          
          
           
   
        }

        private void button5_Click(object sender, EventArgs e)
        {

        }
    }
}
