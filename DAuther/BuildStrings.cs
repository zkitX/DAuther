using System.Security.Cryptography;
using System;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.IO;

namespace DAuther
{
    class BuildStrings
    {
        public static byte[] MasterKey = { 0xCF, 0xA2, 0x17, 0x67, 0x90, 0xA5, 0x3F, 0xF7, 0x49, 0x74, 0xBF, 0xF2, 0xAF, 0x18, 0x09, 0x21 };
        public static byte[] AESUsecaseSeed = { 0x4D, 0x87, 0x09, 0x86, 0xC4, 0x5D, 0x20, 0x72, 0x2F, 0xBA, 0x10, 0x53, 0xDA, 0x92, 0xE8, 0xA9 };
        public static byte[] DAuth_KEK = { 0x8B, 0xE4, 0x5A, 0xBC, 0xF9, 0x87, 0x02, 0x15, 0x23, 0xCA, 0x4F, 0x5E, 0x23, 0x00, 0xDB, 0xF0 };
        public static byte[] DataSrc = { 0xDE, 0xD2, 0x4C, 0x35, 0xA5, 0xD8, 0xC0, 0xD7, 0x6C, 0xB8, 0xD7, 0x8C, 0xA0, 0xA5, 0xA5, 0x22 };
        public static bool AcceptAllCertifications(object Input, X509Certificate Cert, X509Chain Chain, System.Net.Security.SslPolicyErrors Err)
        {
            return true;
        }
        public static string MakeReq(string URL, byte[] PostData)
        {
            try
            {
                ServicePointManager.ServerCertificateValidationCallback = AcceptAllCertifications;
                X509Certificate2 Cert = new X509Certificate2("nx_tls_client_cert.pfx", "switch");
                HttpWebRequest Request = (HttpWebRequest)WebRequest.Create(URL);
                Request.ClientCertificates.Add(Cert);
                Request.UserAgent = "libcurl (nnDauth; 789f928b-138e-4b2f-afeb-1acae821d897; SDK 5.3.0.0; Add-on 5.3.0.0)";
                Request.Accept = "*/*";
                Request.Method = "POST";
                Stream DataStream = Request.GetRequestStream();
                DataStream.Write(PostData, 0, PostData.Length);
                DataStream.Close();
                WebResponse Response = Request.GetResponse();
                DataStream = Response.GetResponseStream();
                StreamReader Reader = new StreamReader(DataStream);
                string ResponseContent = Reader.ReadToEnd();
                return ResponseContent;
            }
            catch (WebException ex) {
                var resp = new StreamReader(ex.Response.GetResponseStream()).ReadToEnd();
                return resp;
            }
        }
        public static byte[] Decrypt(byte[] Data, byte[] Key)
        {
            RijndaelManaged Unwrap = new RijndaelManaged();
            Unwrap.Mode = CipherMode.ECB;
            Unwrap.Key = Key;
            Unwrap.Padding = PaddingMode.None;
            var Decrypt = Unwrap.CreateDecryptor();
            byte[] output = Decrypt.TransformFinalBlock(Data,0,16);
            return output;
        }
        public static byte[] GenerateAESKek(byte[] MasterKey, byte[] AESUsecaseSeed, byte[] DAuth_KEK, byte[] KEKEK)
        {
            byte[] GenAESKey = Decrypt(AESUsecaseSeed, MasterKey);
            byte[] FirstKEK = Decrypt(DAuth_KEK, GenAESKey);
            byte[] Final = Decrypt(KEKEK, FirstKEK);
            return Final;
        }
        public static byte[] PostChallenge()
        {
            string Data = "key_generation=5";
            return Encoding.UTF8.GetBytes(Data);
        }
        public static string BuildRequestString(string Challenge)
        {
            string Data = "challenge=" + Challenge + "&client_id=93af0acb26258de9&key_generation=5&system_version=gW93A#00050100#29uVhARHOdeTZmfdPnP785egrfRbPUW5n3IAACuHoPw=";
            return Data;
        }
        public static string GenerateCMACOfRequestString(byte[] Key, string RequestData)
        {
            byte[] CMAC = GenAESCMAC.AESCMAC(Key, Encoding.UTF8.GetBytes(RequestData));
            string base64 = System.Convert.ToBase64String(CMAC).Replace('+', '-').Replace('/', '_').Replace("=","");
            return base64;
        }
        public static byte[] PostAuthToken(string Data, string MAC)
        {
            string BuildMAC = Data + "&mac=" + MAC;
            byte[] byteArray = Encoding.UTF8.GetBytes(BuildMAC);
            return byteArray;
        }
    }
}
