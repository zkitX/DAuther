using System.Security.Cryptography;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.IO;
using System;

namespace DAuther
{
    class BuildStrings
    {
        public static string URLSafe(string Str)
        {
            return Str.Replace("+", "-").Replace("/", "_").Replace("=", "");
        }
        public static byte[] MasterKey = { 0xCF, 0xA2, 0x17, 0x67, 0x90, 0xA5, 0x3F, 0xF7, 0x49, 0x74, 0xBF, 0xF2, 0xAF, 0x18, 0x09, 0x21 };
        public static byte[] AESUseSrc = { 0x4D, 0x87, 0x09, 0x86, 0xC4, 0x5D, 0x20, 0x72, 0x2F, 0xBA, 0x10, 0x53, 0xDA, 0x92, 0xE8, 0xA9 };
        public static byte[] DAuth_KEK = { 0x8B, 0xE4, 0x5A, 0xBC, 0xF9, 0x87, 0x02, 0x15, 0x23, 0xCA, 0x4F, 0x5E, 0x23, 0x00, 0xDB, 0xF0 };
        public static byte[] DAuth_Src = { 0xDE, 0xD2, 0x4C, 0x35, 0xA5, 0xD8, 0xC0, 0xD7, 0x6C, 0xB8, 0xD7, 0x8C, 0xA0, 0xA5, 0xA5, 0x22 };
        public static string[] Client_ID =
        {
        "93af0acb26258de9",
        "81333c548b2e876d"
        };
        public static string UserAgent = string.Format("libcurl (nnDauth; {0}; SDK {1}.{2}.{3}.{4}; Add-on {1}.{2}.{3}.{4})", "789f928b-138e-4b2f-afeb-1acae821d897", 5, 3, 0, 0);
        public static string Challenge = string.Format("key_generation={0}", 5);
        public static string SysDigest = "gW93A#00050100#29uVhARHOdeTZmfdPnP785egrfRbPUW5n3IAACuHoPw=";
        public static X509Certificate2 Cert = new X509Certificate2("nx_tls_client_cert.pfx", "switch");
        public static bool AcceptAllCertifications(object Input, X509Certificate Cert, X509Chain Chain, System.Net.Security.SslPolicyErrors Err)
        {
            return true;
        }
        public static string MakeReq(string URL, byte[] PostData, int ContentLength)
        {
            try
            {
                ServicePointManager.ServerCertificateValidationCallback = AcceptAllCertifications;
                HttpWebRequest Request = (HttpWebRequest)WebRequest.Create(URL);
                Request.ClientCertificates.Add(Cert);
                Request.Host = "dauth-lp1.ndas.srv.nintendo.net";
                Request.UserAgent = UserAgent;
                Request.Accept = "*/*";
                Request.ContentLength = ContentLength;
                Request.ContentType = "application/x-www-form-urlencoded";
                Request.Method = "POST";
                Stream DataStream = Request.GetRequestStream();
                DataStream.Write(PostData, 0, PostData.Length);
                DataStream.Close();
                WebResponse Response = Request.GetResponse();
                StreamReader Reader = new StreamReader(Response.GetResponseStream());
                return Reader.ReadToEnd();
            }
            catch (WebException Ex) {
                var ErrorBody = new StreamReader(Ex.Response.GetResponseStream()).ReadToEnd();
                return ErrorBody;
            }
        }
        public static byte[] Decrypt(byte[] Data, byte[] Key)
        {
            RijndaelManaged Unwrap = new RijndaelManaged
            {
                Mode = CipherMode.ECB,
                Key = Key,
                Padding = PaddingMode.None
            };
            var Decrypt = Unwrap.CreateDecryptor();
            byte[] Out = Decrypt.TransformFinalBlock(Data,0,16);
            return Out;
        }
        public static byte[] GenerateAESKek(byte[] MasterKey, byte[] AESUseSrc, byte[] DAuth_KEK, byte[] DAuth_Src)
        {
            byte[] GenAESKey = Decrypt(AESUseSrc, MasterKey);
            byte[] GenAESKek = Decrypt(DAuth_KEK, GenAESKey);
            return Decrypt(DAuth_Src, GenAESKek);
        }
        public static string BuildFirstRequestString(string Challenge)
        {
            return string.Format("challenge={0}&client_id={1}&key_generation={2}&system_version={3}", Challenge, Client_ID[0], 5, SysDigest);
        }
        public static string BuildSecondRequestString(string Challenge)
        {
            return string.Format("challenge={0}&client_id={1}&key_generation={2}&system_version={3}", Challenge, Client_ID[1], 5, SysDigest);
        }
        public static string GenerateCMACOfRequestString(byte[] Key, string RequestData)
        {
            return URLSafe(Convert.ToBase64String(GenAESCMAC.AESCMAC(Key, Encoding.UTF8.GetBytes(RequestData))));
        }
        public static byte[] PostAuthToken(string Data, string MAC)
        {
            return Encoding.UTF8.GetBytes(string.Format("{0}&mac={1}", Data, MAC));
        }
    }
}
