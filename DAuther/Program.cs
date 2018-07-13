namespace DAuther
{
    using Newtonsoft.Json.Linq;
    using System;
    using System.Text;
    using static BuildStrings;
    class Program
    {
        static string ChallengeURL = "https://dauth-lp1.ndas.srv.nintendo.net/v3-59ed5fa1c25bb2aea8c4d73d74b919a94d89ed48d6865b728f63547943b17404/challenge";
        static string DeviceAuthTokenURL = "https://dauth-lp1.ndas.srv.nintendo.net/v3-59ed5fa1c25bb2aea8c4d73d74b919a94d89ed48d6865b728f63547943b17404/device_auth_token";
        static void Main()
        {
            string ChallengeData = MakeReq(ChallengeURL, Encoding.UTF8.GetBytes(Challenge));
            JObject ParseJSON = JObject.Parse(ChallengeData);
            string ParseChallenge = ParseJSON["challenge"].ToString();
            byte[] EKS = Convert.FromBase64String(ParseJSON["data"].ToString());
            if (EKS[8] != DAuth_Src[8])
            {
                Console.WriteLine("Error: Keydata changed, please discontinue use of this program until this issue is rectified.");
                Console.WriteLine(BitConverter.ToString(EKS).Replace("-","") + " was returned, while hardcoded key is " + BitConverter.ToString(DAuth_Src).Replace("-", ""));
                Environment.Exit(0);
            }
            byte[] KEK = GenerateAESKek(MasterKey, AESUseSrc, DAuth_KEK, EKS);
            string BaseRequest = BuildRequestString(ParseChallenge);
            string CMAC = GenerateCMACOfRequestString(KEK, BaseRequest);
            byte[] PostFinal = PostAuthToken(BaseRequest, CMAC);
            string FinalReq = MakeReq(DeviceAuthTokenURL, PostFinal);
            JObject ParseFinal = JObject.Parse(FinalReq);
            try
            {
                Console.WriteLine("Auth token: " + ParseFinal["device_auth_token"].ToString());
                Console.WriteLine("Expires at: " + DateTime.Now.AddSeconds(Convert.ToDouble(ParseFinal["expires_in"].ToString())));
                System.IO.File.WriteAllText("device_auth_token.txt", ParseFinal["device_auth_token"].ToString());
                Console.WriteLine("Your token was successfully saved to \"device_auth_token.txt\"!");
            }
            catch (Exception)
            {
                try
                {
                    Console.WriteLine("Error " + ParseFinal["errors"][0]["code"].ToString() + ":");
                    Console.WriteLine(ParseFinal["errors"][0]["message"].ToString());
                }
                catch(Exception)
                {
                    Console.WriteLine(FinalReq);
                }
            }          
        }
    }
}