namespace DAuther
{
    using Newtonsoft.Json.Linq;
    using System;
    using static BuildStrings;
    class Program
    {
        static string ChallengeURL = "https://dauth-lp1.ndas.srv.nintendo.net/v3-59ed5fa1c25bb2aea8c4d73d74b919a94d89ed48d6865b728f63547943b17404/challenge";
        static string DeviceAuthTokenURL = "https://dauth-lp1.ndas.srv.nintendo.net/v3-59ed5fa1c25bb2aea8c4d73d74b919a94d89ed48d6865b728f63547943b17404/device_auth_token";
        static void Main()
        {
            string ChallengeData = MakeReq(ChallengeURL, PostChallenge());
            JObject ParseJSON = JObject.Parse(ChallengeData);
            string Challenge = ParseJSON["challenge"].ToString();
            byte[] EKS = Convert.FromBase64String(ParseJSON["data"].ToString());
            if (EKS[8] != DataSrc[8])
            {
                Console.WriteLine("Error: Keydata changed, please discontinue use of this program until this issue is rectified.");
                Console.WriteLine(BitConverter.ToString(EKS).Replace("-","") + " was returned, while hardcoded key is " + BitConverter.ToString(DataSrc).Replace("-", ""));
                Environment.Exit(0);
            }
            byte[] KEK = GenerateAESKek(MasterKey, AESUsecaseSeed, DAuth_KEK, EKS);
            string BaseRequest = BuildRequestString(Challenge);
            string CMAC = GenerateCMACOfRequestString(KEK, BaseRequest);
            byte[] PostFinal = PostAuthToken(BaseRequest, CMAC);
            string FinalReq = MakeReq(DeviceAuthTokenURL, PostFinal);
            Console.WriteLine(FinalReq);
        }
    }
}