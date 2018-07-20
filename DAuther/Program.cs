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
            string ChallengeData1 = MakeReq(ChallengeURL, Encoding.UTF8.GetBytes(Challenge), 16);
            JObject ParseJSON1 = JObject.Parse(ChallengeData1);
            string ParseChallenge1 = ParseJSON1["challenge"].ToString();

            byte[] KeySource = Convert.FromBase64String(ParseJSON1["data"].ToString());

            byte[] KEK = GenerateAESKek(MasterKey, AESUseSrc, DAuth_KEK, KeySource);

            string ChallengeData2 = MakeReq(ChallengeURL, Encoding.UTF8.GetBytes(Challenge), 16);
            JObject ParseJSON2 = JObject.Parse(ChallengeData1);
            string ParseChallenge2 = ParseJSON1["challenge"].ToString();

            System.Threading.Thread.Sleep(50);

            string BaseRequest1 = BuildFirstRequestString(ParseChallenge1);
            string CMAC1 = GenerateCMACOfRequestString(KEK, BaseRequest1);
            byte[] PostFinal1 = PostAuthToken(BaseRequest1, CMAC1);
            string FinalReq1 = MakeReq(DeviceAuthTokenURL, PostFinal1, 200);
            JObject ParseFinal1 = JObject.Parse(FinalReq1);
            try
            {
                Console.WriteLine("Auth token: " + ParseFinal1["device_auth_token"].ToString());
                Console.WriteLine("Expires at: " + DateTime.Now.AddSeconds(Convert.ToDouble(ParseFinal1["expires_in"].ToString())));
                System.IO.File.WriteAllText("device_auth_token_" + Client_ID[0] + ".txt", ParseFinal1["device_auth_token"].ToString());
                Console.WriteLine("Your first token was successfully saved!");
            }
            catch (Exception)
            {
                try
                {
                    Console.WriteLine("Error " + ParseFinal1["errors"][0]["code"].ToString() + ":");
                    Console.WriteLine(ParseFinal1["errors"][0]["message"].ToString());
                }
                catch(Exception)
                {
                    Console.WriteLine(FinalReq1);
                }
            }

            string BaseRequest2 = BuildFirstRequestString(ParseChallenge2);
            string CMAC2 = GenerateCMACOfRequestString(KEK, BaseRequest2);
            byte[] PostFinal2 = PostAuthToken(BaseRequest2, CMAC2);
            string FinalReq2 = MakeReq(DeviceAuthTokenURL, PostFinal2, 200);
            JObject ParseFinal2 = JObject.Parse(FinalReq2);
            try
            {
                Console.WriteLine("Auth token: " + ParseFinal2["device_auth_token"].ToString());
                Console.WriteLine("Expires at: " + DateTime.Now.AddSeconds(Convert.ToDouble(ParseFinal2["expires_in"].ToString())));
                System.IO.File.WriteAllText("device_auth_token_" + Client_ID[1] + ".txt", ParseFinal2["device_auth_token"].ToString());
                Console.WriteLine("Your second token was successfully saved!");
            }
            catch (Exception)
            {
                try
                {
                    Console.WriteLine("Error " + ParseFinal2["errors"][0]["code"].ToString() + ":");
                    Console.WriteLine(ParseFinal2["errors"][0]["message"].ToString());
                }
                catch (Exception)
                {
                    Console.WriteLine(FinalReq2);
                }
            }
        }
    }
}