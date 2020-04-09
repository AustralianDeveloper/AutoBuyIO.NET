using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace AutoBuyIO.NET
{
    class Program
    {
        /// <summary>
        /// Simple AutoBuy.IO test program using RestSharp, Newtonsoft.JSON and Costura.
        /// Authenticates license keys and HWID without API key needed.
        /// Saves and reads key from registry.
        /// PLEASE obfuscate your program or I will be coming to crack it!
        /// </summary>

        // Get these two below at https://autobuy.io/Licensing/STORENAME/Projects
        static string projectID = "00000000-0000-0000-0000-000000000000";
        static string projectName = "Test Product";

        static void Main(string[] args)
        {
            // Set Console Title.
            Console.Title = projectName;

            // Draw Logo.
            DrawLogo();

            // Create Registry Key.
            RegistryKey key = Registry.CurrentUser.CreateSubKey($"SOFTWARE\\{projectName}", true);
            if (key.GetValueNames().Contains("License Key"))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(" Reading saved license key.");
                if (AuthKey(Encoding.UTF8.GetString(Convert.FromBase64String((string)key.GetValue("License Key")))) == false)
                {
                    goto License;
                }
                else
                {
                    goto Menu;
                }
            }

        // Request License Key.
        License:
            Thread.Sleep(1000);
            Console.Clear();
            DrawLogo();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write(" License Key » ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            if (AuthKey(Console.ReadLine()) == false)
                goto License;
            else
                goto Menu;

        // Licensing done.
        // Main Menu
        Menu:
            Thread.Sleep(1000);
            Console.Clear();
            DrawLogo();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($" {projectName} has been authenticated.");
            Console.ReadLine();
        }

        // Centre Text in Console
        static string CentreText(string text)
        {
            return string.Format("{0," + ((Console.WindowWidth / 2) + (text.Length / 2)) + "}", text);
        }

        // Authenticate License Key and Hardware ID.
        static bool AuthKey(string licenseKey)
        {
            // Check if key is in correct format.
            if (!Regex.IsMatch(licenseKey, @"^[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}$"))
            {
                // Random sleep is to discourage bruteforcing.
                Thread.Sleep(2000 - new Random().Next(1000));
                Console.WriteLine(" Your key does not exist!");
                return false;
            }

            // Get response from AutoBuy.io API.
            string response = "";
            try
            {
                var client = new RestClient("https://autobuy.io/api/Licensing");
                client.Timeout = 5000; // 5 second timeout.
                var request = new RestRequest(Method.GET);
                request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                request.AddParameter("id", licenseKey);
                response = Convert.ToString(client.Execute(request).Content);
            }
            catch
            {
                Console.WriteLine(" This should not have happened at all, but your internet could be slow.\n Tell the developer to fix this.");
                return false;
            }

            try
            {
                Console.ForegroundColor = ConsoleColor.Red;

                // Open reg key with write access.
                RegistryKey key = Registry.CurrentUser.OpenSubKey($"SOFTWARE\\{projectName}", true);

                // Check if response is valid JSON.
                if (!IsValidJSON(response))
                {
                    Console.WriteLine(" Your key does not exist, or some really fucked up error occured on the backend.");
                    if (key.GetValueNames().Contains(projectName))
                    {
                        key.DeleteValue(projectName);
                    }
                    return false;
                }

                // Deserialise JSON response to dictionary.
                var keyDict = JsonConvert.DeserializeObject<Dictionary<string, string>>(response);

                // Check if entered license key matches the one in response (this error should NOT happen but it could be a tell-tale of packet tampering).
                if (keyDict["Id"] != licenseKey)
                {
                    Console.WriteLine(" This should not have happened at all.\nTell the developer to fix this.");
                    if (key.GetValueNames().Contains(projectName))
                    {
                        key.DeleteValue(projectName);
                    }
                    return false;
                }

                // Check if key matches project (remember the API URI's we can use without AutoBuy.io API key, so it is public.
                // Therefore, we must check key because a skid could make a key for his own project and try authenticate this one.
                if ((Convert.ToString(keyDict["ProjectName"]) != projectName) || (Convert.ToString(keyDict["ProjectId"]) != projectID))
                {
                    Console.WriteLine($" Your key isn't for {projectName}!");
                    if (key.GetValueNames().Contains(projectName))
                    {
                        key.DeleteValue(projectName);
                    }
                    return false;
                }

                // Check if key is banned.
                if (Convert.ToBoolean(keyDict["IsBan"]) == true)
                {
                    Console.WriteLine($" Your key for {keyDict["ProjectName"]} is banned!\n Ban Reason: {keyDict["BanReason"]}.");
                    if (key.GetValueNames().Contains(projectName))
                    {
                        key.DeleteValue(projectName);
                    }
                    return false;
                }

                // Check if HWID is matching (if HWID is not set to key yet, it will set it and return true to authenticate key).
                if (CheckHWID(licenseKey) == false)
                {
                    Console.WriteLine($" Your HWID for {keyDict["ProjectName"]} doesn't match!");
                    if (key.GetValueNames().Contains(projectName))
                    {
                        key.DeleteValue(projectName);
                    }
                    return false;
                }

                // Check if key has expired.
                // There are a lot more secure ways of doing this, someone can simply wind their system clock back/
                if (Convert.ToInt32(ConvertToUnixTime(Convert.ToDateTime(keyDict["TimeExpired"]))) <= (int)DateTime.Now.Subtract(new DateTime(1970, 1, 1)).TotalSeconds)
                {
                    Console.WriteLine($" Your key for {keyDict["ProjectName"]} has expired!");
                    if (key.GetValueNames().Contains(projectName))
                    {
                        key.DeleteValue(projectName);
                    }
                    return false;
                }
                
                // Key is correct.
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($" Your license key is correct, and you may now use {projectName}!");

                key.SetValue("License Key", Convert.ToBase64String(Encoding.UTF8.GetBytes(licenseKey)));
                key.Close();

                return true;
            }
            catch
            {
                return false;
            }
        }

        // Check HWID.
        static bool CheckHWID(string licenseKey)
        {
            var client = new RestClient("https://autobuy.io/api/Licensing/VerifyHardwareId");
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
            request.AddParameter("Id", licenseKey);
            request.AddParameter("HardwareId", GetHWID());
            string response = Convert.ToString(client.Execute(request).Content).Replace("\"", ""); // Quotes in response :/

            if (response == "Hardware Id does not match!")
            {
                return false;
            }
            else
            {
                if (response == "Hardware Id set!")
                {
                    return true;
                }
                else if (response == "Hardware Id Verified!")
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        // Get HWID (do this however you like).
        static string GetHWID()
        {
            return Environment.UserName;
        }

        // Check JSON is valid.
        public static bool IsValidJSON(string json)
        {
            try
            {
                JToken token = JObject.Parse(json);
                return true;
            }
            catch
            {
                return false;
            }
        }

        // Convert time to Unix Timestamp. https://yomotherboard.com/convert-c-datetime-object-unix-timestamp/
        public static long ConvertToUnixTime(DateTime datetime)
        {
            DateTime sTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            return (long)(datetime - sTime).TotalSeconds;
        }

        // Draw Logo.
        public static void DrawLogo()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine(CentreText(" █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ██╗   ██╗██╗   ██╗██╗ ██████╗ "));
            Console.WriteLine(CentreText("██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██║   ██║╚██╗ ██╔╝██║██╔═══██╗"));
            Console.WriteLine(CentreText("███████║██║   ██║   ██║   ██║   ██║██████╔╝██║   ██║ ╚████╔╝ ██║██║   ██║"));
            Console.WriteLine(CentreText("██╔══██║██║   ██║   ██║   ██║   ██║██╔══██╗██║   ██║  ╚██╔╝  ██║██║   ██║"));
            Console.WriteLine(CentreText("██║  ██║╚██████╔╝   ██║   ╚██████╔╝██████╔╝╚██████╔╝   ██║██╗██║╚██████╔╝"));
            Console.WriteLine(CentreText("╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝╚═╝╚═╝ ╚═════╝ "));
            Console.WriteLine(CentreText($"Project: {projectName}"));
            Console.WriteLine();
        }
    }
}
