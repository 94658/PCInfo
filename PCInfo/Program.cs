using System;
using System.Net;
using System.Management;
using System.IO;
using System.Net.NetworkInformation;
using System.Text;
using System.Collections.Generic;

namespace PCInfo
{
    class Program
    {

        

        static void Main(string[] args)
        {

            BasicInfo basic = new BasicInfo();


            FileStream ostrm;
            StreamWriter writer;
            TextWriter oldOut = Console.Out;
            


            try
            {
                ostrm = new FileStream("./" + System.Environment.MachineName + " - " + GetIPAddress() + ".txt", FileMode.OpenOrCreate, FileAccess.Write);
                writer = new StreamWriter(ostrm);
            }
            catch (Exception e)
            {
                Console.WriteLine("Cannot open Redirect.txt for writing");
                Console.WriteLine(e.Message);
                return;
            }
            Console.SetOut(writer);
            basic.displayInfo();
            Console.SetOut(oldOut);
            writer.Close();
            ostrm.Close();
            ///---
            ///
            // System.IO.FileStream fs = new System.IO.FileStream(@"C:\Desktop\Output.txt", System.IO.FileMode.Create);
            //System.IO.StreamWriter sw = new System.IO.StreamWriter(fs);
            //System.Console.SetOut(sw);

            Console.ReadKey();
        }

        private static string GetIPAddress()

        {

            List<string> IP = new List<string>();
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                {
                    
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                           IP.Add(ip.Address.ToString());
                        }
                    }
                }
               
            }

            return string.Join(",",IP.ToArray());

        }

    }
}