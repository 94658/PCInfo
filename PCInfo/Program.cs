using System;
using System.Net;
using System.Management;
using System.IO;
using System.Net.NetworkInformation;
using System.Text;
using System.Collections.Generic;
using System.Net.Sockets;

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
                ostrm = new FileStream(@"\\172.16.2.7\craft-silicon-local$\Dumps\" + System.Environment.MachineName + " - " + GetIPAddress() + ".txt", FileMode.OpenOrCreate, FileAccess.Write);
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
            
            System.Environment.Exit(0);
        }

        //Display IP Addresses of the PC
        private static string GetIPAddress()
        {

            
             List<string> IP = new List<string>();
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if ((ni.OperationalStatus == OperationalStatus.Up)
                        && (ip.Address.AddressFamily == AddressFamily.InterNetwork) && (!ni.Description.ToString().Contains("Virtual")) && (!ni.Description.ToString().Contains("Loopback")) && (ip.Address.ToString().Contains("172.")))
                        {
                            IP.Add(ip.Address.ToString());
                        }
                    }

                


            }

            return string.Join(",", IP.ToArray());
        }

       
    }
}