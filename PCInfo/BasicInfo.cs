using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Management;
using System.Management.Automation;
using System.Collections.ObjectModel;
using System.IO;
using System.Net.NetworkInformation;
using Microsoft.Win32;

namespace PCInfo
{
    class BasicInfo
    {

        IPHostEntry host;


        public void displayInfo()
        {





            //Account information
            Console.WriteLine("---------------User Account Info--------------");
            Console.WriteLine("Machine Name {0}", System.Environment.MachineName);
            Console.WriteLine("Current User : {0}", System.Environment.UserName);
            Console.WriteLine("User Domain Name: {0}", System.Environment.UserDomainName);
            Console.WriteLine("User Domain: {0}", System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName);
            Console.WriteLine(" ");
            Console.WriteLine(" ");

            //OS info
            Console.WriteLine("-----------------OS INFO--------------------");
            Console.Write("OS Name:");
            Console.WriteLine(System.Environment.OSVersion.Platform);

            ManagementObjectSearcher myOperativeSystemObject = new ManagementObjectSearcher("select * from Win32_OperatingSystem");

            foreach (ManagementObject obj in myOperativeSystemObject.Get())
            {
                Console.WriteLine("Caption  -  " + obj["Caption"]);
                Console.WriteLine("WindowsDirectory -  " + obj["WindowsDirectory"]);
                Console.WriteLine("SystemDirectory  -  " + obj["SystemDirectory"]);
                Console.WriteLine("EncryptionLevel  -  " + obj["EncryptionLevel"]);
                Console.WriteLine("OSType  -  " + obj["OSType"]);

            }
            Console.Write("OS Version:");
            Console.WriteLine(System.Environment.OSVersion.Version);
            Console.WriteLine(System.Environment.OSVersion.VersionString);

            Console.WriteLine(" ");
            Console.WriteLine(" ");

            //Network Configuration Info
            Console.WriteLine("------------Network Information Configuration-----------------");
            string hostname = Dns.GetHostName();
            Console.Write("Host Name: ");
            Console.WriteLine(hostname);

            host = Dns.GetHostEntry(hostname);
            foreach (IPAddress ip in host.AddressList)
            {
                if (ip.AddressFamily.ToString() == "InterNetwork")
                {
                    string localIP = ip.ToString();
                    Console.Write("IP Address: ");
                    Console.WriteLine(localIP);

                }
            }

            Console.WriteLine(" ");
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                {
                    Console.Write(ni.Name + ":  ");
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            Console.WriteLine(ip.Address.ToString());
                        }
                    }
                }
            }

            Console.WriteLine(" ");
            Console.WriteLine(" ");

            //Hardware Details Info
            Console.WriteLine("-----------------Hardware Details Info--------------------");
            Console.WriteLine(" ");

            Console.WriteLine("----Memory Info----");
            ObjectQuery wql = new ObjectQuery("SELECT * FROM Win32_OperatingSystem");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wql);
            ManagementObjectCollection results = searcher.Get();

            double res;

            foreach (ManagementObject result in results)
            {
                res = Convert.ToDouble(result["TotalVisibleMemorySize"]);
                double fres = Math.Round((res / (1024 * 1024)), 2);
                Console.WriteLine("Total usable memory size: " + fres + "GB");
                Console.WriteLine("Total usable memory size: " + res + "KB");
            }



            Console.WriteLine(" ");


            Console.WriteLine("-----Processor Info------");
            ManagementObjectSearcher myProcessorObject = new ManagementObjectSearcher("select * from Win32_Processor");

            foreach (ManagementObject obj in myProcessorObject.Get())
            {
                Console.WriteLine("Name  -  " + obj["Name"]);
                Console.WriteLine("DeviceID  -  " + obj["DeviceID"]);
                Console.WriteLine("Manufacturer  -  " + obj["Manufacturer"]);
                Console.WriteLine("CurrentClockSpeed  -  " + obj["CurrentClockSpeed"]);
                Console.WriteLine("Caption  -  " + obj["Caption"]);
                Console.WriteLine("NumberOfCores  -  " + obj["NumberOfCores"]);
                Console.WriteLine("NumberOfEnabledCore  -  " + obj["NumberOfEnabledCore"]);
                Console.WriteLine("NumberOfLogicalProcessors  -  " + obj["NumberOfLogicalProcessors"]);
                Console.WriteLine("Architecture  -  " + obj["Architecture"]);
                Console.WriteLine("Family  -  " + obj["Family"]);
                Console.WriteLine("ProcessorType  -  " + obj["ProcessorType"]);
                Console.WriteLine("Characteristics  -  " + obj["Characteristics"]);
                Console.WriteLine("AddressWidth  -  " + obj["AddressWidth"]);
            }

            if (System.Environment.Is64BitOperatingSystem == true)
            {
                Console.WriteLine("Processor Bit: 64 Bit OS");
            }
            else
            {
                Console.WriteLine("Processor Bit: 32 Bit Os");

            }
            Console.WriteLine(" ");

            Console.WriteLine("----DRIVE INFO-----");
            DriveInfo[] allDrives = DriveInfo.GetDrives();
            foreach (DriveInfo d in allDrives)
            {
                string[] SizeSuffixes = { "bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB" };

                string SizeSuffix(Int64 value)
                {
                    if (value < 0) { return "-" + SizeSuffix(-value); }
                    if (value == 0) { return "0.0 bytes"; }

                    int mag = (int)Math.Log(value, 1024);
                    decimal adjustedSize = (decimal)value / (1L << (mag * 10));

                    return string.Format("{0:n1} {1}", adjustedSize, SizeSuffixes[mag]);
                }

                Console.WriteLine("Drive {0}", d.Name);
                Console.WriteLine("  Drive type: {0}", d.DriveType);
                Console.WriteLine("  File system: {0}", d.DriveFormat);
                Console.WriteLine("  Root directory:            {0, 12}", d.RootDirectory);
                Console.WriteLine("  Available space to current user:{0, 15}", SizeSuffix(d.AvailableFreeSpace));
                Console.WriteLine("  Total available space:          {0, 15}", SizeSuffix(d.TotalFreeSpace));
                Console.WriteLine("  Total size of drive:            {0, 15} ", SizeSuffix(d.TotalSize));
                Console.WriteLine(" ");


                
                

            }
            Console.WriteLine("----Updates made-----");
            const string query = "SELECT HotFixID FROM Win32_QuickFixEngineering";
            var search = new ManagementObjectSearcher(query);
            var collection = search.Get();

            foreach (ManagementObject quickFix in collection)
                Console.WriteLine(quickFix["HotFixID"].ToString());
            Console.WriteLine(" ");
            Console.WriteLine("----Windows Installed Apps Info----");
            Console.WriteLine(GetX64Installedsoftware());

        }
        private string GetX64Installedsoftware()
        {
            string Software = null;
            string SoftwareKey = @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

            Software += "\r\nWINDOWS X64 Software\r\n\r\n\r\n ";
            using (RegistryKey rk = Registry.LocalMachine.OpenSubKey(SoftwareKey))
            {
                if (rk == null)
                {
                    return Software;
                }
                foreach (string skName in rk.GetSubKeyNames())
                {
                    using (RegistryKey sk = rk.OpenSubKey(skName))
                    {
                        try
                        {
                            if (!(sk.GetValue("DisplayName") == null))
                            {
                                if (sk.GetValue("InstallLocation") == null)
                                    Software += sk.GetValue("DisplayName") + " - Install path not known \r\n ";
                                else
                                    Software += sk.GetValue("DisplayName") + " - " + sk.GetValue("InstallLocation") + "\r\n ";
                            }
                        }
                        catch (Exception ex)
                        {
                        }
                    }
                }
            }
            return Software;
        }

        private void returnUpdates()
        {
            PowerShell pinstance = PowerShell.Create();
            pinstance.AddScript

        }

    }

}