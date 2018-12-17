using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Management;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections.ObjectModel;
using System.IO;
using System.Net.NetworkInformation;
using System.DirectoryServices;
using System.Security.AccessControl;
using Microsoft.Win32;
using System.DirectoryServices.ActiveDirectory;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Windows.Forms;
using System.Net.Sockets;

namespace PCInfo
{
    /// Test class object to instantiate from inside PowerShell script.
    /// </summary>
    public class TestObject
    {
        /// Gets or sets the Name property
        public string Name { get; set; }
    }
    
    
    class BasicInfo
    {

        
        IPHostEntry host;

        //Account information
        private void DisplayUsers()
        {
            
            Console.WriteLine("-----------------------User Account Info--------------------");
            Console.WriteLine("Machine Name {0}", System.Environment.MachineName);
            Console.WriteLine("Current User : {0}", System.Environment.UserName);
            Console.WriteLine("User Domain Name: {0}", System.Environment.UserDomainName);
            Console.WriteLine("User Domain: {0}", System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName);

            Console.WriteLine(" ");
            Console.WriteLine("Users: ");

            try
            {
                string dirPath = @"C:\\Users";

                List<string> dirs = new List<string>(Directory.EnumerateDirectories(dirPath));

                foreach (var dir in dirs)

                {
                    string currentfolder = dir.Substring(dir.LastIndexOf("\\") + 1);
                    var stringcheck = new List<string> {"Default","All Users","Default User","Public" };
                    bool strbool = stringcheck.Contains(currentfolder);
                    if (strbool == false)
                    {
                        Console.WriteLine("      {0}", dir.Substring(dir.LastIndexOf("\\") + 1));
                    }    
                    
                }
                //Console.WriteLine("{0} directories found.", dirs.Count);
            }
            catch (UnauthorizedAccessException UAEx)
            {
                Console.WriteLine(UAEx.Message);
            }
            catch (PathTooLongException PathEx)
            {
                Console.WriteLine(PathEx.Message);
            }
            Console.WriteLine(" ");
            //ReturnLocalUsers();
           

        }

        //OS info
        private void DisplayOSInfo()
        {
            Console.WriteLine("-----------------OS INFO----------------------");
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
        }

        //Network Configuration Info
        private void DisplayNetworkInfo()
        {   Console.WriteLine("------------Network Information Configuration-----------------");
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
                foreach (var ip in ni.GetIPProperties().UnicastAddresses)
                {
                    
                    if ((ni.OperationalStatus == OperationalStatus.Up)
                    && (ip.Address.AddressFamily == AddressFamily.InterNetwork) && (!ni.Description.ToString().Contains("Virtual")) && (!ni.Description.ToString().Contains("Loopback")))
                    {
                        Console.Write(ni.Name + ":  ");
                        Console.Out.WriteLine(ip.Address.ToString() + " | " + ni.Description.ToString() + " | " + ni.NetworkInterfaceType);
                    }
                }
                //if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                //{
                    
                //    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                //    {
                //        if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                //        {
                //            Console.WriteLine(ip.Address.ToString());
                //        }
                //    }
                //}
            }
            Console.WriteLine(" ");
        }


        //Hardware Details Info
        private void displayHardwareDetails()
        {
            Console.WriteLine("-----------------Hardware Details Info--------------------");
            Console.WriteLine(" ");
            Console.WriteLine("--------Memory Info--------");
            ObjectQuery wql = new ObjectQuery("SELECT * FROM Win32_OperatingSystem");
            ManagementObjectSearcher mysearcher = new ManagementObjectSearcher(wql);
            ManagementObjectCollection results = mysearcher.Get();

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

            Console.WriteLine("-------DRIVE INFO----------");
            DriveInfo[] allDrives = DriveInfo.GetDrives();
            foreach (DriveInfo d in allDrives)
            {
                if (d.IsReady == true)
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
            }

        }

        //returns list of local users
        private void ReturnLocalUsers()
        {
            try
            {
                  using(PowerShell psInstance = PowerShell.Create())
                {
                    string value = "LocalAccount=True";
                    psInstance.AddCommand("Get-WmiObject")
                        .AddArgument("Win32_UserAccount").AddParameter("Filter",value);
                    Collection<PSObject> psOut = psInstance.Invoke();
                    Console.WriteLine("-------------------LOCAL USERS INFO----------------------");
                    foreach(PSObject outPutItem in psOut)
                    {
                        if (outPutItem != null)
                        {
                            Console.WriteLine(outPutItem.BaseObject.GetType().FullName);
                            Console.WriteLine(outPutItem.BaseObject.ToString() + "\n");
                        }
                    }

                    if(psInstance.Streams.Error.Count > 0)
                    {
                        string temp = psInstance.Streams.Error.First().ToString();
                        Console.WriteLine("Error {0}", temp);
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            Console.WriteLine(" ");
        }
        //Returns Installed Softwares
        private string GetX64Installedsoftware()
        {
            string Software = null;
            string SoftwareKey = @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

            Software += "\r\nWINDOWS X64 Software\r\n\r\n";
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

                            if (!(sk.GetValue("DisplayName") == null) && !sk.GetValue("DisplayName").ToString().Contains("KB")) 
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

        //captures the Hotfix
        public void captureHotfix()
        {
            Process process = new System.Diagnostics.Process();
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = "/c systeminfo";
            process.StartInfo = startInfo;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            //MessageBox.Show(output);
            string regex = @"(Hotfix.*[\s\S]*?)Network";
            Regex tmpregex = new Regex(regex);

            Match tmpmatch = tmpregex.Match(output);
            Group tmpgroup = tmpmatch.Groups[1];
            //MessageBox.Show(tmpgroup.ToString());
            Console.WriteLine("----------Updates Installed-----------");
            Console.WriteLine(tmpgroup.ToString());
        }

        //calls the other methods
        public void displayInfo()
        {
            DisplayUsers();
            DisplayOSInfo();
            Console.WriteLine(" ");
            DisplayNetworkInfo();
            Console.WriteLine(" ");
            displayHardwareDetails();

            Console.WriteLine(" ");
            Console.WriteLine("-------Windows Installed Apps Info------");
            Console.WriteLine(GetX64Installedsoftware());
            Console.WriteLine(" ");
            captureHotfix();
        }
    }
}