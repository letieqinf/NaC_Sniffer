﻿using SharpPcap;
using PacketDotNet;
using System.Net.NetworkInformation;
using System.Text;


namespace Sniffer
{
    class Program
    {
        static void Main(string[] args)
        {
            var deviceList = CaptureDeviceList.Instance;
            Console.WriteLine("Доступные устройства: ");
            foreach (var device in deviceList.Select((value, i) 
                         => new { i, value.Name, value.Description }))
                Console.WriteLine($"[{device.i + 1}] Name: {device.Name}; Desc: {device.Description};");
            Console.WriteLine();
            Console.ReadKey();
            
            var captureDevice = deviceList[2];
            
            captureDevice.OnPacketArrival += device_OnPacketArrival;
            captureDevice.Open(DeviceModes.Promiscuous, 2000);
            
            captureDevice.StartCapture();
            Console.ReadKey();
            captureDevice.StopCapture();
        }

        private static void device_OnPacketArrival(object sender, PacketCapture e)
        {
            var packet = e.GetPacket();
            var packetData = Packet.ParsePacket(packet.LinkLayerType, packet.Data);

            var ipPacket = packetData.Extract<IPPacket>();
            if (ipPacket == null)
                return;
            
            var tcpPacket = ipPacket.Extract<TcpPacket>();
            var udpPacket = ipPacket.Extract<UdpPacket>();

            if (tcpPacket == null && udpPacket == null)
                return;
            
            Console.WriteLine("========= ПОЛУЧЕН ПАКЕТ =========\n");
            
            if (tcpPacket != null)
                Print(tcpPacket);
            
            if (udpPacket != null)
                Print(udpPacket);
            
            Console.WriteLine("Адрес отправителя: " + ipPacket.SourceAddress);
            Console.WriteLine("Адрес получателя: " + ipPacket.DestinationAddress);
            
            Console.WriteLine();

            Console.WriteLine("Время: " + packet.Timeval.Date);
            Console.WriteLine("\n=================================\n");
        }

        private static void Print(TransportPacket packet)
        {
            Console.WriteLine($"Тип: {packet.GetType().ToString()[13..^6].ToUpper()}");
            Console.WriteLine("Порт отправителя: " + packet.SourcePort);
            Console.WriteLine("Порт получателя: " + packet.DestinationPort);
            Console.WriteLine();
        }
    }
}
