# Wireless Frame Analysis


**Overview:** The goal of this lab was to capture and analyze 802.11 wireless packets, focusing on signal strength, encryption detection, and channel analysis.

**Skills Developed:** Wireless packet capturing, encryption analysis (WPA), signal strength evaluation.

**Tools Used:** Wireshark, Tshark.

---


**Lab Details**

Introduction
This lab will provide basic information about 802.11 wireless packet capture. A 802.11 wireless device is the Wireless Local Area Network (WLAN) standard of computers, tablets, smartphones, and other Wi-Fi capable devices. Most WLAN networks operate on a both 2.4 gigahertz (GHz) and 5.0 GHz called dual band. The packets that will be analyzed in this lab will be both 2.4 and 5.0 GHz. 

Objective
The objective of this lab is to provide individuals with hands-on experience identifying 802.11 wireless devices and configuration settings from a wireless packet capture such as Wireshark or tcpdump. This lab will provide data from a network analyzing packet capture from the physical and data link layer of a wireless network. 
Software and Websites used to perform analysis:
•	Windows 11 Home Premium Service 
•	Google Chrome
•	Wireshark Network Protocol Analyzer 
•	Tshark

Results and Analysis
The first task for the user is to download Wireshark Network analyzer. This will allow the user to view the following information. Once Wireshark is downloaded onto the users computer, the user will open the 802.11 zip file sent from the professor for examination. This should open Wireshark with the file titled ‘802.11capture.pcap’ if done properly. 
Once the individual has opened Wireshark to view the zip file. First the user will want to go to the wireless tab and select WLAN traffic. This will display all the statistics for the WLAN network for the file. The figure below should appear. 

Figure 1: WLAN statistics  

![image](https://github.com/user-attachments/assets/fec2d6e3-11c0-4c84-8fd2-6e46ce87933b)


The user can now see that there are 5 devices total because the first 5 numbers start with a letter or number. This shows the devices Basic Service Set Identifier (BSSID). These are a unique 48 bit label associated with an individual access point affiliated with a service set. Often times this will just be the Media Access Control (MAC) address number which is labeled the same way. The MAC address is a unique 48-bit label identifying every member of the BSSID whether the access point or end station. The MAC address is factory set for every radio. The next lines that state ‘ff:ff:ff:ff:ff:ff’ indicate a broadcast, meaning the packet is sent from one host to any other on the network. 
Next the user will right click on one of the address information and select apply filter then select ‘selected’ this will place the information into the main Wireshark window. Next the user will then open the radiotap header and go down to the Channel flags tab to see if that packet is a 2ghz or 5ghz device. The channel frequency will be displayed right above the channel flags as well. In the first device, the address is 00:00:00:00:00:00, the user places the information in the main Wireshark window two packets appear. 1 is for a 2ghz device with a channel frequency of 2412 and the next is on a 5ghz device with a channel frequency of 5260. 

Figure 2: Spectrum and channel frequency

![image](https://github.com/user-attachments/assets/53db4ee5-a01f-4316-8736-67c6274d1a43)

 
Figure 2 continued

![image](https://github.com/user-attachments/assets/0c27a742-43d1-49fa-8636-2d358e6d59a6)

 
For address 00:0f:66:e5:7f:c5, 324 packets were displayed and all packets were on a 2ghz device. The channel frequency differed this could be due to different destinations. The channel frequency displayed 2437, 2442, 2452, 2457, 2427, 2457, 2432, 2417, 2447, 2412, 2467, and 2422. 
The next address is 00:1b:90:55:86:80, 37 packets were displayed and all packets were on a 2ghz device. The channel frequency for all packets was 2412. 
The next address is 84:db:2f:07:38:ba, there were 363 packets and all packets were on a 2ghz device. The channel frequency for the packets displayed 2417, 2422, 2432, 2427, 2437, 2457, 2484.
The next address is d0:57:85:79:96:59, there were 73 packets and all packets were on a 5ghz device. The channel frequency for the packets displayed 5745. 
Next the user will use still use the WLAN statistics window. However, the user can use the normal Wireshark window. The user will use the filter ‘radiotap.channel.freq == 2437’. This is filter all packets so the user can see only the packets that were on channel frequency 2437. Then depending on how the user filtered the packets. In this lab, the packets were filtered using the WLAN statistics screen the device will appear at the top of the screen. The user will disregard the second device because its on channel 3 and the question asked about channel 6. Then the next BSSID is a broadcast request so that will also be disregarded. 

Figure 3: Devices on channel 6 

![image](https://github.com/user-attachments/assets/5ad62818-34cd-41a4-b416-c02347673eb5)


Using the WLAN statistic window and filtering the devices the user can see which devices are on 2 ghz and in between channels 1-11. The following are screenshot and shown below. 

Figure 4: Devices transmitting outside the US FCC

![image](https://github.com/user-attachments/assets/719940c2-c0ff-44cc-abe3-932c95c18134)

 
Figure 4 continued
 
![image](https://github.com/user-attachments/assets/9598c146-b566-45b8-8d90-8444ba3b0f08)



![image](https://github.com/user-attachments/assets/ab978877-f01e-49d4-be02-f0f9e69f7e84)


 ![image](https://github.com/user-attachments/assets/5fb0e2b3-aae0-4b32-947e-2b15cc895236)


![image](https://github.com/user-attachments/assets/99b8698e-e95a-4f85-81a4-f5b81fa788e9)

 
Next the user will find the strongest signal strengths and weakest signal strengths observed for incoming packets. These are measured in negative numbers so the weakest number will be the highest negative number and the strongest will be the lowest number being closest to zero. Using the filter in the main Wireshark screen ‘radiotap.dbm_antsignal == -44’ the user can see the device and packet with the strongest strength. Then using the same filter ‘radiotap.dbm_antsignal == -95’ the user will be able to see the packet and device with the weakest signal. The screenshots below show both packets. 

Figure 5: dBM strongest signal 

![image](https://github.com/user-attachments/assets/295f30bf-2898-4432-9cf1-91c2b505187d)


Figure 6: dBM weakest signal 

![image](https://github.com/user-attachments/assets/fe8749aa-b132-413f-94b2-cb1174b488e2)


Next the user will use the WLAN statistics window and then type the following filter ‘wlan.fc.type_subtype == 4’ this will show all the clients that request probes throughout the 802.11 network. This does not mean these are connected to network only scanning, however, these did appear on the packet capture. Using the filter ‘wlan.fc.type_subtype == 5’ this will display the clients who are on the network. 

Figure 7: clients scanning on network  

![image](https://github.com/user-attachments/assets/f9c9e751-ee04-429e-8269-20670b62bbac)


Figure 8: clients on network

 ![image](https://github.com/user-attachments/assets/e1ea0661-826c-4468-a6ad-24623bc94ea7)



Next the user will use the same WLAN statistics window and filter out the devices that show the number of access points. The filter used will be ‘wlan.fc.type_subtype == 8’ This will show the number of access points that appear in this packet capture. 

Figure 9: number of access points 

![image](https://github.com/user-attachments/assets/90f25d52-34e9-46e8-b063-a17cfe58b79d)


This will also display the number of MAC addresses and SSID pairs as well. So the individual can use the same filter, however, for further information the user will open each tab to clarify there isn’t any more pairs. 

Figure 10: MAC addresses with SSID 

![image](https://github.com/user-attachments/assets/c8715c45-014d-4544-a162-b5ad46160a3b)


When looking to see which access points have data confidentiality 3 devices use encryption, one is freely open. The two of the three devices have the title ‘group cipher’ with the encryption ‘AES’. In cryptography, this stands for Advanced Encryption Standard. However, in this lab the user just needs to know that the pack being filtered through the device is being encrypted. The device using the PSK (Pre-Shared Key) is the device that is used for the home or office network and is a standard version of encryption for Wi-Fi Protected Access(WPA). Below the user can see the detailed information for Wireshark on the 3 encrypted access points and the 1 open access point. The one open access point is 00:db:90:55:86:80 and the SSID is “guestwifi”. 

Figure 11: WPA encrypted access point
 
![image](https://github.com/user-attachments/assets/07492691-5f43-469d-a378-de54f403ec5e)



Figure 12: Encrypted access point 

![image](https://github.com/user-attachments/assets/27a90fda-4982-47e4-9049-341ce0659a4b)


Figure 13: Encrypted access point
 

![image](https://github.com/user-attachments/assets/5121bfd1-3f4c-485e-8749-af63112f920f)



Figure 14: Open access point
 
![image](https://github.com/user-attachments/assets/5b978ec6-369a-45dc-a6e1-d8e87aca7143)


Two possible network attacks are ‘evil twinning’ and packet sniffing. Evil twinning is a type of man in the middle attack where an individual will set up a fake wi-fi access point hoping that users will connect to it instead of a legitimate one. When users connect to the fake access point, all the data they share with the network passes through a server controlled by the attacker. An attacker can create an evil twin with a smartphone or other internet capable device and some readily available software. Evil twin attacks are more common on public wi-fi networks which are unsecured and leave your personal data vulnerable. A packet sniffing attack or simply sniffing attack is an attack that involves intercepting and misusing the content passing through a network in the form of packets. Unencrypted email communications, login, passwords, and financial information are common targets for packet sniffing attack. An attacker may also use sniffing tools to hijack packets by injecting malware into the packet itself which executes once it reaches the target of choice. 

Conclusion
Wireshark is a powerful network packet analyzer.  This tool can be used to do a variety of analysis for any individual on any network including wireless access points as seen in in this lab. This can be used for good to help companies stay secure or even help a home network stay secure. However, this analyzing tool can be used for attacks as well. It is a fine line how this tool can be used. Although, the best goal for any individual is keep the wireless network secure with a passphrase of their choice. This will help reduce the chances of an individual attacking the network.  
