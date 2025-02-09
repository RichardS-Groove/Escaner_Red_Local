
# 🔍 **Network Device Scanner – IoT Security Audit**

## 🚀 **Project Overview**  

This project is a **network scanning tool** designed to identify **IP cameras, printers, and IoT devices** on a local network. It helps assess **security risks** by detecting potentially vulnerable devices and open ports.  

### 🎯 **Key Features**  

- **Detect IoT devices** (IP cameras, printers, smart home devices...)  
- **Retrieve manufacturer details** based on MAC address  
- **Identify open ports** on detected devices  
- **Fast and optimized network scanning** using ARP requests  
- **Multithreaded scanning** for better performance  
- **Export results in JSON format**  

---

## 🏗 **Project Architecture**  

- **ARP-based Device Discovery** 🔍  
  - Identifies connected devices on the network  
  - Retrieves associated MAC and IP addresses  

- **Vendor Lookup & IoT Detection** 📡  
  - Queries known manufacturer databases  
  - Identifies devices from IoT vendors 

- **Port Scanning** 🔓  
  - Scans for common open ports and can be tweaked (22, 80, 443, 3389, 53, 445)  
  - Helps assess potential security risks  

- **Results Visualization & Export** 📄  
  - Displays structured results in a table
  - Option to export data in **JSON format**  

---

## 📜 **Prerequisites**  

### 🛠 **System Requirements**  

- **OS**: Linux
- **Python 3.8+** installed  
- **Administrator privileges** to scan the network  

### 📦 **Required Libraries**  

- `scapy` (network packet analysis)  
- `netifaces` (network interface management)  
- `requests` (API calls for vendor lookup)  
- `rich` (beautiful terminal tables)  
- `concurrent.futures` (multithreading for faster scans)  

Install dependencies:  

    pip install -r requirements.txt

---

## 🚀 **Usage**  

    sudo python3 main.py

---

## 📊 **Example Output**  

| IP Address   | MAC Address        | Vendor       | Open Ports   | IoT Device |
|-------------|------------------|-------------|------------|------------|
| 192.168.1.10 | 00:1A:2B:3C:4D:5E | TP-Link     | 80, 443    | ✅ Yes     |
| 192.168.1.15 | 11:22:33:44:55:66 | HP          | 9100       | ❌ No      |
| 192.168.1.20 | AA:BB:CC:DD:EE:FF | Netgear     | 22, 445    | ✅ Yes     |

---

## ⚠️ **Legal Disclaimer**  

This tool is intended for **educational and cybersecurity research purposes only**. Unauthorized network scanning may be **illegal** and is strictly prohibited.  

By using this software, you agree to comply with **all applicable laws and regulations**. The author assumes **no responsibility** for misuse.  

---

## 👨‍💻 **Author & License**  

💻 **Author**: [HackTheVoid](https://github.com/hack-the-void)  
📌 **License**: MIT  
