# 🦍 ARP Poisoning Toolkit

A CLI tool for performing **ARP poisoning (spoofing)** attacks, built in Go using the `gopacket` and `pcap` libraries. Supports both **static** and **dynamic** modes for targeting victims and gateways on a local network.

---

## 🛡️ Warning

> ⚠️ **This tool is for educational and authorized penetration testing only.**  
> Unauthorized use on networks without permission is illegal and unethical.

---

## 📦 Features

- 🔎 Dynamic network scanning and device discovery.
- ✍️ Static mode with manual input.
- 🧠 Intelligent interface selection with address listing.
- 🎯 Real-time ARP poisoning.
- 🧵 Concurrent goroutine handling for sniffing and sending.


## 🚀 Getting Started
- This project was design primary for Linux 🐧. But it may work on Windows (Have not tested yet !)
- Require Root access.
- Require port forwarding enable on Linux for now will be implemented in the code Soon!.


### 📥 Installation

```bash
git clone https://github.com/Cythonic1/Go-Poison.git

cd Go-Poison

go build -o gopoizn

```

## 🧪 Usage

### help menu 🆘

```bash
╔════════════════════════════════════════════════════════════════════════════╗
║                        🦍 Jungle Packet Tool - Help Menu                   ║
╠════════════════════════════════════════════════════════════════════════════╣
║ Usage: ./ gopoizn       [dynamic | static]                                 ║
║                                                                            ║
║ Modes:                                                                     ║
║  dynamic               Perform automatic discovery (no additional flags)   ║
║  static                Requires manual input of all the flags below        ║
║                                                                            ║
║ Required Flags for 'static' mode:                                          ║
║  -amac <MAC>           Attacker's MAC address                              ║
║  -vmac <MAC>           Victim's MAC address                                ║
║  -vip <IP>             Victim's IP address                                 ║
║  -dip <IP>             Default gateway IP address                          ║
║                                                                            ║
║ General Flags:                                                             ║
║  -h, --help            Show this help menu                                 ║
╚════════════════════════════════════════════════════════════════════════════╝
```
### Dynamic mode 🖥️
- The tool provide dynamic host discovery and dynamic interface selection and detection.
- when running dynamic mode no need to any more command arguments

```bash
sudo gopoizn dynamic
```

### static mode 🧰
- In static mode you need to provide everything as shown above in the help menu



## Contributing 🤝
- Please feel free to note anything if there anything I miss.
- This is my first go project so it maybe no the best thing.
- And yeah thank you if you read until here 💓.


## 📜 License
MIT License


## TODOs ✋
- Some fixes require
- scanning dynamic range
- some code cleaning


