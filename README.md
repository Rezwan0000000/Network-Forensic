# 🛡️ Wireshark-Style CLI Packet Analyzer

A powerful, colorized, interactive Python toolkit for advanced packet analysis—right in your terminal.  
Inspired by Wireshark, built for blue/red teams, CTFs, and network forensics!

---

## 🚀 Features

- **Wireshark-style Output**:  
  - Tabular, true PCAP ordering ("No." matches original file)
  - Protocol color, expert info highlights (errors, warnings, notes, anomalies)
  - Real capture date/time per packet
- **Advanced Filtering**:  
  - By protocol, source IP, destination IP, src/dst port, and Info field (keyword)
- **Flows (Session) Summary**:  
  - Tally conversations between hosts/ports—like Wireshark's Conversations tool
- **Paging**:  
  - View results in pages (first 50, then 30 more with `m`/`more`)
- **Export & Payload Dump**:  
  - Export filtered results to a new PCAP, or dump TCP/raw payloads to a text file
- **Theme Support**:  
  - Choose between default, dark, or light terminal color themes
- **Live or Offline**:  
  - Capture real-time network traffic or analyze existing PCAP files

---

## 🛠️ Installation

pip install scapy colorama

> For live capture: run as administrator or with sudo/root.

---

## ⚡ Usage

### Start


### Select Theme

Choose your color scheme (default/dark/light) when prompted.

### Main Menu

- `1` — Live capture and analysis (saves packets to `new_packet.pcap`)
- `2` — Analyze an existing PCAP file

---

### Analyzing an Existing PCAP

1. **Enter PCAP filename**  
   Respond to the prompt with your `.pcap` file path.

2. **See Protocol Summary**  
   Get an instant table of protocols and packet counts.

3. **Protocol + Filtering**  
   - Select protocol (e.g., TCP, UDP, etc.)  
   - Enter optional filters:  
     - Source IP  
     - Destination IP  
     - Port (source or destination)  
     - Keyword (Info field)

   _Leave fields blank to skip or use them all to combine filters!_

4. **Results Table**  
   - See results—matching the original PCAP numbering, colorized severity and protocols, searchable Info field.
   - Type `m`/`more` to see 10 more packets at a time, or [Enter] to return to filtering.

5. **Flows/Summary**  
   - At the protocol prompt, type `flows` for a conversation/session summary across all traffic or a protocol.

6. **Exporting Results**  
   - Save filtered results as a new PCAP  
   - Dump matching payloads to a text file for further review

---

## 🧰 Example Output

<img width="857" height="841" alt="image" src="https://github.com/user-attachments/assets/12aa6e4e-5528-4bbc-94e7-1c6b42279178" />

<img width="963" height="980" alt="image" src="https://github.com/user-attachments/assets/df20e9b7-229e-458f-b90e-e3ba836428ee" />

<img width="703" height="116" alt="image" src="https://github.com/user-attachments/assets/f4acf431-5f7d-4ff3-8e11-71e1e61155ff" />

<img width="834" height="221" alt="image" src="https://github.com/user-attachments/assets/5edee8b9-2ab3-4897-9042-b043e25e1bc9" />

Will display only matching SSH handshake packets from the given IP, with color and severity for errors/warnings.

---

## 🔎 Professional & CTF Quick Wins

- **Flows Summary:** Map sessions like Wireshark’s Conversations.
- **Payload Dump:** Extract sensitive or CTF-relevant data for quick investigation.
- **Alerts:** Instantly see ARP spoofing, bad flags, and protocol errors—colorized and emoji-tagged for priority.
- **True PCAP IDs:** Always know the original packet number to cross-reference in Wireshark or other tools.

---

## 🤝 Contributing

- Add protocol decoders, more expert info, or extra output options!
- Pull requests and issues welcome.

---

## 📄 License

MIT — Free for professional, academic, and CTF use.
