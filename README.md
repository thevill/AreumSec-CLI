# AreumSec-CLI
**AreumSec-CLI** is a real-time cybersecurity threat analysis application built with Python. Designed for security analysts and VAPT professionals, for rapid file, URL, and IP/hash investigations.


### **Screenshot:**
![image](https://github.com/user-attachments/assets/4c686382-b153-4e45-b5fd-ee3e934fb8b4)



### **Running the App:**<br>
```bash
pip install -r requirements.txt
```
```bash
python areumsec_cli.py
```


### **Features:**
1) Real-Time Analysis<br>
   URLs & Domains, IPv4 / IPv6 addresses, File Hash (SHA256), EML / MSG / TXT files
3) VirusTotal + Google SafeBrowsing Integration<br>
   API keys are securely managed in a separate config file.


### **Tech Stack:**
1) Python 3
2) VirusTotal & Google SafeBrowsing APIs


### **API Keys:**<br>
Add your api_keys in config.py:<br>
