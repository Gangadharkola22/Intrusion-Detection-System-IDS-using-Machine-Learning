#  Real-Time Intrusion Detection System using Scapy & Machine Learning

This project implements a simple **Intrusion Detection System (IDS)** using `Scapy` for packet capture and `Scikit-learn` for attack classification. It detects:
- `Normal` (Ping)
- `Scan` (Nmap)
- `DoS` (hping3)

---

##  Project Structure

idsusingscapy/
├── dos_generator.py
├── scan_generator.py
├── normal_generator.py
├── trainer.py
├── realtime.py
├── packet_utils.py
├── model.pkl # (Generated after training)
├── normal.csv # (Generated)
├── scan.csv # (Generated)
├── dos.csv # (Generated)
└── ids-env/ # Python virtual environment


## ⚙Step-by-Step Setup & Execution

### 1. Clone or Copy the Project
Navigate to your desired directory and place the project files there.

---

### 2. Create & Activate Virtual Environment
python3 -m venv ids-env
source ids-env/bin/activate
3.  Install Required Packages
pip install -r requirements.txt
If requirements.txt is missing, use:

pip install scikit-learn pandas joblib numpy scapy
4. Generate Dataset for Training
Run the following scripts to simulate traffic and generate labeled CSVs:

# Run each in a separate terminal or sequentially
sudo python normal_generator.py   # Simulates ping (normal)
sudo python scan_generator.py     # Simulates nmap (scan)
sudo python dos_generator.py      # Simulates hping3 (dos)
Each script will create:

normal.csv

scan.csv

dos.csv

5. Train the Model
bash
Copy
Edit
sudo ./ids-env/bin/python trainer.py
This will:

Load CSVs

Train a RandomForestClassifier

Save the model to model.pkl

6. Run the Real-Time IDS
bash
Copy
Edit
sudo ./ids-env/bin/python realtime.py
This script:

Captures live packets

Extracts features

Loads the trained model

Predicts and displays the attack type

Attack Simulation Tools
ping <target_ip> — generates normal ICMP traffic

nmap <target_ip> — simulates port scan

hping3 -1 --flood <target_ip> — simulates DoS

Notes
Must run with sudo to capture packets with Scapy.

Ensure all .csv files are generated before training.

Tested with Python 3.10+ and scikit-learn 1.7+

Author
Developed by: Kola Gangadhar
Date: August 2025
Environment: Kali Linux, Python venv, Scapy, Scikit-learn

yaml
Copy
Edit
