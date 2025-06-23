🛡️ Proactive Intrusion Detection System (PIDS)
Proactive Intrusion Detection System (PIDS) is an AI-powered, real-time cybersecurity solution designed to detect, prevent, and respond to potential threats on a network. Built with FastAPI, the system combines machine learning, packet analysis, automated firewall control, and intelligent alerting mechanisms to proactively safeguard systems against suspicious activities.
.
🔎 What It Does
Traditional intrusion detection systems react after an attack is detected. PIDS goes a step further — it not only detects threats as they occur but also takes preventive actions automatically. It can:

Capture live network packets
Analyze them in real-time using a trained ML model
Block malicious IP addresses dynamically
Send alerts if unsecured HTTP traffic is detected
Provide an interactive chatbot to assist with security queries

⚙️ Key Components Explained
🧠 Machine Learning Threat Detection
Uses a trained XGBoost model to classify network packets as safe or malicious based on features like protocol, flags, size, and timing. This enables intelligent threat detection without relying solely on fixed rules.
🧹 Real-Time Packet Sniffing
Continuously monitors the network using Scapy to sniff packets and analyze their behavior in real time.
✉️ Email Alerting System
Detects unsafe HTTP requests (unencrypted traffic) and notifies administrators via email alerts using Brevo (Sendinblue).

🚀 Why It Matters
In today's environment of increasing cyber threats, reactive defense mechanisms are no longer enough. PIDS provides a proactive, intelligent, and automated layer of defense — empowering system administrators to:

Detect threats early
Respond automatically
Stay informed in real-time
Reduce manual monitoring overhead
It is especially useful for small to medium organizations looking to implement smart, affordable security measures.


