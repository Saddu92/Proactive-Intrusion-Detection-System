from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import sniff
from collections import defaultdict
import pandas as pd
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import joblib
import os
import nltk
import json
import random
import asyncio
import logging
import numpy as np
import subprocess
import logging
import asyncio
from fastapi import FastAPI, HTTPException, BackgroundTasks
from typing import Optional
from nltk.stem import WordNetLemmatizer
from tensorflow.keras.models import load_model
import google.generativeai as genai
from dotenv import load_dotenv
from pydantic import BaseModel
from typing import Optional
from sib_api_v3_sdk import ApiClient, Configuration
from sib_api_v3_sdk.api.transactional_emails_api import TransactionalEmailsApi
from sib_api_v3_sdk.models import SendSmtpEmail  # Correct import
# Removed redundant import for SendSmtpEmail
import subprocess

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log')
    ]
)

# Initialize Brevo configuration
configuration = Configuration()
configuration.api_key['api-key'] = os.getenv("BREVO_API_KEY")

headers = {
    "accept": "application/json",
    "api-key": os.getenv("BREVO_API_KEY"),
    "content-type": "application/json"
}

# Download NLTK data
nltk.download('punkt')
nltk.download('wordnet')
nltk.download('omw-1.4')

# Models and data initialization
MODEL_PATH = "./model/xgboost_model.pkl"
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")

chatbot_model = load_model('./model/chatbot_model.h5')
intents = json.loads(open('./model/cybersecurity_intents.json', encoding="utf8").read())
words = joblib.load('./model/words.pkl')
classes = joblib.load('./model/classes.pkl')

# Initialize Gemini
API_KEY = os.getenv("AIzaSyCVPkMlRkmZIUOrn_4TJf_CBZzjhmnGFAs")
if API_KEY:
    genai.configure(api_key=API_KEY)

# Pydantic models
class EmailRequest(BaseModel):
    email: str

# Helper classes
class EmailAlertService:
    def __init__(self):
        self.from_email = "shaikhmdsaad92@gmail.com"

    def send_http_alert(self, email, url):
        try:
            print(f"\n📧 Preparing HTTP security alert for {email}...")
            
            configuration = Configuration()
            configuration.api_key['api-key'] = os.getenv("BREVO_API_KEY", "Jg7THNEV3s4GL9ZY")

            api_client = ApiClient(configuration)
            api_instance = TransactionalEmailsApi(api_client)

            send_smtp_email = SendSmtpEmail(
                to=[{"email": email}],
                sender={"name": "Security Alert System", "email": self.from_email},
                subject="⚠️ Unsecured HTTP Visit Detected",
                html_content=f"""
                <h2>Security Alert</h2>
                <p>Our system detected that you visited an unsecured HTTP website:</p>
                <p><strong>Website:</strong> {url}</p>
                <p>This connection is not encrypted and could be monitored by attackers.</p>
                <p>For your security, we recommend:</p>
                <ul>
                    <li>Avoid entering any sensitive information on this site</li>
                    <li>Check if the site offers HTTPS version</li>
                    <li>Use a VPN when accessing sensitive websites</li>
                </ul>
                <p>Stay safe!</p>
                <p><em>Security Team</em></p>
                """
            )

            response = api_instance.send_transac_email(send_smtp_email)
            print(f"✅ Alert email successfully sent to {email}")
            print(f"   Response: {response}")
            return True
        except Exception as e:
            logging.error(f"Failed to send alert to {email}: {e}")
            print(f"❌ Failed to send alert to {email}: {e}")
            return False


# Initialize services
email_service = EmailAlertService()

captured_packets = []
flows = defaultdict(lambda: {
    'fwd_pkts': 0, 'bwd_pkts': 0,
    'fwd_len': 0, 'bwd_len': 0,
    'start_time': None, 'end_time': None
})

# Initialize FastAPI
blocked_ips = set()
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper functions
def preprocess_features(df):
    # Fill missing values
    df['Source IP'].ffill(inplace=True)
    df['Destination IP'].ffill(inplace=True)
    df['Protocol'].ffill(inplace=True)
    df['Source Port'].fillna(df['Source Port'].mean(), inplace=True)
    df['Dst Port'].fillna(df['Dst Port'].mean(), inplace=True)
    df['Flow Byts/s'].fillna(df['Flow Byts/s'].mode()[0], inplace=True)
    df['Flow Duration'].fillna(df['Flow Duration'].mean(), inplace=True)

    # Encode categorical features
    le = LabelEncoder()
    df["Flags"] = le.fit_transform(df["Flags"])
    df['Flags'].fillna(df['Flags'].mean(), inplace=True)

    # Fill missing values for other columns
    df['Fwd Pkt Len Mean'].fillna(df['Fwd Pkt Len Mean'].mean(), inplace=True)
    df['Bwd Pkt Len Mean'].fillna(df['Bwd Pkt Len Mean'].mean(), inplace=True)
    df['Tot Fwd Pkts'].fillna(df['Tot Fwd Pkts'].mode()[0], inplace=True)
    df['Tot Bwd Pkts'].fillna(df['Tot Bwd Pkts'].mode()[0], inplace=True)
    df['SYN Flag Cnt'].fillna(0, inplace=True)

    # Select and normalize required columns
    required_columns = ["Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", 
                      "Tot Bwd Pkts", "Fwd Pkt Len Mean", "Bwd Pkt Len Mean", 
                      "Flow Byts/s", "SYN Flag Cnt"]
    df = df[required_columns]
    
    scaler = MinMaxScaler()
    df['Flow Byts/s'] = scaler.fit_transform(df[['Flow Byts/s']])
    df['Fwd Pkt Len Mean'] = scaler.fit_transform(df[['Fwd Pkt Len Mean']])
    df['Tot Fwd Pkts'] = scaler.fit_transform(df[['Tot Fwd Pkts']])
    df['Dst Port'] = scaler.fit_transform(df[['Dst Port']])

    return df

def extract_features(packets):
    features_list = []
    for packet in packets:
        features = {}
        if packet.haslayer('IP'):
            features['Source IP'] = packet['IP'].src
            features['Destination IP'] = packet['IP'].dst
            features['Protocol'] = packet['IP'].proto
        else:
            features['Source IP'] = None
            features['Destination IP'] = None
            features['Protocol'] = None

        if packet.haslayer('TCP'):
            features['Source Port'] = packet['TCP'].sport
            features['Dst Port'] = packet['TCP'].dport
            features['Flags'] = str(packet['TCP'].flags)
            features['SYN Flag Cnt'] = 1 if 'S' in str(packet['TCP'].flags) else 0
        elif packet.haslayer('UDP'):
            features['Source Port'] = packet['UDP'].sport
            features['Dst Port'] = packet['UDP'].dport
            features['Flags'] = None
            features['SYN Flag Cnt'] = 0
        else:
            features['Source Port'] = None
            features['Dst Port'] = None
            features['Flags'] = None
            features['SYN Flag Cnt'] = 0

        features['Packet Length'] = len(packet)

        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            protocol = packet['IP'].proto
            dst_port = None

            if packet.haslayer('TCP'):
                dst_port = packet['TCP'].dport
            elif packet.haslayer('UDP'):
                dst_port = packet['UDP'].dport

            flow_key = (src_ip, dst_ip, dst_port, protocol)
            flow = flows[flow_key]

            if flow['start_time'] is not None and flow['end_time'] is not None:
                flow_duration = flow['end_time'] - flow['start_time']
                flow_bytes_per_sec = (flow['fwd_len'] + flow['bwd_len']) / flow_duration if flow_duration > 0 else 0
                fwd_pkt_len_mean = flow['fwd_len'] / flow['fwd_pkts'] if flow['fwd_pkts'] > 0 else 0
                bwd_pkt_len_mean = flow['bwd_len'] / flow['bwd_pkts'] if flow['bwd_pkts'] > 0 else 0

                features['Flow Duration'] = flow_duration
                features['Flow Byts/s'] = flow_bytes_per_sec
                features['Fwd Pkt Len Mean'] = fwd_pkt_len_mean
                features['Bwd Pkt Len Mean'] = bwd_pkt_len_mean
                features['Tot Fwd Pkts'] = flow['fwd_pkts']
                features['Tot Bwd Pkts'] = flow['bwd_pkts']
            else:
                features['Flow Duration'] = 0
                features['Flow Byts/s'] = 0
                features['Fwd Pkt Len Mean'] = 0
                features['Bwd Pkt Len Mean'] = 0
                features['Tot Fwd Pkts'] = 0
                features['Tot Bwd Pkts'] = 0

        features_list.append(features)
    return features_list


def packet_handler(packet, background_tasks: BackgroundTasks = None, user_email: str = None):
    # Print packet summary to console
    print(f"\n📦 Packet captured: {packet.summary()}")
    
    captured_packets.append(packet)

    if not packet.haslayer('IP'):
        return None

    # Update flow statistics
    src_ip = packet['IP'].src
    dst_ip = packet['IP'].dst
    protocol = packet['IP'].proto
    dst_port = None

    if packet.haslayer('TCP'):
        dst_port = packet['TCP'].dport
    elif packet.haslayer('UDP'):
        dst_port = packet['UDP'].dport

    flow_key = (src_ip, dst_ip, dst_port, protocol)
    flow = flows[flow_key]

    if flow['start_time'] is None:
        flow['start_time'] = packet.time
    flow['end_time'] = packet.time

    if src_ip == packet['IP'].src:
        flow['fwd_pkts'] += 1
        flow['fwd_len'] += len(packet)
    else:
        flow['bwd_pkts'] += 1
        flow['bwd_len'] += len(packet)

    # Enhanced HTTP detection
    if packet.haslayer('TCP') and packet['TCP'].dport == 80 and packet.haslayer('Raw'):
        try:
            payload = bytes(packet['TCP'].payload)
            
            # Detect HTTP traffic by looking for HTTP methods or headers
            if payload.startswith((b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ')) or \
               b'HTTP/1.' in payload or b'Host: ' in payload:
                
                host = None
                if b'Host: ' in payload:
                    host_line = payload.split(b'Host: ')[1].split(b'\r\n')[0]
                    host = host_line.decode('utf-8', errors='ignore').strip()
                
                if host:
                    print(f"\n🚨 Unsecured HTTP traffic detected!")
                    print(f"   Source: {src_ip}:{packet['TCP'].sport}")
                    print(f"   Destination: {dst_ip}:80")
                    print(f"   Host: {host}")
                    print(f"   Packet length: {len(packet)} bytes")
                    
                    if user_email and background_tasks:
                        print(f"   ⚡ Preparing to send alert to {user_email}")
                        background_tasks.add_task(
                            email_service.send_http_alert,
                            user_email,
                            f"http://{host}"
                        )
                    return "http_detected"
                    
        except Exception as e:
            logging.error(f"Error processing HTTP packet: {str(e)}")
            print(f"Error processing HTTP packet: {str(e)}")
    
    return None

def make_predictions(df):
    predictions = model.predict(df)
    return predictions.tolist()

# Chatbot functions
lemmatizer = WordNetLemmatizer()

def clean_up_sentence(sentence):
    sentence_words = nltk.word_tokenize(sentence)
    return [lemmatizer.lemmatize(word.lower()) for word in sentence_words]

def bow(sentence, words):
    sentence_words = clean_up_sentence(sentence)
    bag = [1 if w in sentence_words else 0 for w in words]
    return np.array(bag)

def predict_class(sentence):
    p = bow(sentence, words)
    res = chatbot_model.predict(np.array([p]))[0]
    ERROR_THRESHOLD = 0.25
    results = [{"intent": classes[i], "probability": r} for i, r in enumerate(res) if r > ERROR_THRESHOLD]
    results.sort(key=lambda x: x["probability"], reverse=True)
    return results

def get_response(ints):
    if ints:
        tag = ints[0]['intent']
        for i in intents['intents']:
            if i['tag'] == tag:
                return random.choice(i['responses'])
    return None

def query_gemini(user_input):
    try:
        model = genai.GenerativeModel("gemini-1.5-pro-latest")
        response = model.generate_content(user_input)
        return response.text
    except Exception as e:
        logging.error(f"Gemini API error: {e}")
        return "I'm sorry, I couldn't process your request at the moment."

def hybrid_chatbot_response(user_input):
    predicted_intents = predict_class(user_input)
    rule_based_response = get_response(predicted_intents)
    if rule_based_response is not None:
        return rule_based_response
    return query_gemini(user_input)

# API endpoints
@app.get("/")
async def root():
    return JSONResponse(content={"message": "Proactive Firewall API is running!"})

@app.get("/chatbot/{name}")
async def chatbot(name: str):
    message = name.replace("+", " ")
    response = hybrid_chatbot_response(message)
    return JSONResponse(content={"response": response})

@app.post("/register-email-for-alerts/")
async def register_email_for_alerts(email_request: EmailRequest):
    return {"message": "Email registered for security alerts", "email": email_request.email}

@app.post("/block-ip/")
async def block_ip(ip: str, duration: Optional[int] = 300, background_tasks: BackgroundTasks = None):
    if ip in blocked_ips:
        raise HTTPException(status_code=400, detail="IP already blocked")
    
    try:
        subprocess.run(
            f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}',
            shell=True, check=True
        )
        blocked_ips.add(ip)
        logging.info(f"🚫 Blocked IP: {ip}")

        # Schedule automatic unblock after `duration` seconds
        background_tasks.add_task(unblock_ip_after_delay, ip, duration)

        return {"message": f"IP {ip} blocked and will be unblocked after {duration} seconds."}
    except subprocess.CalledProcessError as e:
        logging.error(f"Error blocking IP {ip}: {e}")
        raise HTTPException(status_code=500, detail="Failed to block IP")

async def unblock_ip_after_delay(ip: str, delay: int = 300):
    await asyncio.sleep(delay)
    try:
        subprocess.run(
            f'netsh advfirewall firewall delete rule name="Block {ip}"',
            shell=True, check=True
        )
        blocked_ips.discard(ip)
        logging.info(f"✅ Unblocked IP: {ip} after {delay} seconds")
    except subprocess.CalledProcessError as e:
        logging.error(f"⚠️ Failed to unblock IP {ip}: {e}")


@app.post("/start-capture-and-predict/")
async def start_capture_and_predict(
    background_tasks: BackgroundTasks,
    email_request: Optional[EmailRequest] = None
):
    global captured_packets, flows
    captured_packets = []
    flows = defaultdict(lambda: {
        'fwd_pkts': 0, 'bwd_pkts': 0,
        'fwd_len': 0, 'bwd_len': 0,
        'start_time': None, 'end_time': None
    })

    http_alerts_detected = False
    http_hosts = set()

    def handler(pkt):
        nonlocal http_alerts_detected
        result = packet_handler(
            pkt, 
            background_tasks, 
            email_request.email if email_request else None
        )
        if result == "http_detected":
            http_alerts_detected = True
            if pkt.haslayer('TCP') and pkt.haslayer('Raw'):
                try:
                    payload = bytes(pkt['TCP'].payload)
                    if b'Host: ' in payload:
                        host = payload.split(b'Host: ')[1].split(b'\r\n')[0].decode().strip()
                        http_hosts.add(host)
                except:
                    pass

    print("\n" + "="*50)
    print("🚀 Starting packet capture on Wi-Fi interface...")
    print("="*50 + "\n")
    
    # Start capture with timeout
    sniff(iface="Wi-Fi", prn=handler, count=500, timeout=60)
    
    print("\n" + "="*50)
    print("✅ Packet capture completed")
    print(f"Total packets captured: {len(captured_packets)}")
    if http_alerts_detected:
        print(f"Unsecured HTTP visits detected: {len(http_hosts)}")
        for host in http_hosts:
            print(f" - {host}")
    print("="*50 + "\n")

    # Extract features and make predictions
    features_list = extract_features(captured_packets)
    df = preprocess_features(pd.DataFrame(features_list))
    predictions = make_predictions(df)

    # Prepare packet data
    packet_data = []
    for packet in captured_packets:
        packet_info = {
            'Source IP': packet['IP'].src if packet.haslayer('IP') else None,
            'Destination IP': packet['IP'].dst if packet.haslayer('IP') else None,
            'Protocol': packet['IP'].proto if packet.haslayer('IP') else None,
            'Source Port': packet['TCP'].sport if packet.haslayer('TCP') else packet['UDP'].sport if packet.haslayer('UDP') else None,
            'Destination Port': packet['TCP'].dport if packet.haslayer('TCP') else packet['UDP'].dport if packet.haslayer('UDP') else None,
            'Packet Length': len(packet),
        }
        packet_data.append(packet_info)

    return JSONResponse(content={
        "message": "Packet capture completed.",
        "statistics": {
            "total_packets": len(captured_packets),
            "http_visits": len(http_hosts),
            "unsecured_sites": list(http_hosts),
            "suspicious_packets": sum(1 for p in predictions if p == 1)
        },
        "predictions": predictions,
        "packet_data": packet_data,
        "http_alerts": {
            "detected": http_alerts_detected,
            "email_sent": http_alerts_detected and email_request is not None,
            "registered_email": email_request.email if email_request else None,
            "unsecured_sites": list(http_hosts)
        }
    })

@app.post("/predict-csv/")
async def predict_csv(file: UploadFile = File(...)):
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="File must be a CSV.")

    try:
        df = pd.read_csv(file.file)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading CSV file: {str(e)}")

    df = preprocess_features(df)
    predictions = make_predictions(df)
    packet_data = df.to_dict(orient="records")

    return JSONResponse(content={
        "message": "CSV file processed successfully.",
        "predictions": predictions,
        "packet_data": packet_data,
    })

@app.post("/test-email-alert/")
async def test_email_alert(email_request: EmailRequest):
    """Endpoint to test email alert functionality"""
    test_website = "http://test-insecure-site.com"
    success = await email_service.send_http_alert(email_request.email, test_website)
    
    return {
        "success": success,
        "message": "Test alert sent successfully" if success else "Failed to send test alert",
        "email": email_request.email,
        "test_website": test_website
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)