import streamlit as st
import base64
import json
from flask import Flask, request
from threading import Thread, Lock
import binascii
import time

app = Flask(__name__)

# Initialize a list to store received packets and a lock for thread safety
packet_reports = []
lock = Lock()

# Flask route to receive packet reports
@app.route('/api/', methods=['GET'])
def receive_packet_report():
    global packet_reports

    # Get the base64 encoded query string from the IDS
    b64_payload = request.args.get('data', '')

    if b64_payload:
        try:
            # Add padding if necessary
            missing_padding = len(b64_payload) % 4
            if missing_padding:
                b64_payload += '=' * (4 - missing_padding)
            
            # Decode the base64 string
            decoded_json = base64.b64decode(b64_payload).decode('utf-8')

            # Convert the JSON string back to a Python dictionary
            packet_report = json.loads(decoded_json)

            # Add the packet report to the list with thread safety
            with lock:
                packet_reports.append(packet_report)
                print("Received packet report:", packet_report)  # Debugging line

            # Send a response back to the IDS
            return {'status': 'success', 'message': 'Packet received'}, 200

        except (UnicodeDecodeError, binascii.Error) as e:
            return {'status': 'error', 'message': f'Decoding error: {e}'}, 400
        except json.JSONDecodeError as e:
            return {'status': 'error', 'message': f'JSON parsing error: {e}'}, 400

    else:
        return {'status': 'error', 'message': 'No data received'}, 400

def run_flask():
    app.run(host='127.0.0.1', port=8080)

def display_dashboard():
    st.title("Packet Monitoring Dashboard")
    st.write("Received Packet Reports:")
    
    while True:  # Keep updating the dashboard
        with lock:
            if packet_reports:
                st.json(packet_reports)
            else:
                st.write("No packet reports received yet.")
        
        time.sleep(1)  # Pause to reduce CPU usage

if __name__ == '__main__':
    # Start the Flask server in a separate thread
    flask_thread = Thread(target=run_flask, daemon=True)
    flask_thread.start()

    # Start the Streamlit app
    display_dashboard()
