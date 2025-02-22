
# import os
# import glob
# import threading
# import time
# import re
# import subprocess
# from flask import Flask, render_template_string
# from flask_socketio import SocketIO, emit
# from google import genai
# from google.genai import types

# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'secret!'
# socketio = SocketIO(app)

# # Initialize the Gemini AI client with your API key
# client = genai.Client(api_key="AIzaSyDK6Fsd9DcMeduph7bUlwttAOboBCqZNQw")  # Replace with your actual API key

# # System instruction for Gemini
# sys_instruct = (
#     "You are an LLM model that reads Wireshark captures, responds back   any suspicious IPs and their activities, and flag them by formatting the response as this: Suspicious IPs: <ipaddress>, if not respond with \"nothing to report\". "
# )


# # Global variables to store untrusted IPs and the latest analysis text.
# # untrusted_ips is a dictionary with {ip: last_suspicious_timestamp}
# untrusted_ips = {}
# # latest_analysis holds the full analysis text from the most recent capture processing.
# latest_analysis = ""

# # A lock to protect shared data between threads.
# lock = threading.Lock()

# def convert_pcap_to_text(pcap_path):
#     """
#     Convert a pcap file to text using tshark.
#     Ensure that tshark is installed and in your PATH.
#     """
#     try:
#         # Using tshark to read the pcap file.
#         result = subprocess.run(["tshark", "-r", pcap_path], capture_output=True, text=True)
#         return result.stdout
#     except Exception as e:
#         print(f"Error converting pcap to text: {e}")
#         return ""

# def analyze_wireshark(file_content):
#     """
#     Send the file content (as text) to the Gemini AI and return the analysis result.
#     """
#     response = client.models.generate_content_stream(
#         model="gemini-2.0-flash",
#         config=types.GenerateContentConfig(system_instruction=sys_instruct),
#         contents=[file_content]
#     )
#     # Concatenate all response chunks into a single string.
#     return "".join(chunk.text for chunk in response)

# def extract_suspicious_ips(analysis_text):
#     """
#     Extract suspicious IP addresses from the analysis text.
#     For this example, we assume that any line containing the word 'suspicious'
#     will also contain one or more IPv4 addresses.
#     """
#     suspicious_ips = []
#     for line in analysis_text.splitlines():
#         if "suspicious" in line.lower():
#             # Find IPv4 addresses in the line.
#             ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", line)
#             suspicious_ips.extend(ips)
#     return suspicious_ips

# def update_untrusted_ips(suspicious_ips):
#     """
#     Update the global untrusted_ips dictionary.
#     For each IP found, update its timestamp to now.
#     Also, forgive (remove) IPs if no suspicious activity has been seen for over 10 minutes.
#     Returns True if any update occurred.
#     """
#     now = time.time()
#     updated = False
#     with lock:
#         for ip in suspicious_ips:
#             untrusted_ips[ip] = now
#             updated = True

#         # Remove IPs if no suspicious activity in the last 10 minutes (600 seconds)
#         for ip in list(untrusted_ips.keys()):
#             if now - untrusted_ips[ip] > 600:
#                 del untrusted_ips[ip]
#                 updated = True
#     return updated

# def background_task():
#     """
#     Background thread that:
#       - Checks for the newest pcap file in the "pcaps" directory every 60 seconds.
#       - Converts the pcap to text.
#       - Analyzes the text with Gemini AI.
#       - Extracts suspicious IPs and updates the global list.
#       - Emits a SocketIO event if suspicious activity is detected.
#     """
#     global latest_analysis
#     last_processed_file = None
#     while True:
#         # Look for pcap files in the "pcaps" directory.
#         pcap_files = glob.glob("pcaps/*.pcap")
#         if pcap_files:
#             # Find the newest file by modification time.
#             newest_file = max(pcap_files, key=os.path.getmtime)
#             if newest_file != last_processed_file:
#                 print(f"Processing new file: {newest_file}")
#                 text_content = convert_pcap_to_text(newest_file)
#                 if text_content:
#                     analysis = analyze_wireshark(text_content)
#                     with lock:
#                         latest_analysis = analysis
#                     suspicious_ips = extract_suspicious_ips(analysis)
#                     updated = update_untrusted_ips(suspicious_ips)
#                     last_processed_file = newest_file
#                     # If suspicious activity was found or IP list updated, emit an update event.
#                     if suspicious_ips or updated:
#                         socketio.emit('suspicious_update', {'message': 'New suspicious activity detected'})
#                 else:
#                     print("No text extracted from the pcap.")
#         else:
#             print("No pcap files found in 'pcaps' directory.")
#         time.sleep(60)

# @app.route("/")
# def index():
#     """
#     Main route that displays:
#       - A list of current untrusted IPs with their last detected time.
#       - The full text of the latest analysis.
#     """
#     with lock:
#         ips = dict(untrusted_ips)
#         analysis = latest_analysis
#     # html = """
#     # <!DOCTYPE html>
#     # <html>
#     #   <head>
#     #     <meta charset="UTF-8">
#     #     <title>Untrusted IPs & Latest Analysis</title>
#     #     <script src="https://cdn.socket.io/4.5.1/socket.io.min.js" integrity="sha384-p41ZH78S7jRyyk3T8B6tZa8xYzE9M4cfJY4ygPcnlv14cEUM+1Ff84K4av3dr4E0" crossorigin="anonymous"></script>
#     #     <script type="text/javascript">
#     #       var socket = io();
#     #       socket.on('suspicious_update', function(data) {
#     #           console.log("Received suspicious_update event:", data.message);
#     #           // Reload the page to re-render updated information.
#     #           window.location.reload();
#     #       });
#     #     </script>
#     #   </head>
#     #   <body>
#     #     <h1>Untrusted IP Addresses</h1>
#     #     <ul>
#     #       {% for ip, timestamp in ips.items() %}
#     #         <li>{{ ip }} - Last suspicious: {{ timestamp | timestamp_to_str }}</li>
#     #       {% endfor %}
#     #     </ul>
#     #     <h2>Latest Analysis</h2>
#     #     <pre>{{ analysis }}</pre>
#     #   </body>
#     # </html>
#     # """
#     # return render_template_string(html, ips=ips, analysis=analysis)


#     return render_template("index.html", ips=ips, analysis=analysis)


# @app.template_filter('timestamp_to_str')
# def timestamp_to_str(ts):
#     return time.ctime(ts)

# if __name__ == "__main__":
#     # Start the background task thread as a daemon.
#     thread = threading.Thread(target=background_task, daemon=True)
#     thread.start()
#     # Run the Flask-SocketIO app.
#     socketio.run(app, debug=True)
import os
import glob
import threading
import time
import re
import subprocess
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from google import genai
from google.genai import types

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# Initialize the Gemini AI client with your API key
client = genai.Client(api_key="AIzaSyDK6Fsd9DcMeduph7bUlwttAOboBCqZNQw")  # Replace with your actual API key

# System instruction for Gemini
sys_instruct = (
    "You are a LLM model that reads Wireshark captures, responds in a readable format, "
    "and flags any suspicious IPs and their activities."
)
# sys_instruct = (
#     "You are an LLM model that reads Wireshark captures, responds back   any suspicious IPs and their activities, and flag them by formatting the response as this: Suspicious IPs: <ipaddress>, if not respond with \"nothing to report\". "
# )
# Global variables to store untrusted IPs and the latest analysis text.
# untrusted_ips is a dictionary with {ip: last_suspicious_timestamp}
untrusted_ips = {}
# latest_analysis holds the full analysis text from the most recent capture processing.
latest_analysis = ""

# A lock to protect shared data between threads.
lock = threading.Lock()

def convert_pcap_to_text(pcap_path):
    """
    Convert a pcap file to text using tshark.
    Ensure that tshark is installed and in your PATH.
    """
    try:
        # Using tshark to read the pcap file.
        result = subprocess.run(["tshark", "-r", pcap_path], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error converting pcap to text: {e}")
        return ""

def analyze_wireshark(file_content):
    """
    Send the file content (as text) to the Gemini AI and return the analysis result.
    """
    response = client.models.generate_content_stream(
        model="gemini-2.0-flash",
        config=types.GenerateContentConfig(system_instruction=sys_instruct),
        contents=[file_content]
    )
    # Concatenate all response chunks into a single string.
    return "".join(chunk.text for chunk in response)

def extract_suspicious_ips(analysis_text):
    """
    Extract suspicious IP addresses from the analysis text.
    For this example, we assume that any line containing the word 'suspicious'
    will also contain one or more IPv4 addresses.
    """
    suspicious_ips = []
    for line in analysis_text.splitlines():
        if "suspicious" in line.lower():
            # Find IPv4 addresses in the line.
            ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", line)
            suspicious_ips.extend(ips)
    return suspicious_ips

def update_untrusted_ips(suspicious_ips):
    """
    Update the global untrusted_ips dictionary.
    For each IP found, update its timestamp to now.
    Also, forgive (remove) IPs if no suspicious activity has been seen for over 10 minutes.
    Returns True if any update occurred.
    """
    now = time.time()
    updated = False
    with lock:
        for ip in suspicious_ips:
            untrusted_ips[ip] = now
            updated = True

        # Remove IPs if no suspicious activity in the last 10 minutes (600 seconds)
        for ip in list(untrusted_ips.keys()):
            if now - untrusted_ips[ip] > 600:
                del untrusted_ips[ip]
                updated = True
    return updated

def background_task():
    """
    Background thread that:
      - Checks for the newest pcap file in the "pcaps" directory every 60 seconds.
      - Converts the pcap to text.
      - Analyzes the text with Gemini AI.
      - Extracts suspicious IPs and updates the global list.
      - Emits a SocketIO event if suspicious activity is detected.
    """
    global latest_analysis
    last_processed_file = None
    while True:
        # Look for pcap files in the "pcaps" directory.
        pcap_files = glob.glob("pcaps/*.pcap")
        if pcap_files:
            # Find the newest file by modification time.
            newest_file = max(pcap_files, key=os.path.getmtime)
            if newest_file != last_processed_file:
                print(f"Processing new file: {newest_file}")
                text_content = convert_pcap_to_text(newest_file)
                if text_content:
                    analysis = analyze_wireshark(text_content)
                    with lock:
                        latest_analysis = analysis
                    suspicious_ips = extract_suspicious_ips(analysis)
                    updated = update_untrusted_ips(suspicious_ips)
                    last_processed_file = newest_file
                    # If suspicious activity was found or IP list updated, emit an update event.
                    if suspicious_ips or updated:
                        socketio.emit('suspicious_update', {'message': 'New suspicious activity detected'})
                else:
                    print("No text extracted from the pcap.")
        else:
            print("No pcap files found in 'pcaps' directory.")
        time.sleep(60)

@app.route("/")
def index():
    """
    Main route that displays:
      - A list of current untrusted IPs with their last detected time.
      - The full text of the latest analysis.
    """
    with lock:
        ips = dict(untrusted_ips)
        analysis = latest_analysis
    return render_template("index.html", ips=ips, analysis=analysis)

@app.template_filter('timestamp_to_str')
def timestamp_to_str(ts):
    """Converts a timestamp to a readable string."""
    return time.ctime(ts)

if __name__ == "__main__":
    # Start the background task thread as a daemon.
    thread = threading.Thread(target=background_task, daemon=True)
    thread.start()
    # Run the Flask-SocketIO app.
    socketio.run(app, debug=True)
