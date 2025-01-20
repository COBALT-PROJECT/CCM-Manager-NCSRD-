# example call
# curl -X POST http://127.0.0.1:6868 -H "Content-Type: application/json" -d '{"trigger": "start"}'
import socket
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import re


# Starting logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create rotating file handler for the logger
# max_bytes = 15 * 1024 * 1024  # 15 MB
max_bytes = 10 * 1024 # 5KB to test the rotation
backup_count = 30 # up to 30 old log files
#file_handler = logging.FileHandler('ccm-agent.log')
hostname = socket.gethostname()
file_handler = RotatingFileHandler(f'ccm-agent-{hostname}-listener.log', 'a', max_bytes, backup_count)
file_handler.setLevel(logging.INFO)

# Create formatter of the log file
#formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(funcName)s: %(message)s')
script_name = os.path.basename(__file__)
ccm_trigger_id = 225
formatter = logging.Formatter(f'%(asctime)s - {script_name} - [{ccm_trigger_id}] - %(levelname)s: %(message)s ')
file_handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(file_handler)

logger.info("#--------------------------------------------------#")
logger.info("#------ INITIATING CCM AGENT LISTENER -------------#")
logger.info("#--------------------------------------------------#")

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Read the length of the content
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length else b''

        try:
            # Parse incoming JSON data if necessary
            request_data = json.loads(post_data) if post_data else {}
            logger.info(f"Received API request: {request_data}")

            # Trigger the execution of the agent script
            logger.info("Executing main.py...")
            result = subprocess.run(["python3", "main.py"], capture_output=True, text=True)
            
            # Send back the result of the script execution
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            response_data = {
                "status": "success",
                "output": result.stdout,
                "errors": result.stderr
            }
            self.wfile.write(json.dumps(response_data).encode('utf-8'))

        except Exception as e:
            # Handle any errors
            logger.info(f"Error handling request: {e}")
            self.send_response(500)
            self.end_headers()
            response_data = {"status": "error", "message": str(e)}
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            
    def do_GET(self):
        # Check if the path and message match our condition
        if self.path == "/trigger":
            # Log the request and send an HTTP 200 response
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Trigger received. Executing main.py...")
            logger.info("Received valid trigger, executing main.py")

            # Run main.py using subprocess
            subprocess.Popen(["python", "main.py"])
        else:
            # Send a 404 response for unknown paths
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            logger.warning(f"Unknown request: {self.path}")


def run_server(host='0.0.0.0', port=6868):
    server_address = (host, port)
    httpd = HTTPServer(server_address, RequestHandler)
    logger.info(f"Server running at http://{host}:{port}/")
    httpd.serve_forever()
    logger.info("#--------------------------------------------------#")
    logger.info("#------ INITIATING CCM AGENT LISTENER -------------#")
    logger.info("#--------------------------------------------------#")


if __name__ == "__main__":
    run_server()
