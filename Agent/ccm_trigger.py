<<<<<<< Updated upstream
# example call
# curl -X POST http://127.0.0.1:6868 -H "Content-Type: application/json" -d '{"trigger": "start"}'
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Read the length of the content
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length else b''

        try:
            # Parse incoming JSON data if necessary
            request_data = json.loads(post_data) if post_data else {}
            print(f"Received API request: {request_data}")

            # Trigger the execution of the agent script
            print("Executing get_host_crypto_data.py...")
            result = subprocess.run(["python3", "get_host_crypto_data.py"], capture_output=True, text=True)

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
            print(f"Error handling request: {e}")
            self.send_response(500)
            self.end_headers()
            response_data = {"status": "error", "message": str(e)}
            self.wfile.write(json.dumps(response_data).encode('utf-8'))

def run_server(host='127.0.0.1', port=6868):
    server_address = (host, port)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f"Server running at http://{host}:{port}/")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
=======
# example call
# curl -X POST http://127.0.0.1:6868 -H "Content-Type: application/json" -d '{"trigger": "start"}'
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Read the length of the content
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length else b''

        try:
            # Parse incoming JSON data if necessary
            request_data = json.loads(post_data) if post_data else {}
            print(f"Received API request: {request_data}")

            # Trigger the execution of the agent script
            print("Executing get_host_crypto_data.py...")
            result = subprocess.run(["python3", "get_host_crypto_data.py"], capture_output=True, text=True)
            
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
            print(f"Error handling request: {e}")
            self.send_response(500)
            self.end_headers()
            response_data = {"status": "error", "message": str(e)}
            self.wfile.write(json.dumps(response_data).encode('utf-8'))

def run_server(host='127.0.0.1', port=6868):
    server_address = (host, port)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f"Server running at http://{host}:{port}/")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
>>>>>>> Stashed changes
