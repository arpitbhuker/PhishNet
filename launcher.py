# launcher.py
import threading, webbrowser, time
from server import app

def run_server():
    app.run(host='127.0.0.1', port=5000)

if __name__ == "__main__":
    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    time.sleep(1)  # wait for server
    webbrowser.open("http://127.0.0.1:5000")
    t.join()

