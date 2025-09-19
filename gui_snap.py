import os
import shlex
import threading
import subprocess
from flask import Flask, render_template, request
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

@app.route("/")
def index():
    return render_template("index.html")

def run_snapshot(host, snapshot_name, snapshot_desc, sid):
    """Run vm_snapshot.py and emit progress to frontend."""
    # Full path to vm_snapshot.py
    script_path = os.path.join(os.path.dirname(__file__), "vm_snapshot.py")
    cmd = [
        "python",
        script_path,
        "--vm", host,
        "--snapshot-name", snapshot_name,
        "--snapshot-desc", snapshot_desc,
        "--verbose"
    ]

    # Debug
    print("[DEBUG] Running command:", " ".join(shlex.quote(arg) for arg in cmd))

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )

        for line in iter(process.stdout.readline, ''):
            if not line:
                continue
            line = line.strip()
            msg_lower = line.lower()
            progress = 0
            if "connect" in msg_lower:
                progress = 10
            elif "search" in msg_lower:
                progress = 30
            elif "found" in msg_lower or "vm matched" in msg_lower:
                progress = 50
            elif "creating snapshot" in msg_lower:
                progress = 70
            elif "snapshot created" in msg_lower or "created successfully" in msg_lower:
                progress = 90

            # Emit progress to frontend using the user-provided host
            socketio.emit(
                "snapshot_progress",
                {"host": host, "message": line, "progress": progress},
                room=sid
            )
        process.stdout.close()
        retcode = process.wait()
        print(f"[DEBUG] vm_snapshot.py finished for {host} with exit code {retcode}")

        # Ensure final 100% progress
        socketio.emit(
            "snapshot_progress",
            {"host": host, "message": "Snapshot complete", "progress": 100},
            room=sid
        )
        socketio.emit("snapshot_complete", {"host": host}, room=sid)

    except Exception as e:
        print(f"[ERROR] Exception for host {host}: {e}")
        socketio.emit(
            "snapshot_progress",
            {"host": host, "message": f"Error: {e}", "progress": 100},
            room=sid
        )
        socketio.emit("snapshot_complete", {"host": host}, room=sid)

@socketio.on("start_snapshots")
def handle_start_snapshots(data):
    hosts = data.get("hosts", [])
    snapshot_name = data.get("snapshot_name", "AutoSnapshot")
    snapshot_desc = data.get("snapshot_desc", "Created via web UI")
    sid = request.sid

    for h in hosts:
        if h.get("selected", True):
            host = h["name"]
            print(f"[DEBUG] Launching snapshot thread for host: {host}")
            threading.Thread(
                target=run_snapshot,
                args=(host, snapshot_name, snapshot_desc, sid),
                daemon=True
            ).start()

@socketio.on("connect")
def handle_connect():
    print("[DEBUG] Client connected:", request.sid)

@socketio.on("disconnect")
def handle_disconnect():
    print("[DEBUG] Client disconnected:", request.sid)

if __name__ == "__main__":
    print("[DEBUG] Starting Flask-SocketIO server...")
    socketio.run(app, host="0.0.0.0", port=8080, debug=True)
