import os
import shlex
import threading
import subprocess
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")


@app.route("/")
def index():
    return render_template("index.html")


def run_snapshot(host, snapshot_name, snapshot_desc, sid):
    """
    Run vm_snapshot.py and emit progress if sid is provided.
    """
    script_path = os.path.join(os.path.dirname(__file__), "vm_snapshot.py")
    cmd = [
        "python",
        script_path,
        "--vm", host,
        "--snapshot-name", snapshot_name,
        "--snapshot-desc", snapshot_desc,
        "--verbose"
    ]

    print(f"[DEBUG] Running snapshot for {host}: {' '.join(cmd)}")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )

        found_vm = False
        snapshot_created = False

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
                found_vm = True
            elif "creating snapshot" in msg_lower:
                progress = 70
            elif "snapshot created" in msg_lower or "created successfully" in msg_lower:
                progress = 90
                snapshot_created = True

            if sid:
                socketio.emit(
                    "snapshot_progress",
                    {"host": host, "message": line, "progress": progress},
                    room=sid
                )

        process.stdout.close()
        retcode = process.wait()
        print(f"[DEBUG] Snapshot process finished for {host}, exit code {retcode}")

        success = found_vm and snapshot_created

        if sid:
            socketio.emit(
                "snapshot_complete",
                {"host": host, "success": success},
                room=sid
            )
        else:
            print(f"[WEBHOOK] Snapshot {'succeeded ✅' if success else 'failed ❌'} for {host}")

    except Exception as e:
        print(f"[ERROR] Exception during snapshot for host {host}: {e}")
        if sid:
            socketio.emit(
                "snapshot_progress",
                {"host": host, "message": f"Error: {e}", "progress": 100},
                room=sid
            )
            socketio.emit("snapshot_complete", {"host": host, "success": False}, room=sid)
        else:
            print(f"[WEBHOOK] Snapshot failed for {host}: {e}")


# --- Web UI triggers ---
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


# --- Webhook endpoint ---
@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json()
    if not data or "hosts" not in data:
        return jsonify({"status": "error", "message": "Invalid payload, 'hosts' required"}), 400

    hosts = [{"name": h, "selected": True} for h in data.get("hosts", [])]
    snapshot_name = data.get("snapshot_name", "AutoSnapshot")
    snapshot_desc = data.get("snapshot_desc", "Triggered via webhook")

    for h in hosts:
        host_name = h["name"]
        print(f"[WEBHOOK] Triggering snapshot for host: {host_name}")
        threading.Thread(
            target=run_snapshot,
            args=(host_name, snapshot_name, snapshot_desc, None),  # sid=None for webhook
            daemon=True
        ).start()

    return jsonify({"status": "success", "message": f"Snapshots triggered for {len(hosts)} host(s)"}), 200


# --- SocketIO events ---
@socketio.on("connect")
def handle_connect():
    print(f"[DEBUG] Client connected: {request.sid}")


@socketio.on("disconnect")
def handle_disconnect():
    print(f"[DEBUG] Client disconnected: {request.sid}")


if __name__ == "__main__":
    print("[DEBUG] Starting Flask-SocketIO server...")
    socketio.run(app, host="0.0.0.0", port=8080, debug=True)
