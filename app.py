import os
import re
import json
import time
import uuid
import threading
import secrets
from flask import Flask, request, jsonify

app = Flask(__name__)

DATA_DIR = os.environ.get("USERS_DATA", "/data")
if not os.path.exists(DATA_DIR):
    DATA_DIR = "/tmp/unco-users"
os.makedirs(DATA_DIR, exist_ok=True)

USERS_FILE = os.path.join(DATA_DIR, "users.json")
NAMES_FILE = os.path.join(DATA_DIR, "names.json")

_lock = threading.Lock()

ADMIN_NAME = "MaxxShevtsov"
ADMIN_KEY = os.environ.get("ADMIN_KEY", "change_me_in_secrets")

NAME_RE = re.compile(r'^[a-zA-Z0-9_\-\.]{2,32}$')


def _load(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save(path, data):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception:
        pass


def _sanitize(s, maxlen=64):
    return re.sub(r'[<>&"\']', '', str(s or '')).strip()[:maxlen]


def _new_id():
    return "u" + uuid.uuid4().hex[:10]


def _is_admin_key(key):
    return key and secrets.compare_digest(str(key), ADMIN_KEY)


@app.route("/", methods=["GET"])
def health():
    with _lock:
        users = _load(USERS_FILE)
    return jsonify({
        "status": "ok",
        "service": "UnCo Users",
        "version": "1.0.0",
        "users_count": len(users),
        "data_dir": DATA_DIR,
        "persistent": DATA_DIR == "/data"
    })


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    name = _sanitize(data.get("name", ""), 32)

    if not name:
        return jsonify({"error": "empty name"}), 400
    if not NAME_RE.match(name):
        return jsonify({
            "error": "имя должно быть 2-32 символа, только латиница, цифры, _ - ."
        }), 400

    with _lock:
        users = _load(USERS_FILE)
        names = _load(NAMES_FILE)

        if name in names:
            return jsonify({"error": "имя уже занято", "taken": True}), 409

        uid = _new_id()
        while uid in users:
            uid = _new_id()

        is_admin = (name == ADMIN_NAME)
        users[uid] = {
            "id": uid,
            "name": name,
            "verified": False,
            "admin": is_admin,
            "created": int(time.time())
        }
        names[name] = uid
        _save(USERS_FILE, users)
        _save(NAMES_FILE, names)

    return jsonify({
        "ok": True,
        "id": uid,
        "name": name,
        "verified": False,
        "admin": is_admin
    })


@app.route("/verify/<uid>", methods=["GET"])
def verify(uid):
    with _lock:
        users = _load(USERS_FILE)
    u = users.get(uid)
    if not u:
        return jsonify({"valid": False})
    return jsonify({
        "valid": True,
        "id": u["id"],
        "name": u["name"],
        "verified": u.get("verified", False),
        "admin": u.get("admin", False)
    })


@app.route("/user/<uid>", methods=["GET"])
def get_user(uid):
    with _lock:
        users = _load(USERS_FILE)
    u = users.get(uid)
    if not u:
        return jsonify({"error": "not found"}), 404
    return jsonify(u)


@app.route("/user-by-name/<name>", methods=["GET"])
def get_user_by_name(name):
    name = _sanitize(name, 32)
    with _lock:
        names = _load(NAMES_FILE)
        users = _load(USERS_FILE)
    uid = names.get(name)
    if not uid or uid not in users:
        return jsonify({"error": "not found"}), 404
    return jsonify(users[uid])


@app.route("/name-available/<name>", methods=["GET"])
def name_available(name):
    name = _sanitize(name, 32)
    if not NAME_RE.match(name):
        return jsonify({"available": False, "reason": "invalid"})
    with _lock:
        names = _load(NAMES_FILE)
    return jsonify({"available": name not in names})


@app.route("/admin/verify", methods=["POST"])
def admin_verify():
    data = request.get_json(silent=True) or {}
    key = data.get("key", "")
    target = _sanitize(data.get("target", ""), 64)

    if not _is_admin_key(key):
        return jsonify({"error": "wrong admin key"}), 403
    if not target:
        return jsonify({"error": "no target"}), 400

    with _lock:
        users = _load(USERS_FILE)
        names = _load(NAMES_FILE)

        uid = target if target in users else names.get(target)
        if not uid or uid not in users:
            return jsonify({"error": "user not found"}), 404

        users[uid]["verified"] = True
        _save(USERS_FILE, users)

    return jsonify({"ok": True, "id": uid, "name": users[uid]["name"]})


@app.route("/admin/unverify", methods=["POST"])
def admin_unverify():
    data = request.get_json(silent=True) or {}
    key = data.get("key", "")
    target = _sanitize(data.get("target", ""), 64)

    if not _is_admin_key(key):
        return jsonify({"error": "wrong admin key"}), 403

    with _lock:
        users = _load(USERS_FILE)
        names = _load(NAMES_FILE)
        uid = target if target in users else names.get(target)
        if not uid or uid not in users:
            return jsonify({"error": "user not found"}), 404
        users[uid]["verified"] = False
        _save(USERS_FILE, users)

    return jsonify({"ok": True, "id": uid, "name": users[uid]["name"]})


@app.route("/admin/list", methods=["POST"])
def admin_list():
    data = request.get_json(silent=True) or {}
    key = data.get("key", "")
    if not _is_admin_key(key):
        return jsonify({"error": "wrong admin key"}), 403
    with _lock:
        users = _load(USERS_FILE)
    items = sorted(users.values(), key=lambda x: x.get("created", 0), reverse=True)
    return jsonify({"users": items, "count": len(items)})


@app.route("/admin/delete-user", methods=["POST"])
def admin_delete_user():
    data = request.get_json(silent=True) or {}
    key = data.get("key", "")
    target = _sanitize(data.get("target", ""), 64)

    if not _is_admin_key(key):
        return jsonify({"error": "wrong admin key"}), 403

    with _lock:
        users = _load(USERS_FILE)
        names = _load(NAMES_FILE)
        uid = target if target in users else names.get(target)
        if not uid or uid not in users:
            return jsonify({"error": "user not found"}), 404

        uname = users[uid]["name"]
        del users[uid]
        if uname in names:
            del names[uname]
        _save(USERS_FILE, users)
        _save(NAMES_FILE, names)

    return jsonify({"ok": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
