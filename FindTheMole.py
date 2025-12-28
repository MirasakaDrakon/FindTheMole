#!/usr/bin/env python3
from pystyle import Colors, Colorate, Center
import os, sys, time, math, hashlib, shutil, logging, json, re
from collections import Counter
from datetime import datetime, timezone
import yara

try:
  import requests
except ImportError:
  requests = None

import argparse

# =====================
# CONFIG
# =====================
def print_banner():
  banner = r"""
  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣾⣿⣿⣷⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣤⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣤⣤⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿Find The Mole⣿⣿
⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀
⠀⠀⠀ ⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
  """
  
  print(Colorate.Horizontal(Colors.blue_to_cyan,banner))

BASE_DIR = os.path.expanduser("~/.findthemole")
YARA_DIR = os.path.join(BASE_DIR, "yara")
os.makedirs(YARA_DIR, exist_ok=True)
PROTECTED_PATHS = (
    # Linux / Android
    "/data/data/com.termux/usr",
    "/data/data/com.termux/.suroot",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/usr",
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/system",
    "/vendor",

    # TERMUX (КРИТИЧНО)
    
    #"/data/data/com.termux",
    #"/data/data/com.termux/files",
    os.path.expanduser("~/.termux"),
    os.path.expanduser("~/.bashrc"),
    os.path.expanduser("~/.profile"),
)
BASE_DIR = os.path.expanduser("~/.findthemole")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
REPORT_DIR = os.path.join(BASE_DIR, "reports")

HASH_DB = os.path.join(BASE_DIR, "hashes.db")
BLACKLIST_DB = os.path.join(BASE_DIR, "blacklist.db")
WHITELIST = os.path.join(BASE_DIR, "whitelist.txt")
LOGFILE = os.path.join(BASE_DIR, "mole.log")

SCAN_INTERVAL = 3600  # 1 hour
DEFAULT_KARMA = 1000

# =====================
# SETUP
# =====================
def load_yara_rules():
    rules = {}
    for f in os.listdir(YARA_DIR):
        if f.endswith(".yar") or f.endswith(".yara"):
            rules[f] = os.path.join(YARA_DIR, f)
    if not rules:
        return None
    return yara.compile(filepaths=rules)

YARA_RULES = load_yara_rules()

def yara_scan(path):
    if not YARA_RULES:
        return []
    try:
        matches = YARA_RULES.match(path)
        return [m.rule for m in matches]
    except Exception:
        return []
import sqlite3

INFESTED_DB = os.path.join(BASE_DIR, "infested.db")

FILES_DB = {}  # path -> {hash, karma, reasons, status, source, added_at}

def restore_from_quarantine(sha):
    # получаем путь из БД
    original_path = None
    with sqlite3.connect(INFESTED_DB) as db:
        row = db.execute("SELECT original_path FROM infested WHERE hash=?", (sha,)).fetchone()
        if row:
            original_path = row[0]

    for f in os.listdir(QUARANTINE_DIR):
        if f.startswith(sha):
            src = os.path.join(QUARANTINE_DIR, f)
            dst = original_path or os.path.join("/", f.split("_", 1)[1])
            try:
                shutil.move(src, dst)
                logging.info(f"Restored from quarantine: {dst}")
                return dst
            except Exception as e:
                logging.error(f"Restore failed: {e}")
    return None

def pardon(target, is_hash=False, new_karma=DEFAULT_KARMA):
    sha = target if is_hash else sha256(target)

    # удалить из blacklist и infested
    if os.path.exists(BLACKLIST_DB):
        lines = open(BLACKLIST_DB).readlines()
        with open(BLACKLIST_DB, "w") as f:
            for l in lines:
                if sha not in l:
                    f.write(l)
    if os.path.exists(INFESTED_DB):
        with sqlite3.connect(INFESTED_DB) as db:
            db.execute("DELETE FROM infested WHERE hash=?", (sha,))

    # вернуть из карантина
    restored_path = restore_from_quarantine(sha)
    path = restored_path or target

    # обновить FILES_DB
    FILES_DB[path] = {
        "hash": sha,
        "karma": new_karma,
        "reasons": [],
        "status": "clean",
        "source": "pardon",
        "added_at": datetime.now(timezone.utc).isoformat()
    }

    # обновить хэши
    all_hashes = load_hashes()
    all_hashes[path] = {"hash": sha, "time": datetime.now(timezone.utc).isoformat()}
    save_all_hashes(all_hashes)

    logging.info(f"PARDONED {path} | Karma restored to {new_karma}")
    print(f"[✓] Pardon applied:{path}")

def sync_all_databases(path):
    f = FILES_DB[path]
    logging.debug(
      f"DB_SYNC path={path} status={f['status']} karma={f['karma']} source={f['source']}"
    )
    f = FILES_DB[path]
    h = f["hash"]
    karma = f["karma"]
    reasons = ",".join(f["reasons"])
    status = f["status"]
    source = f["source"]
    added_at = f["added_at"]

    # ---- Blacklist ----
    if status == "blacklist":
        blacklist_entry(h, path, "HIGH_RISK")
    
    # ---- Infested DB ----
    with sqlite3.connect(INFESTED_DB) as db:
        db.execute("""
            INSERT OR REPLACE INTO infested (hash, name, added_at, reason, risk, source)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (h, os.path.basename(path), added_at, reasons, karma, source))

# Инициализация инфестед.db
def init_infested_db():
    with sqlite3.connect(INFESTED_DB) as db:
        db.execute("""
        CREATE TABLE IF NOT EXISTS infested (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT,
            name TEXT,
            added_at TEXT,
            reason TEXT,
            risk INTEGER,
            source TEXT
        )
        """)
def update_karma(path, new_karma, reason=None, source="scan"):
    if path not in FILES_DB:
        FILES_DB[path] = {
            "hash": sha256(path),
            "karma": DEFAULT_KARMA,
            "reasons": [],
            "status": "clean",
            "source": source,
            "added_at": datetime.now(timezone.utc).isoformat()
        }

    f = FILES_DB[path]
    f['karma'] = new_karma
    if reason:
        f['reasons'].append(reason)
    f['source'] = source

    sync_all_databases(path)
    
for d in [BASE_DIR, QUARANTINE_DIR, REPORT_DIR]:
    os.makedirs(d, exist_ok=True)

logging.basicConfig(
    filename=LOGFILE,
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logging.getLogger().addHandler(console)
def is_protected(path):
    try:
        rp = os.path.realpath(path)
    except:
        return True

    for p in PROTECTED_PATHS:
        p = os.path.realpath(p)
        if rp == p or rp.startswith(p + os.sep):
            return True
    return False
# =====================
# UTILS
# =====================
import subprocess
def clamav_scan_file(path):
    try:
        mode = clamav_mode()
        if mode == "clamd":
            cmd = ["clamdscan", "--no-summary", path]
        elif mode == "clamscan":
            cmd = ["clamscan", "--no-summary", path]
        else:
            return False

        r = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print(f"CLAMAV OUTPUT:\n{r.stdout}")
        return "FOUND" in r.stdout
    except Exception:
        return False

def clamav_mode():
    # clamdscan ТОЛЬКО если реально живой демон
    if shutil.which("clamdscan"):
        try:
            r = subprocess.run(
                ["clamdscan", "--ping"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2
            )
            if r.returncode == 0:
                return "clamd"
        except:
            pass

    # fallback — ВСЕГДА clamscan
    if shutil.which("clamscan"):
        return "clamscan"

    return None

def clamav_scan_path(path):
    try:
        mode = clamav_mode()

        if mode == "clamd":
            cmd = ["clamdscan", "--no-summary", "-r", path]
        elif mode == "clamscan":
            cmd = ["clamscan", "--no-summary", "-r", path]
        else:
            logging.warning("ClamAV not available")
            return []

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        infected = []
        for line in result.stdout.splitlines():
            if line.endswith("FOUND"):
                infected.append(line)

        return infected

    except subprocess.TimeoutExpired:
        logging.warning("ClamAV scan timeout")
        return []

    except Exception as e:
        logging.error(f"ClamAV scan failed: {e}")
        return None
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(8192), b""):
            h.update(c)
    return h.hexdigest()

def entropy(data):
    if not data:
        return 0
    c = Counter(data)
    l = len(data)
    return -sum((v/l)*math.log2(v/l) for v in c.values())

def extract_strings(data, min_len=6):
    buf, out = b"", []
    for b in data:
        if 32 <= b <= 126:
            buf += bytes([b])
        else:
            if len(buf) >= min_len:
                out.append(buf.decode(errors="ignore"))
            buf = b""
    if len(buf) >= min_len:
        out.append(buf.decode(errors="ignore"))
    return out

def load_whitelist():
    if not os.path.exists(WHITELIST):
        return []
    return [l.strip() for l in open(WHITELIST)]

def is_whitelisted(path):
    rp = os.path.realpath(path)
    for w in load_whitelist():
        w = os.path.realpath(w)
        if rp == w or rp.startswith(w + os.sep):
            return True
    return False

def load_hashes():
    hashes = {}
    if not os.path.exists(HASH_DB):
        return hashes
    with open(HASH_DB) as f:
        for line in f:
            path, h, ts = line.strip().split("|", 2)
            hashes[path] = {"hash": h, "time": ts}
    return hashes

def save_all_hashes(hash_map):
    with open(HASH_DB, "w") as f:
        for path, info in hash_map.items():
            f.write(f"{path}|{info['hash']}|{info['time']}\n")

def blacklist_entry(h, path, status):
    entry = f"{h}|{path}|{status}\n"
    if os.path.exists(BLACKLIST_DB):
        with open(BLACKLIST_DB) as f:
            if entry in f.read():
                return
    with open(BLACKLIST_DB, "a") as f:
        f.write(entry)

# =====================
# VIRUSTOTAL
# =====================
def vt_lookup(sha):
    if not requests:
        return None
    key = os.getenv("VT_API_KEY")
    if not key:
        return None
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha}",
            headers={"x-apikey": key}
        )
        if r.status_code != 200:
            return None
        return r.json()["data"]["attributes"]["last_analysis_stats"]
    except:
        return None

# =====================
# ANALYSIS
# =====================
def analyze(path):
    karma = DEFAULT_KARMA
    reasons = []

    try:
        size = os.path.getsize(path)
        if size > 50 * 1024 * 1024:
            logging.debug(f"SKIP large file: {path}")
            return karma, reasons

        with open(path, "rb") as f:
            data = f.read()

        if not data:
            logging.debug(f"SKIP empty file: {path}")
            return karma, reasons

    except Exception as e:
        logging.debug(f"READ FAIL {path}: {e}")
        return karma, reasons

    # === ENTROPY ===
    e = entropy(data)
    if e > 7.5 and not path.lower().endswith((".zip", ".png", ".jpg", ".gz", ".7z")):
        karma -= 200
        reasons.append("high entropy")
        logging.info(f"[ENTROPY] {path} entropy={e:.2f}")

    # === RCE HEURISTICS ===
    text = data.decode(errors="ignore").lower()

    rce_patterns = {
        "nc": r"\bnc\b",
        "bash": r"bash\s+-c",
        "sh": r"/bin/sh",
        "powershell": r"powershell",
        "curl": r"\bcurl\b",
        "wget": r"\bwget\b",
    }

    for name, pattern in rce_patterns.items():
        if re.search(pattern, text):
            karma -= 500
            reasons.append(f"RCE:{name}")
            logging.warning(f"[RCE HIT] {path} pattern={name}")
            print(f"[RCE HIT] {path} -> {name}")

    # === YARA ===
    try:
        yara_hits = yara_scan(path)
        for rule in yara_hits:
            karma -= 600
            reasons.append(f"YARA:{rule}")
            logging.critical(f"[YARA HIT] {path} rule={rule}")
            print(f"[YARA HIT] {path} -> {rule}")
    except Exception as e:
        logging.error(f"YARA FAIL {path}: {e}")

    logging.debug(f"ANALYZE RESULT {path} karma={karma} reasons={reasons}")
    return karma, reasons
# =====================
# QUARANTINE ANALYSIS
# =====================
def analyze_quarantine(path, sha):
    report = {
        "file": path,
        "sha256": sha,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "size": os.path.getsize(path),
        "entropy": None,
        "strings": [],
        "urls": [],
        "ips": [],
        "vt": None,
        "flags": []
    }

    data = open(path, "rb").read()
    report["entropy"] = entropy(data)
    strings = extract_strings(data)
    report["strings"] = strings[:1000]
    report["urls"] = [s for s in strings if re.search(r"https?://", s)]
    report["ips"] = [s for s in strings if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", s)]

    if report["entropy"] > 7.8:
        report["flags"].append("HIGH_ENTROPY")
    if report["urls"]:
        report["flags"].append("NETWORK_ACTIVITY")

    vt = vt_lookup(sha)
    if vt:
        report["vt"] = vt
        if vt.get("malicious", 0) > 0:
            report["flags"].append("VT_MALICIOUS")

    with open(os.path.join(REPORT_DIR, f"{sha}.json"), "w") as f:
        json.dump(report, f, indent=2)

# =====================
# ACTIONS
# =====================

# =====================
# UPDATE HASHES
# =====================
def update_hashes(root):
    hashes = {}
    for base, _, files in os.walk(root, followlinks=False):
        for f in files:
            path = os.path.join(base, f)
            try:
                h = sha256(path)
                hashes[path] = {"hash": h, "time": datetime.now(timezone.utc).isoformat()}
            except:
                continue
    save_all_hashes(hashes)
    logging.info("Hash database manually updated")
    print("[+] Hash database updated")

# =====================
# SCAN
# =====================
def quarantine(path, h):
    if is_protected(path):
        logging.critical(f"BLOCKED quarantine of protected file: {path}")
        return

    try:
        dest = os.path.join(QUARANTINE_DIR, f"{h}_{os.path.basename(path)}")
        shutil.move(path, dest)
        blacklist_entry(h, path, "IN_QUARANTINE")
        logging.warning(f"Quarantined {path}")
        analyze_quarantine(dest, h)
    except Exception as e:
        logging.error(f"Quarantine failed for {path}: {e}")
        
def scan(root):
    logging.info(f"SCAN START root={root}")

    seen = set()

    #  ВАЖНО: если передан ОДИН ФАЙЛ
    if os.path.isfile(root):
        logging.info(f"SINGLE FILE MODE: {root}")
        _scan_file(root, seen)
        logging.info(f"SCAN END root={root}")
        return

    for base, _, files in os.walk(root, followlinks=False):
        for f in files:
            path = os.path.join(base, f)
            _scan_file(path, seen)

    logging.info(f"SCAN END root={root}")
    
def _scan_file(path, seen):
    # === FILTERS ===
    if is_protected(path):
        logging.debug(f"SKIP protected path: {path}")
        return

    if path.startswith(QUARANTINE_DIR):
        logging.debug(f"SKIP quarantine dir: {path}")
        return

    if is_whitelisted(path):
        logging.debug(f"SKIP whitelisted: {path}")
        return

    try:
        file_hash = sha256(path)
    except Exception as e:
        logging.debug(f"SKIP unreadable file: {path} err={e}")
        return

    dedup_key = (path, file_hash)
    if dedup_key in seen:
        return
    seen.add(dedup_key)

    logging.info(f"ANALYZE {path}")
    print(f"[ANALYZE] {path}")

    karma, reasons = analyze(path)
    reasons = list(reasons)

    if clamav_scan_file(path):
        karma = 0
        reasons.append("ClamAV signature match")
        logging.critical(f"CLAMAV HIT file={path}")

    status = "clean"
    if karma < 200:
        status = "quarantine"
        quarantine(path, file_hash)
    elif karma <= 500:
        status = "blacklist"

    FILES_DB[path] = {
        "hash": file_hash,
        "karma": karma,
        "reasons": reasons,
        "status": status,
        "source": "scan",
        "added_at": datetime.now(timezone.utc).isoformat()
    }

    sync_all_databases(path)
# =====================
# DAEMON
# =====================
def daemon(path, SCAN_INTERVAL):
    logging.info(
    f"FindTheMole daemon started | path={args.path} interval={SCAN_INTERVAL}s"
    )

    try:
        while True:
            start = time.time()

            logging.info("Daemon scan cycle started")
            scan(path)
            update_hashes(path)

            elapsed = time.time() - start
            sleep_time = max(1, SCAN_INTERVAL - int(elapsed))

            logging.info(
                f"Daemon cycle finished in {int(elapsed)}s, sleeping {sleep_time}s"
            )
            time.sleep(sleep_time)

    except KeyboardInterrupt:
        logging.warning("Daemon stopped by user (Ctrl+C)")

# =====================
# CLI
# =====================
def cli():
    parser = argparse.ArgumentParser(
        prog="FindTheMole",
        description="Heuristic malware & stego scanner"
    )
    sub = parser.add_subparsers(dest="cmd")

    # scan
    s = sub.add_parser("scan")
    s.add_argument("path")

    # fullscan (daemon)
    fs = sub.add_parser("fullscan")
    fs.add_argument("path")

    # pardon
    p = sub.add_parser("pardon")
    p.add_argument("target")
    p.add_argument("--hash", action="store_true")
    p.add_argument("--karma", type=int, default=DEFAULT_KARMA)
    # add
    add = sub.add_parser("add")
    add_sub = add.add_subparsers(dest="type")
    aw = add_sub.add_parser("whitelist"); aw.add_argument("path")
    ab = add_sub.add_parser("blacklist"); ab.add_argument("path")
    aq = add_sub.add_parser("quarantine"); aq.add_argument("path")

    # list
    lst = sub.add_parser("list")
    lst.add_argument("type", choices=["whitelist","blacklist","quarantine"])

    # report
    r = sub.add_parser("report")
    r.add_argument("sha256")

    # status
    sub.add_parser("status")

    # update-hashes
    uh = sub.add_parser("update-hashes")
    uh.add_argument("path")

    return parser.parse_args()

# =====================
# MAIN
# =====================
def main():
    init_infested_db()
    args = cli()

    if args.cmd == "scan":
        scan(args.path)
    elif args.cmd == "fullscan":
        daemon(args.path)
    elif args.cmd == "update-hashes":
        update_hashes(args.path)
    elif args.cmd == "pardon":
        pardon(
           target=args.target,
           is_hash=args.hash,
           new_karma=args.karma
        )
    elif args.cmd == "add":
        if args.type == "whitelist":
            with open(WHITELIST, "a") as f:
                f.write(args.path + "\n")
            print("[+] Added to whitelist")
        elif args.type == "blacklist":
            h = sha256(args.path)
            quarantine(args.path, h)
            blacklist_entry(h, args.path, "HIGH_RISK")
            print("[!] Blacklisted & quarantined")
        elif args.type == "quarantine":
            h = sha256(args.path)
            quarantine(args.path, h)
            print("[!] Quarantined")
    elif args.cmd == "list":
        if args.type == "whitelist":
            lines = open(WHITELIST).read().splitlines()
            for l in lines:
                print(l)
        elif args.type == "blacklist":
            lines = open(BLACKLIST_DB).read().splitlines()
            for l in lines:
                print(l)
        elif args.type == "quarantine":
            for f in os.listdir(QUARANTINE_DIR):
                print(f)
    elif args.cmd == "report":
        rp = os.path.join(REPORT_DIR, f"{args.sha256}.json")
        if os.path.exists(rp):
            content = open(rp).read()
            for line in content.splitlines():
                print(line)
        else:
            print("Report not found")
    elif args.cmd == "status":
        print(f"Quarantine files: {len(os.listdir(QUARANTINE_DIR))}")
        print(f"Blacklist entries: {sum(1 for _ in open(BLACKLIST_DB)) if os.path.exists(BLACKLIST_DB) else 0}")
        print(f"Last scan: {time.ctime(os.path.getmtime(LOGFILE))}")
    else:
        print("Use --help")

if __name__ == "__main__":
    print_banner()
    main()
