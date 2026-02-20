import json
import os
import time
import uuid
import random
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

import requests

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "agent_config.json")


def now_local() -> datetime:
    # Por ahora usamos la hora local del PC (luego usamos timezone del backend si quieres)
    return datetime.now()


def load_config() -> Dict[str, Any]:
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg: Dict[str, Any]) -> None:
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def ensure_device_id(cfg: Dict[str, Any]) -> str:
    if cfg.get("device_id"):
        return cfg["device_id"]
    did = "PC-" + uuid.uuid4().hex[:12]
    cfg["device_id"] = did
    save_config(cfg)
    return did


def api_headers(agent_token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {agent_token}"}


def claim_activation_token(base_url: str, activation_token: str, device_id: str) -> str:
    url = base_url.rstrip("/") + "/activate/claim"
    r = requests.post(url, json={"activation_token": activation_token, "device_id": device_id}, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Claim failed: HTTP {r.status_code} | {r.text}")
    data = r.json()
    token = data.get("agent_token")
    if not token:
        raise RuntimeError(f"Claim response missing agent_token: {data}")
    return token


def fetch_agent_config(base_url: str, agent_token: str) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/agent/config"
    r = requests.get(url, headers=api_headers(agent_token), timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Config failed: HTTP {r.status_code} | {r.text}")
    return r.json()


def heartbeat(base_url: str, agent_token: str) -> None:
    url = base_url.rstrip("/") + "/agent/heartbeat"
    requests.post(url, json={"status": "ok"}, headers=api_headers(agent_token), timeout=30)


def report_sent(base_url: str, agent_token: str, window: str, sent_at: Optional[datetime] = None) -> None:
    url = base_url.rstrip("/") + "/agent/report"
    payload = {"window": window}
    if sent_at:
        payload["sent_at"] = sent_at.isoformat()
    requests.post(url, json=payload, headers=api_headers(agent_token), timeout=30)


def in_window(dt: datetime, start_hhmm: str, end_hhmm: str) -> bool:
    sh, sm = [int(x) for x in start_hhmm.split(":")]
    eh, em = [int(x) for x in end_hhmm.split(":")]
    start = dt.replace(hour=sh, minute=sm, second=0, microsecond=0)
    end = dt.replace(hour=eh, minute=em, second=0, microsecond=0)
    return start <= dt <= end


def weekday_key(dt: datetime) -> str:
    # monday=0 ... sunday=6
    keys = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
    return keys[dt.weekday()]


def should_send(cfg: Dict[str, Any], window_name: str, last_sent_key: str) -> bool:
    dt = now_local()
    if not cfg.get("enabled", False):
        return False

    # Sunday no messages (por config vendría sin "sun" en days)
    wcfg = cfg.get(window_name)
    if not wcfg:
        return False

    if weekday_key(dt) not in wcfg.get("days", []):
        return False

    if not in_window(dt, wcfg["start"], wcfg["end"]):
        return False

    # one message per window per day
    last = cfg.get(last_sent_key)
    if last:
        try:
            last_dt = datetime.fromisoformat(last)
            if last_dt.date() == dt.date():
                return False
        except Exception:
            pass

    # Random delay inside window: 0–20 minutes (simple)
    # Guardamos una "scheduled_time" por ventana para no recalcular cada loop
    sched_key = f"{window_name}_scheduled_at"
    sched_val = cfg.get(sched_key)
    if not sched_val:
        delay_min = random.randint(0, 20)
        sched_dt = dt + timedelta(minutes=delay_min)
        cfg[sched_key] = sched_dt.isoformat()
        save_config(cfg)
        return False

    try:
        sched_dt = datetime.fromisoformat(sched_val)
    except Exception:
        cfg.pop(sched_key, None)
        save_config(cfg)
        return False

    if dt >= sched_dt:
        # ready to send
        return True

    return False


def mark_sent(cfg: Dict[str, Any], window_name: str, last_sent_key: str) -> None:
    dt = now_local()
    cfg[last_sent_key] = dt.isoformat()
    cfg.pop(f"{window_name}_scheduled_at", None)
    save_config(cfg)


def main():
    local_cfg = load_config()

    print("KeepConnected Agent (CLI)")
    print("-------------------------")

    if not local_cfg.get("base_url"):
        base_url = input("Backend URL (ej: https://api.keepconnected.io o http://127.0.0.1:8000): ").strip()
        local_cfg["base_url"] = base_url
        save_config(local_cfg)

    base_url = local_cfg["base_url"]
    device_id = ensure_device_id(local_cfg)

    if not local_cfg.get("agent_token"):
        print(f"Device ID: {device_id}")
        activation_token = input("Pega tu Activation Token (kc_live_...): ").strip()
        agent_token = claim_activation_token(base_url, activation_token, device_id)
        local_cfg["agent_token"] = agent_token
        save_config(local_cfg)
        print("✅ Activado. Agent token guardado.")

    agent_token = local_cfg["agent_token"]

    # Loop principal
    while True:
        try:
            server_cfg = fetch_agent_config(base_url, agent_token)

            # Unimos config del server a config local
            local_cfg["enabled"] = bool(server_cfg.get("enabled", True))
            local_cfg["morning"] = server_cfg.get("morning", {})
            local_cfg["evening"] = server_cfg.get("evening", {})
            save_config(local_cfg)

            heartbeat(base_url, agent_token)

            # Morning
            if should_send(local_cfg, "morning", "last_morning_sent"):
                # Aquí luego conectamos WhatsApp real
                print(f"[{now_local().isoformat()}] Sending MORNING message (SIMULATION)")
                report_sent(base_url, agent_token, "morning", now_local())
                mark_sent(local_cfg, "morning", "last_morning_sent")

            # Evening
            if should_send(local_cfg, "evening", "last_evening_sent"):
                print(f"[{now_local().isoformat()}] Sending EVENING message (SIMULATION)")
                report_sent(base_url, agent_token, "evening", now_local())
                mark_sent(local_cfg, "evening", "last_evening_sent")

        except Exception as e:
            print(f"[{now_local().isoformat()}] ERROR: {e}")

        time.sleep(300)  # every 5 minutes


if __name__ == "__main__":
    main()
