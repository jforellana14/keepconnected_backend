import os
import json
import time
import random
from datetime import datetime, timedelta
from typing import Dict, Any, List

import requests

# Selenium
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

BACKEND_URL = os.getenv("BACKEND_URL", "https://api.keepconnected.io").rstrip("/")

def now_local() -> datetime:
    return datetime.now()

def load_state(path: str) -> Dict[str, Any]:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_state(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def fetch_config(agent_token: str) -> Dict[str, Any]:
    r = requests.get(
        BACKEND_URL + "/agent/config",
        headers={"Authorization": f"Bearer {agent_token}"},
        timeout=30
    )
    r.raise_for_status()
    return r.json()

def is_day_enabled(settings: Dict[str, Any], dt: datetime) -> bool:
    days = settings.get("days_enabled")
    if not days:
        days = [0,1,2,3,4,5]
    return dt.weekday() in days

def get_windows(settings: Dict[str, Any]):
    return settings.get("windows") or [
        {"key": "morning", "enabled": True, "start": "09:00", "end": "11:00"},
        {"key": "evening", "enabled": True, "start": "16:00", "end": "18:00"},
        {"key": "night",   "enabled": False, "start": "20:00", "end": "22:00"},
    ]

def parse_hhmm(s: str, base: datetime):
    hh, mm = s.split(":")
    return base.replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)

def min_gap(settings: Dict[str, Any]) -> float:
    return float(settings.get("min_gap_hours", 2))

def max_per_day(settings: Dict[str, Any]) -> int:
    return int(settings.get("max_messages_per_day", 3))

def random_time(start: datetime, end: datetime) -> datetime:
    delta = int((end - start).total_seconds())
    if delta <= 0:
        delta = 60
    return start + timedelta(seconds=random.randint(1, delta))

def count_sent_today(state: Dict[str, Any], today: str) -> int:
    return len(list((state.get("sent", {}).get(today, {}) or {}).values()))

def mark_sent(state: Dict[str, Any], key: str, today: str):
    state.setdefault("sent", {}).setdefault(today, {})[key] = True
    state["last_sent_at"] = now_local().isoformat()

def last_sent(state: Dict[str, Any]):
    s = state.get("last_sent_at")
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except:
        return None

def pick_slots(settings: Dict[str, Any], plan: str) -> List[Dict[str, Any]]:
    slots = settings.get("slots") or []

    plan = (plan or "basic").lower()
    if plan == "basic":
        max_slots = 1
        max_groups = 0
    elif plan == "pro":
        max_slots = 2
        max_groups = 1
    else:
        max_slots = 5
        max_groups = 3

    contacts = [s for s in slots if s.get("type") == "contact"]
    groups = [s for s in slots if s.get("type") == "group"]

    groups = groups[:max_groups]
    merged = (contacts + groups)[:max_slots]
    return merged

def pick_message(settings: Dict[str, Any], key: str) -> str:
    msgs = (settings.get("messages") or {}).get(key) or []

    if not msgs:
        fallback = {
            "morning": ["Buenos dÃ­as!"],
            "evening": ["Buenas tardes! CÃ³mo vas?"],
            "night":   ["Buenas noches, que descanses!"],
        }
        msgs = fallback.get(key, ["Hola!"])

    return random.choice(msgs)

def open_driver(profile_dir: str):
    opts = Options()
    opts.add_argument("--disable-notifications")
    opts.add_argument(f"--user-data-dir={profile_dir}")
    opts.add_argument("--lang=es")
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)

    service = Service(ChromeDriverManager().install())
    return webdriver.Chrome(service=service, options=opts)

def send_whatsapp(driver, slot: Dict[str, Any], msg: str):
    driver.get("https://web.whatsapp.com/")
    time.sleep(6)

    phone = slot.get("phone")
    name = slot.get("name") or ""
    stype = slot.get("type") or "contact"

    # --- Preferred: direct send via phone
    if stype == "contact" and phone:
        import urllib.parse as up
        txt = up.quote(msg)
        driver.get(f"https://web.whatsapp.com/send?phone={phone.replace('+','')}&text={txt}")
        time.sleep(6)
        try:
            active = driver.switch_to.active_element
            active.send_keys(Keys.ENTER)
            time.sleep(2)
            return
        except:
            pass

    # --- Fallback: search bar
    search_selectors = [
        'div[contenteditable="true"][data-tab="3"]',
        'div[contenteditable="true"][role="textbox"]'
    ]

    search = None
    for css in search_selectors:
        try:
            elems = driver.find_elements(By.CSS_SELECTOR, css)
            if elems:
                search = elems[0]
                break
        except:
            pass

    if not search:
        raise RuntimeError("No pude localizar el buscador de WhatsApp Web.")

    search.click()
    time.sleep(1)
    search.send_keys(name)
    time.sleep(2)
    search.send_keys(Keys.ENTER)
    time.sleep(2)

    msg_selectors = [
        'div[contenteditable="true"][data-tab="10"]',
        'div[contenteditable="true"][role="textbox"]'
    ]

    box = None
    for css in msg_selectors:
        try:
            elems = driver.find_elements(By.CSS_SELECTOR, css)
            if elems:
                box = elems[-1]
                break
        except:
            pass

    if not box:
        raise RuntimeError("No pude encontrar el input de mensaje.")

    box.click()
    box.send_keys(msg)
    time.sleep(0.5)
    box.send_keys(Keys.ENTER)
    time.sleep(1.5)
def loop(agent_token: str, profile_dir: str, state_path: str):
    state = load_state(state_path)
    print("Agent running with backend:", BACKEND_URL)

    while True:
        cfg = fetch_config(agent_token)
        settings = cfg.get("settings") or {}
        plan = cfg.get("plan") or "basic"

        dt = now_local()
        today = dt.strftime("%Y-%m-%d")

        # Day
        if not is_day_enabled(settings, dt):
            time.sleep(60)
            continue

        # Count today
        if count_sent_today(state, today) >= max_per_day(settings):
            time.sleep(60)
            continue

        # Gap
        last_dt = last_sent(state)
        if last_dt and (dt - last_dt).total_seconds() < (min_gap(settings) * 3600):
            time.sleep(60)
            continue

        windows = [w for w in get_windows(settings) if w.get("enabled") is True]
        sent_any = False

        for w in windows:
            key = w.get("key")
            if not key:
                continue

            if state.get("sent", {}).get(today, {}).get(key):
                continue

            start = parse_hhmm(w.get("start", "09:00"), dt)
            end   = parse_hhmm(w.get("end", "11:00"), dt)

            if dt < start or dt > end:
                continue

            # random wait inside window
            t2 = random_time(dt, end)
            wait = max(5, int((t2 - dt).total_seconds()))
            print(f"[{key}] Waiting {wait}s before sending...")
            time.sleep(wait)

            # re-check
            dt2 = now_local()
            today2 = dt2.strftime("%Y-%m-%d")

            if not is_day_enabled(settings, dt2):
                continue
            if count_sent_today(state, today2) >= max_per_day(settings):
                continue

            slots = pick_slots(settings, plan)
            if not slots:
                print("No slots configured")
                time.sleep(60)
                continue

            slot = random.choice(slots)
            msg  = pick_message(settings, key)

            try:
                driver = open_driver(profile_dir)
                send_whatsapp(driver, slot, msg)
                driver.quit()

                mark_sent(state, key, today2)
                save_state(state_path, state)
                print("Sent", key, "to", slot.get("name"))
                sent_any = True
            except Exception as e:
                try:
                    driver.quit()
                except:
                    pass
                print("Send error:", str(e))

        if not sent_any:
            time.sleep(60)

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-token", required=True)
    ap.add_argument("--profile-dir", default=os.path.abspath("./agent_profile"))
    ap.add_argument("--state", default=os.path.abspath("./agent_state.json"))
    args = ap.parse_args()

    os.makedirs(args.profile_dir, exist_ok=True)
    loop(args.agent_token, args.profile_dir, args.state)

if __name__ == "__main__":
    main()
