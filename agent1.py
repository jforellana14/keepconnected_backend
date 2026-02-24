import requests
import time
import sys

BACKEND = "http://127.0.0.1:8000"

def get_user(token):
    r = requests.get(f"{BACKEND}/me", params={"token": token})
    if r.status_code != 200:
        return None
    return r.json()

def get_limits(token):
    r = requests.get(f"{BACKEND}/plan-limits", params={"token": token})
    if r.status_code != 200:
        return None
    return r.json()

def main():
    token = input("🔑 Introduce tu token: ")

    while True:
        user = get_user(token)

        if not user:
            print("❌ Token inválido")
            sys.exit()

        if not user["plan"]:
            print("⛔ Plan inactivo. Esperando renovación...")
            time.sleep(10)
            continue

        print(f"✅ Plan activo: {user['plan']}")

        limits = get_limits(token)
        print(f"📊 Límites: {limits}")

        print("🚀 Agente operativo...")
        time.sleep(15)

if __name__ == "__main__":
    main()