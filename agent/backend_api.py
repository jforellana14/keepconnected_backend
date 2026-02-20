import requests
import os

BACKEND = os.getenv('BACKEND_URL', 'https://api.keepconnected.io')

def ping_backend():
    r = requests.get(BACKEND)
    print('Backend:', r.status_code)
