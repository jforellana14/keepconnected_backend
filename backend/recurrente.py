import os
from typing import Dict

def plan_store_link(plan: str, period: str) -> str:
    plan = (plan or "basic").lower()
    period = (period or "monthly").lower()

    env_map = {
        "basic": {
            "monthly": os.getenv("STORE_BASIC_MONTHLY_LINK", ""),
            "yearly":  os.getenv("STORE_BASIC_YEARLY_LINK", "")
        },
        "pro": {
            "monthly": os.getenv("STORE_PRO_MONTHLY_LINK", ""),
            "yearly":  os.getenv("STORE_PRO_YEARLY_LINK", "")
        },
        "premium": {
            "monthly": os.getenv("STORE_PREMIUM_MONTHLY_LINK", ""),
            "yearly":  os.getenv("STORE_PREMIUM_YEARLY_LINK", "")
        }
    }

    return env_map.get(plan, {}).get(period, "")

def product_ids() -> Dict[str, Dict[str, str]]:
    return {
        "basic": {
            "monthly": os.getenv("PROD_BASIC_MONTHLY", ""),
            "yearly":  os.getenv("PROD_BASIC_YEARLY", "")
        },
        "pro": {
            "monthly": os.getenv("PROD_PRO_MONTHLY", ""),
            "yearly":  os.getenv("PROD_PRO_YEARLY", "")
        },
        "premium": {
            "monthly": os.getenv("PROD_PREMIUM_MONTHLY", ""),
            "yearly":  os.getenv("PROD_PREMIUM_YEARLY", "")
        }
    }
