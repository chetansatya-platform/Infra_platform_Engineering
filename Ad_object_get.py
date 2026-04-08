import pandas as pd
from ldap3 import Server, Connection, ALL
import getpass

# ---------------- CONFIG ----------------
AD_SERVER = "yourdomain.com"
BASE_DN = "DC=yourdomain,DC=com"
INPUT_FILE = "servers.txt"
OUTPUT_FILE = "ad_check_results.xlsx"
# --------------------------------------


# Prompt for credentials
username = input("Enter AD Username (DOMAIN\\user): ")
password = getpass.getpass("Enter Password: ")


# Read server names
with open(INPUT_FILE, "r") as f:
    servers = [line.strip() for line in f if line.strip()]


# Connect to AD
server = Server(AD_SERVER, get_info=ALL)
conn = Connection(server, user=username, password=password, auto_bind=True)

results = []

for srv in servers:
    search_filter = f"(sAMAccountName={srv}$)"

    conn.search(
        search_base=BASE_DN,
        search_filter=search_filter,
        attributes=['cn']
    )

    if conn.entries:
        for entry in conn.entries:
            results.append({
                "Server Name": srv,
                "AD Object Name": str(entry.cn),
                "Status": "Found"
            })
    else:
        results.append({
            "Server Name": srv,
            "AD Object Name": "",
            "Status": "Not Found"
        })


# Export to Excel
df = pd.DataFrame(results)
df.to_excel(OUTPUT_FILE, index=False)

print("Done. Results saved to Excel.")
