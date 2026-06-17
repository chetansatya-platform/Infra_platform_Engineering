import pandas as pd
from ldap3 import Server, Connection, ALL
from ldap3.utils.conv import escape_filter_chars
import getpass
import sys

# ---------------- CONFIG ----------------
AD_SERVER = "AD_Server.example.com"
BASE_DN = "DC=example,DC=com"
INPUT_FILE = "servers.txt"
OUTPUT_FILE = "ad_check_results.xlsx"
CHUNK_SIZE = 50  # Process 50 hostnames at a time
# --------------------------------------

def parse_ad_timestamp(timestamp_value):
    """Converts LDAP datetime object into a clean string."""
    if not timestamp_value:
        return "Never"
    if hasattr(timestamp_value, 'strftime'):
        return timestamp_value.strftime('%Y-%m-%d %H:%M:%S')
    return str(timestamp_value)

# Prompt for credentials
username = input("Enter AD Username (WMT\\user or user@wmt.com): ")
password = getpass.getpass("Enter Password: ")

try:
    with open(INPUT_FILE, "r") as f:
        servers = []
        for line in f:
            # Clean spaces and force uppercase
            clean = line.strip().split('.')[0].upper()
            if clean:
                servers.append(clean)
        # Remove duplicate hostnames
        servers = list(set(servers))
except FileNotFoundError:
    print(f"Error: {INPUT_FILE} not found. Please create this file in the same folder.")
    sys.exit(1)

ad_data = {}
server = Server(AD_SERVER, get_info=ALL)

try:
    # Use auto_bind=True to establish and validate the credentials immediately
    with Connection(server, user=username, password=password, auto_bind=True) as conn:
        for i in range(0, len(servers), CHUNK_SIZE):
            chunk = servers[i:i + CHUNK_SIZE]
            
            # Match strictly by the short hostname machine account: (sAMAccountName=HOSTNAME$)
            filter_parts = [f"(sAMAccountName={escape_filter_chars(srv)}$)" for srv in chunk]
            search_filter = f"(|{''.join(filter_parts)})"

            conn.search(
                search_base=BASE_DN,
                search_filter=search_filter,
                attributes=['cn', 'sAMAccountName', 'dNSHostName', 'operatingSystem', 'pwdLastSet', 'distinguishedName']
            )

            for entry in conn.entries:
                sam_name = str(entry.sAMAccountName).upper().rstrip('$')
                ad_data[sam_name] = {
                    "AD Object Name": str(entry.cn),
                    "FQDN": str(entry.dNSHostName) if 'dNSHostName' in entry else "N/A",
                    "DN Path": str(entry.distinguishedName),
                    "OS": str(entry.operatingSystem) if 'operatingSystem' in entry else "N/A",
                    "Password Last Set": parse_ad_timestamp(entry.pwdLastSet.value)
                }
except Exception as e:
    print(f"LDAP Connection Error: {e}")
    sys.exit(1)

# Map results back to original list to catch "Not Found" servers
results = []
for srv in servers:
    if srv in ad_data:
        results.append({
            "Search Hostname": srv,
            "Server FQDN": ad_data[srv]["FQDN"],
            "AD Object Name": ad_data[srv]["AD Object Name"],
            "AD Location (DN)": ad_data[srv]["DN Path"],
            "Operating System": ad_data[srv]["OS"],
            "Password Last Set": ad_data[srv]["Password Last Set"],
            "Status": "Found"
        })
    else:
        results.append({
            "Search Hostname": srv,
            "Server FQDN": "",
            "AD Object Name": "",
            "AD Location (DN)": "",
            "Operating System": "",
            "Password Last Set": "",
            "Status": "Not Found"
        })

# Export to Excel
df = pd.DataFrame(results)
df.to_excel(OUTPUT_FILE, index=False)
print(f"Done. Processed {len(servers)} short hostnames. Output saved to {OUTPUT_FILE}.")
