import requests
import hashlib
import time
import os

def check_license(license_key, local_key=''):
    # Configuration Values
    whmcs_url = 'http://www.portal.stallioninternet.com/'
    licensing_secret_key = 'Jordan#2014$'
    local_key_days = 15
    allow_check_fail_days = 5

    # Local key validation
    local_key_valid = False
    if local_key:
        local_key = local_key.replace("\n", '')
        local_data = local_key[:-32]
        md5_hash = local_key[-32:]
        if md5_hash == hashlib.md5((local_data + licensing_secret_key).encode()).hexdigest():
            local_data = local_data[::-1]
            md5_hash = local_data[:32]
            local_data = local_data[32:]
            local_data = base64.b64decode(local_data)
            local_key_results = pickle.loads(local_data)
            original_check_date = local_key_results['checkdate']
            if md5_hash == hashlib.md5((original_check_date + licensing_secret_key).encode()).hexdigest():
                local_expiry = (datetime.datetime.now() - datetime.timedelta(days=local_key_days)).strftime("%Y%m%d")
                if original_check_date > local_expiry:
                    local_key_valid = True
                    results = local_key_results
                    valid_domains = results['validdomain'].split(',')
                    if os.environ.get('SERVER_NAME') not in valid_domains:
                        local_key_valid = False
                        results['status'] = "Invalid"
                        results = {}
                    valid_ips = results['validip'].split(',')
                    if os.environ.get('SERVER_ADDR') not in valid_ips:
                        local_key_valid = False
                        results['status'] = "Invalid"
                        results = {}
                    valid_dirs = results['validdirectory'].split(',')
                    if os.path.dirname(__file__) not in valid_dirs:
                        local_key_valid = False
                        results['status'] = "Invalid"
                        results = {}
    if not local_key_valid:
        check_token = str(int(time.time())) + hashlib.md5(str(random.randint(1000000000, 9999999999)).encode() + license_key.encode()).hexdigest()
        postfields = {
            'licensekey': license_key,
            'domain': os.environ.get('SERVER_NAME'),
            'ip': os.environ.get('SERVER_ADDR') or os.environ.get('LOCAL_ADDR'),
            'dir': os.path.dirname(__file__),
        }
        if check_token:
            postfields['check_token'] = check_token
        try:
            response = requests.post(whmcs_url + 'modules/servers/licensing/verify.php', data=postfields, timeout=30)
            data = response.text
        except requests.exceptions.RequestException as e:
            data = None
        if not data:
            local_expiry = (datetime.datetime.now() - datetime.timedelta(days=(local_key_days + allow_check_fail_days))).strftime("%Y%m%d")
            if original_check_date > local_expiry:
                results = local_key_results
            else:
                results = {}
                results['status'] = "Invalid"
                results['description'] = "Remote Check Failed"
                return results
        else:
            matches = re.findall(r'<(.*?)>([^<]+)</\1>', data)
            results = {}
            for match in matches:
                results[match[0]] = match[1]
        if not isinstance(results, dict):
            raise ValueError("Invalid License Server Response")
        if results.get('md5hash'):
            if results['md5hash'] != hashlib.md5((licensing_secret_key + check_token).encode()).hexdigest():
                results['status'] = "Invalid"
                results['description'] = "MD5 Checksum Verification Failed"
                return results
        if results.get('status') == "Active":
            results['checkdate'] = time.strftime("%Y%m%d")
            data_encoded = base64.b64encode(pickle.dumps(results)).decode()
            data_encoded = hashlib.md5((time.strftime("%Y%m%d") + licensing_secret_key).encode()).hexdigest() + data_encoded
            data_encoded = data_encoded[::-1]
            data_encoded = data_encoded + hashlib.md5((data_encoded + licensing_secret_key).encode()).hexdigest()
            data_encoded = '\n'.join(textwrap.wrap(data_encoded, 80))
            results['localkey'] = data_encoded
        results['remotecheck'] = True
    return results

# Get the license key and local key from storage
# These are typically stored either in flat files or an SQL database

license_key = ""
local_key = ""
base_dir = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(base_dir, "license.txt"), "r") as file:
    lines = file.readlines()
    license_key = lines[0].strip()
    local_key = lines[1].strip()

print(license_key)
print(local_key)

# Validate the license key information
results = check_license(license_key, local_key)

# Raw output of results for debugging purpose
print(results)

# Interpret response
status = results.get('status')
if status == "Active":
    # get new local key and save it somewhere
    local_key_data = ''.join(results['localkey'].split())
    with open(os.path.join(base_dir, "license.txt"), "r") as file:
        license_key = file.readline().strip()

    with open(os.path.join(base_dir, "license.txt"), "w") as file:
        file.write(license_key + "\n" + local_key_data + "\n")
elif status == "Invalid":
    print("License key is Invalid")
elif status == "Expired":
    print("License key is Expired")
elif status == "Suspended":
    print("License key is Suspended")
else:
    print("Invalid Response")
