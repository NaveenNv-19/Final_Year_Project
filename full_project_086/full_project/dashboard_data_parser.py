import pandas as pd
import re
import requests

# Parser for the creds file. Returns IP Address, Username, Password.
def parse_creds_audits_log(log_file_path):
    data = []
    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if line:  # Skip empty lines
                    parts = line.split(',')
                    if len(parts) >= 3:  # Ensure at least IP, username, password
                        ip_address = parts[0].strip()
                        username = parts[1].strip()
                        password = parts[2].strip()
                        data.append({'ip_address': ip_address, 'username': username, 'password': password})
                    else:
                        print(f"Skipping malformed line: {line} - Expected format: IP,Username,Password")
    except FileNotFoundError:
        print(f"Log file not found: {log_file_path}")
    except Exception as e:
        print(f"Error parsing log file: {e}")
    return pd.DataFrame(data) if data else pd.DataFrame(columns=['ip_address', 'username', 'password'])

# Parser for commands entered during SSH session.
def parse_cmd_audits_log(cmd_audits_log_file):
    data = []
    
    with open(cmd_audits_log_file, 'r') as file:
        for line in file:
           
            pattern = re.compile(r'Command\s*"([^"]*)"\s*executed\s*by\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            match = pattern.search(line.strip())
            if match:
                command, ip = match.groups()
                data.append({'IP Address': ip, 'Command': command})
    df = pd.DataFrame(data)
    
    return df

def top_10_calculator(dataframe, column):
    top_10_df = pd.DataFrame(columns=[column, "count"])
    if dataframe is not None and not dataframe.empty:
        if column in dataframe.columns:
            top_10_df = dataframe[column].value_counts().reset_index().head(10)
            top_10_df.columns = [column, "count"]
    return top_10_df

def get_country_code(ip):

    data_list = []

    url = f"https://api.cleantalk.org/?method_name=ip_info&ip={ip}"
    try:
        response = requests.get(url)
        api_data = response.json()
        if response.status_code == 200:
            data = response.json()
            ip_data = data.get('data', {})
            country_info = ip_data.get(ip, {})
            data_list.append({'IP Address': ip, 'Country_Code': country_info.get('country_code')})
        elif response.status_code == 429:
            print(api_data["error_message"])
            print(f"[!] CleanTalk IP->Geolocation Rate Limited Exceeded.\n Please wait 60 seconds or turn Country=False (default).\n {response.status_code}")
        else:
            print(f"[!] Error: Unable to retrieve data for IP {ip}. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")

    return data_list

def ip_to_country_code(dataframe):

    data = []

    for ip in dataframe['ip_address']:
        get_country = get_country_code(ip)
        parse_get_country = get_country[0]["Country_Code"]
        data.append({"IP Address": ip, "Country_Code": parse_get_country})
    
    df = pd.DataFrame(data)
    return df