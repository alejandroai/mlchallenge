import hashlib

class Finding:
    def __init__(self, name, analyzer, line_number, severity, extra_data=""):
        self.name = name
        self.analyzer = analyzer
        self.line_number = line_number
        self.severity = severity
        self.extra_data = extra_data

    def to_json(self):
        return json.dumps({
            "name": self.name,
            "analyzer": self.analyzer,
            "line_number": self.line_number,
            "severity": self.severity,
            "extra_data": self.extra_data
        }, indent=4)

    def to_string(self):
        return (
            f"name: {self.name},"
            f"analyzer: {self.analyzer},"
            f"line_number: {self.line_number},"
            f"severity: {self.severity},"
            f"extra_data: {self.extra_data}"
        )

def pwd_finder(config_data, device_type):
    findings = []
    black_list = ["cisco", "admin", "switch", "NOMBRE_EMPRESA", "root", "redes", "networking"]

    def verify_cisco_type5(encrypted_password, plaintext_password):
        parts = encrypted_password.split('$')
        if len(parts) != 4 or parts[1] != '1':
            raise ValueError("Formato de hash Tipo 5 no válido.")
        
        salt = parts[2]
        stored_hash = parts[3]
        salted_password = salt + plaintext_password
        md5_hash = hashlib.md5(salted_password.encode()).hexdigest()
        return md5_hash == stored_hash

    def evaluate_cisco_pwd(type_pwd, psswd, line_number):
        local_findings = []
        if type_pwd == "0" or type_pwd == "":
            local_findings.append(Finding("Plain text password", "pwd_finder", line_number, "HIGH"))
            for pwd_black in black_list:
                if psswd.find(pwd_black) >= 0:
                    local_findings.append(Finding("Insecure/common password", "pwd_finder", line_number, "HIGH"))
        elif type_pwd == "5":
            local_findings.append(Finding("MD5 password", "pwd_finder", line_number, "MEDIUM"))
            for pwd_black in black_list:
                if verify_cisco_type5(psswd, pwd_black):
                    local_findings.append(Finding("Insecure/common password", "pwd_finder", line_number, "HIGH"))
        elif type_pwd == "7":
            local_findings.append(Finding("Reversible cipher stored password", "pwd_finder", line_number, "LOW"))
        return local_findings

    line_number = 0
    for line in config_data.splitlines():
        if len(line) > 0 and line[0] != "!":
            line = line.strip()
            splitted_line = line.split(" ")
            if (splitted_line[0] == "username" or (splitted_line[0] == "enable" and splitted_line[1] == "password") or splitted_line[0] == "password"):
                try:
                    password_pos = splitted_line.index("password")
                    if password_pos == -1:
                        password_pos = splitted_line.index("secret")
                    password = ""
                    cisco_pwd_type = ""
                    if len(splitted_line[password_pos + 1]) == 1:
                        cisco_pwd_type = splitted_line[password_pos + 1]
                        password = splitted_line[password_pos + 2]
                    else:
                        cisco_pwd_type = "0"
                        password = splitted_line[password_pos + 1]
                    password_finding = evaluate_cisco_pwd(cisco_pwd_type, password, line_number)
                    findings.extend(password_finding)
                except:
                    pass
        line_number += 1

    return findings

def cisco_good_practice(config_data, device_type):
    local_findings = []
    if device_type != "switch":
        return []
    
    found_aaa_setting = False
    found_logging_on = False
    found_archive = False
    found_rsyslog = False
    dhcp_enabled = True
    line_number = 0

    for line in config_data.splitlines():
        if len(line) > 0:
            stripped_line = line.strip()
            if stripped_line == "logging on":
                found_logging_on = True
            elif stripped_line == "archive" or stripped_line == "log config":
                found_archive = True
            elif stripped_line == "aaa new-model":
                found_aaa_setting = True
            elif stripped_line == "logging host":
                found_rsyslog = True
            elif stripped_line.startswith("ip address"):
                dhcp_enabled = False
        line_number += 1

    if not found_aaa_setting:
        local_findings.append(Finding("Only local users are used", "cisco_good_practice", line_number, "LOW"))
    if not found_logging_on:
        local_findings.append(Finding("Logging not enabled", "cisco_good_practice", line_number, "LOW"))
    if not found_archive:
        local_findings.append(Finding("No logs for configuration", "cisco_good_practice", line_number, "LOW"))
    if not found_rsyslog:
        local_findings.append(Finding("No remote syslog configured", "cisco_good_practice", line_number, "LOW"))
    if dhcp_enabled:
        local_findings.append(Finding("DHCP for admin interface enabled", "cisco_good_practice", line_number, "HIGH"))

    return local_findings

def cisco_interfaces_vlan(config_data, device_type):
    def analyze_current_config(config_lines, current_config_name):
        local_findings = []
        try:
            if current_config_name == "interface":
                if config_lines[0].split()[1] == "vlan":
                    acl_enabled = False
                    for l in config_lines:
                        l = l.strip()
                        if l.startswith("ip access-group"):
                            acl_enabled = True
                    if not acl_enabled:
                        vlan = config_lines[0].split()[2]
                        local_findings.append(Finding("No ACL defined for vlan", "cisco_interfaces_vlan", line_number, "HIGH", "vlan " + vlan))
                else:
                    need_vlan = True
                    has_stp = False
                    for l in config_lines:
                        l = l.strip()
                        if l.startswith("switchport access vlan") or l.startswith("switchport mode trunk") or l.startswith("switchport voice"):
                            need_vlan = False
                        if l.startswith("switchport access vlan"):
                            has_stp = True
                    if need_vlan:
                        port = config_lines[0].split()[1]
                        local_findings.append(Finding("No VLAN defined for access port", "cisco_interfaces_vlan", line_number, "HIGH", "port: " + port))
                    if not has_stp:
                        port = config_lines[0].split()[1]
                        local_findings.append(Finding("No Spanning Tree Protocol for port", "cisco_interfaces_vlan", line_number, "HIGH", "port: " + port))
        except:
            pass
        return local_findings

    local_findings = []
    if device_type != "switch":
        return []

    line_number = 0
    current_config_name = ""
    config_lines = []
    for line in config_data.splitlines():
        line = line.strip()
        if len(line) > 0:
            if line[0] == "!" and current_config_name != "":
                local_findings.extend(analyze_current_config(config_lines, current_config_name))
                config_lines = []
                current_config_name = ""
            elif current_config_name == "":
                current_config_name = line.split(" ")[0]
                config_lines.append(line)
            else:
                config_lines.append(line)
        line_number += 1

    return local_findings

def create_analyzer_dict():
    analyzers = {
        "switch": [pwd_finder, cisco_good_practice, cisco_interfaces_vlan],
        "router": [pwd_finder]
    }
    return analyzers

def analyze_device(config_data, device_type):
    analyzers = create_analyzer_dict()
    findings = []
    if device_type not in analyzers:
        raise Exception("There is no analyzer for this type of device")
    for analyzer in analyzers[device_type]:
        findings.extend(analyzer(config_data, device_type))
    return findings