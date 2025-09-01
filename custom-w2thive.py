#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-

import os, sys, json, logging, traceback, uuid
# ---------------- logging ----------------
LOG_PATH = "/var/ossec/logs/integrations.log"
logging.basicConfig(filename=LOG_PATH, level=logging.INFO,
                    format="%(asctime)s %(levelname)s custom-w2thive: %(message)s")

# ---------------- config ----------------
THEHIVE_VERIFY_TLS = os.getenv("THEHIVE_VERIFY_TLS", "true").lower() in ("1","true","yes","on")
PROMOTE_TO_CASE = os.getenv("PROMOTE_TO_CASE", "1").lower() in ("1","true","yes","on")  # <- по умолчанию ВКЛ
DEFAULT_TLP = int(os.getenv("DEFAULT_TLP", "2"))
DEFAULT_SEVERITY = int(os.getenv("DEFAULT_SEVERITY", "2"))  # 1..3
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "30"))

# Шаблоны (как у тебя)
TEMPLATE_MAP = {
    "bruteforce": "Brute Force / Password Spray",
    "success_logon": "Suspicious Successful Logon",
    "kerberos": "Kerberos Pre-Auth Failures",
    "privesc": "Privilege Escalation Attempt",
    "acct_create": "Suspicious Account Creation",
    "service_install": "Suspicious Service Installation",
    "recon": "Directory Enumeration",
    "policy": "Policy Tampering",
    "exfil": "Suspicious File Access / Exfiltration",
    "admin_logon": "Unusual Admin Logon",
    "default": "Generic AD Incident"
}

# (опционально) Серьёзность по шаблону
TEMPLATE_SEVERITY = {
    "bruteforce": 2,
    "success_logon": 2,
    "kerberos": 2,
    "privesc": 3,
    "acct_create": 3,
    "service_install": 3,
    "recon": 2,
    "policy": 3,
    "exfil": 3,
    "admin_logon": 2,
    "default": DEFAULT_SEVERITY
}

# ---------------- optional deps ----------------
THEHIVE4PY_AVAILABLE = False
Alert = AlertArtifact = TheHiveApi = None
try:
    from thehive4py.api import TheHiveApi
    from thehive4py.models import Alert, AlertArtifact
    THEHIVE4PY_AVAILABLE = True
except Exception:
    try:
        from thehive4py import TheHiveApi  # type: ignore
        from thehive4py.models import Alert, AlertArtifact  # type: ignore
        THEHIVE4PY_AVAILABLE = True
    except Exception:
        THEHIVE4PY_AVAILABLE = False

REQUESTS_AVAILABLE = True
try:
    import requests
except Exception:
    REQUESTS_AVAILABLE = False

# ---------------- helpers ----------------
def map_severity(raw):
    if raw is None:
        return DEFAULT_SEVERITY
    try:
        n = int(raw)
        if n <= 4: return 1
        elif n <= 10: return 2
        else: return 3
    except Exception:
        s = str(raw).strip().lower()
        if s in ("low","info","informational"): return 1
        if s in ("med","medium","moderate"): return 2
        if s in ("hi","high","critical","severe"): return 3
        return DEFAULT_SEVERITY

def safe_json_dumps(obj):
    try:
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        try:
            return json.dumps(obj, ensure_ascii=True)
        except Exception:
            return str(obj)

def get_nested(dct, dotted):
    cur = dct
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur

def norm_list(x):
    if x is None: return []
    if isinstance(x, list): return [str(i).lower() for i in x]
    return [str(x).lower()]

def extract_event_id(ev):
    # разные места, куда попадает EventID у правил Wazuh/Sysmon/Winlogbeat
    for k in ("win.system.eventID", "win.eventdata.eventID", "system.eventID", "event_id", "data.win.system.eventID"):
        v = get_nested(ev, k)
        if v is not None:
            try: return int(str(v).strip())
            except: pass
    # иногда в description: "EventID: 4625"
    desc = str(get_nested(ev, "rule.description") or ev.get("full_log") or "")
    for token in desc.replace(":", " ").split():
        if token.isdigit():
            n = int(token)
            if 1 <= n <= 65535:
                return n
    return None

def choose_template(wazuh_event):
    """
    Решаем, какой ключ TEMPLATE_MAP выбрать.
    Основания:
      - Windows EventID
      - rule.groups / tags
      - rule.description / data.provider (suricata/zeek/sysmon)
    """
    rule = wazuh_event.get("rule", {}) if isinstance(wazuh_event.get("rule"), dict) else {}
    groups = norm_list(rule.get("groups"))
    tags   = norm_list(rule.get("tags"))
    desc   = str(rule.get("description") or "").lower()
    provider = (get_nested(wazuh_event, "data.provider") or
                get_nested(wazuh_event, "agent.name") or
                get_nested(wazuh_event, "integration") or "")
    provider = str(provider).lower()

    eid = extract_event_id(wazuh_event)

    # --- Windows Security ---
    if eid == 4625:   # failed logon
        return "bruteforce"
    if eid == 4768:   # Kerberos pre-auth failure
        return "kerberos"
    if eid == 4624:   # successful logon
        # если админ-группа/админ аккаунт в тексте
        if "admin" in desc or "administrator" in desc or "domain admin" in desc or "enterprise admin" in desc:
            return "admin_logon"
        return "success_logon"
    if eid == 4720:   # account created
        return "acct_create"
    if eid == 7045:   # service installed
        return "service_install"
    if eid in (4719, 1102):  # audit policy changed / security log cleared
        return "policy"
    if eid == 4662:   # DS access (часто скан/перечень объектов каталога)
        return "recon"

    # --- Sysmon privesc/recon/exec артефакты по описанию/группам ---
    if "privilege escalation" in desc or "uac" in desc or "elevated token" in desc:
        return "privesc"
    if "directory enumeration" in desc or "lsadump" in desc or "sam hive" in desc:
        return "recon"

    # --- Suricata/ET/Zeek: exfil/policy ---
    if "suricata" in provider or "zeek" in provider or "et " in desc or "emerging threats" in desc:
        if "exfil" in desc or "exfiltration" in desc or "large dns" in desc or "data leak" in desc:
            return "exfil"
        if "policy" in desc or "policy violation" in desc:
            return "policy"

    # --- по группам/тегам от правил Wazuh ---
    grp_set = set(groups + tags)
    if {"bruteforce","password","auth_fail"}.intersection(grp_set):
        return "bruteforce"
    if {"kerberos","krb","preauth"}.intersection(grp_set):
        return "kerberos"
    if {"privesc","uac","token"}.intersection(grp_set):
        return "privesc"
    if {"acct_create","account","user_create"}.intersection(grp_set):
        return "acct_create"
    if {"service","service_install"}.intersection(grp_set):
        return "service_install"
    if {"recon","enumeration","ldap","ds_access"}.intersection(grp_set):
        return "recon"
    if {"policy","audit_change","log_cleared"}.intersection(grp_set):
        return "policy"
    if {"exfil","exfiltration","dataloss"}.intersection(grp_set):
        return "exfil"
    if {"admin_logon","admin","da_login"}.intersection(grp_set):
        return "admin_logon"
    if {"success_logon","logon_success"}.intersection(grp_set):
        return "success_logon"

    return "default"

def build_artifacts_from_wazuh(event):
    candidates = []
    keys = [
        ("src_ip","ip"), ("source_ip","ip"), ("dst_ip","ip"), ("destination_ip","ip"),
        ("src_port","port"), ("dst_port","port"),
        ("user","username"),
        ("win.eventdata.image","file"),
        ("win.eventdata.hashes","hash"),
        ("rule.id","other"), ("rule.description","other"),
        ("agent.name","other"), ("agent.ip","ip"),
        ("data.srcip","ip"), ("data.dstip","ip"),
        ("data.url","url"), ("data.hostname","hostname"),
    ]
    for key, atype in keys:
        val = get_nested(event, key) if "." in key else event.get(key)
        if val:
            if key.endswith("hashes") and isinstance(val, str):
                for chunk in val.replace(";", ",").split(","):
                    chunk = chunk.strip()
                    if "=" in chunk:
                        _, hv = chunk.split("=", 1)
                        if hv: candidates.append(("hash", hv.strip()))
            else:
                candidates.append((atype, str(val)))

    seen, uniq = set(), []
    for t, v in candidates:
        sig = (t, v)
        if sig not in seen:
            seen.add(sig); uniq.append((t, v))

    rest_artifacts = [{"dataType": t, "data": v} for t, v in uniq]

    py_artifacts = []
    if THEHIVE4PY_AVAILABLE and AlertArtifact is not None:
        for t, v in uniq:
            try: py_artifacts.append(AlertArtifact(dataType=t, data=v))
            except: pass

    return rest_artifacts, py_artifacts

def promote_alert_rest(thehive_url, api_key, alert_id, case_template=None):
    if not REQUESTS_AVAILABLE:
        logging.warning("requests не установлен — промоут пропущен.")
        return
    try:
        import requests
        base = thehive_url.rstrip("/")
        endpoints = [
            "{}/api/v1/alert/{}/case",        # TH5 «новый»
            "{}/api/v1/alert/{}/createCase",  # TH4/совместимый
            "{}/api/alert/{}/createCase"      # совсем старый
        ]
        body = {"caseTemplate": case_template} if case_template else None
        headers = {
            "Authorization": "Bearer {}".format(api_key),
            "Content-Type": "application/json"
        }
        last = None
        for tpl in endpoints:
            url = tpl.format(base, alert_id)
            r = requests.post(url, headers=headers,
                              data=json.dumps(body) if body else None,
                              timeout=HTTP_TIMEOUT, verify=THEHIVE_VERIFY_TLS)
            last = (url, r.status_code, r.text)
            if 200 <= r.status_code < 300:
                logging.info("Promoted OK via %s (template=%s)", url, case_template or "none")
                return
            # если 404 — пробуем следующий эндпоинт
            if r.status_code != 404:
                break
        logging.warning("Promote failed. Tried %s -> %s %s", last[0], last[1], last[2])
    except Exception:
        logging.exception("Ошибка promote_alert_rest")

# ---------------- main ----------------
def main():
    if len(sys.argv) < 4:
        logging.error("Args: <alert.json> <api_key> <thehive_url>; got=%s", sys.argv)
        sys.exit(1)

    alert_path, api_key, thehive_url = sys.argv[1], sys.argv[2], sys.argv[3]
    logging.info("Start. alert_path=%s, thehive_url=%s, verify_tls=%s, promote=%s",
                 alert_path, thehive_url, THEHIVE_VERIFY_TLS, PROMOTE_TO_CASE)

    try:
        with open(alert_path, "r", encoding="utf-8") as f:
            wazuh_event = json.load(f)
    except Exception:
        logging.exception("Не удалось прочитать alert.json: %s", alert_path)
        sys.exit(1)

    rule = wazuh_event.get("rule", {}) if isinstance(wazuh_event.get("rule"), dict) else {}
    title = rule.get("description") or wazuh_event.get("full_log") or "Wazuh Alert"
    source_ref = str(wazuh_event.get("id") or uuid.uuid4())

    # выбор шаблона
    template_key = choose_template(wazuh_event)
    case_template_name = TEMPLATE_MAP.get(template_key, TEMPLATE_MAP["default"])

    # severity: берём из правила -> приводим -> при необходимости усиливаем от шаблона
    sev_raw = rule.get("level") or rule.get("severity")
    severity = map_severity(sev_raw)
    sev_from_template = TEMPLATE_SEVERITY.get(template_key, DEFAULT_SEVERITY)
    severity = max(severity, sev_from_template)

    tlp = DEFAULT_TLP
    description = safe_json_dumps(wazuh_event)
    rest_artifacts, py_artifacts = build_artifacts_from_wazuh(wazuh_event)

    # --- try thehive4py first ---
    if THEHIVE4PY_AVAILABLE and TheHiveApi is not None and Alert is not None:
        try:
            api = TheHiveApi(thehive_url, api_key, cert=THEHIVE_VERIFY_TLS)
            alert = Alert(
                title=title, tlp=tlp, severity=severity,
                source="wazuh", sourceRef=source_ref, type="external",
                description=description, artifacts=py_artifacts or None, tags=["wazuh", template_key]
            )
            r = api.create_alert(alert)
            if getattr(r, "status_code", 500) // 100 != 2:
                body = getattr(r, "text", "")
                logging.error("create_alert (thehive4py) non-2xx: %s %s", getattr(r, "status_code", "?"), body)
                raise RuntimeError("thehive4py create_alert failed")

            try:
                alert_id = r.json().get("id") or r.json().get("_id")
            except Exception:
                alert_id = None

            logging.info("Alert created via thehive4py. id=%s title=%s sev=%s tlp=%s template_key=%s",
                         alert_id, title, severity, tlp, template_key)

            if PROMOTE_TO_CASE and alert_id:
                promote_alert_rest(thehive_url, api_key, alert_id, case_template_name)

            sys.exit(0)
        except Exception:
            logging.warning("thehive4py ошибка/недоступен — перехожу на REST.\n%s", traceback.format_exc())

    # --- REST fallback ---
    if not REQUESTS_AVAILABLE:
        logging.error("Модуль requests не установлен в /var/ossec/framework/python.")
        sys.exit(1)

    try:
        import requests
        payload = {
            "title": title,
            "type": "external",
            "source": "wazuh",
            "sourceRef": source_ref,
            "severity": severity,
            "tlp": tlp,
            "tags": ["wazuh", template_key],
            "description": description,
            "artifacts": rest_artifacts
        }
        url = "{}/api/v1/alert".format(thehive_url.rstrip("/"))
        r = requests.post(url,
                          headers={"Authorization": "Bearer {}".format(api_key),
                                   "Content-Type": "application/json"},
                          data=json.dumps(payload), timeout=HTTP_TIMEOUT, verify=THEHIVE_VERIFY_TLS)
        if r.status_code // 100 != 2:
            logging.error("create_alert (REST) non-2xx: %s %s", r.status_code, r.text)
            sys.exit(1)

        resp = r.json()
        alert_id = resp.get("id") or resp.get("_id")
        logging.info("Alert created via REST. id=%s title=%s sev=%s tlp=%s template_key=%s",
                     alert_id, title, severity, tlp, template_key)

        if PROMOTE_TO_CASE and alert_id:
            promote_alert_rest(thehive_url, api_key, alert_id, case_template_name)

        sys.exit(0)

    except Exception:
        logging.exception("Ошибка при создании алёрта (REST)")
        sys.exit(1)

if __name__ == "__main__":
    main()
