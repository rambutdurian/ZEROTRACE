import requests
import socket
import json
import threading
from queue import Queue
from rich.console import Console
from rich.panel import Panel
from rich.theme import Theme
from rich.align import Align

# -------------------------------
#  ONE PIECE THEME COLORS
# -------------------------------
op_theme = Theme({
    "gold": "bold #FFD700",
    "luffy_red": "bold #FF0000",
    "sea_blue": "bold #1E90FF",
    "straw_hat": "#E5AA70",
    "bounty": "bold #8B4513",
    "success": "bold green",
    "warn": "bold yellow",
    "danger": "bold red"
})
console = Console(theme=op_theme)

COMMON_PORTS = [80, 443, 21, 22, 25, 3306, 8080, 8443]
THREADS = 20
TIMEOUT = 1

# -------------------------------
#  STRAW HAT BANNER
# -------------------------------
def print_banner():
    banner = r"""
[gold]                    ☠️  xxxxxxxxxxxxxxxxxxx  ☠️[/gold]

                    [straw_hat]        _________      [/straw_hat]
                    [straw_hat]       /  ______ \     [/straw_hat]
                    [straw_hat]      |  |        |    [/straw_hat]
                    [straw_hat]      |  |        |    [/straw_hat]
                    [straw_hat]       \  \______/     [/straw_hat]
                    [straw_hat]      -------------  [/straw_hat]
                         [luffy_red]     O     O     [/luffy_red]
                         [luffy_red]        ▽        [/luffy_red]
                      [sea_blue]      \_________/      [/sea_blue]

[luffy_red][bold]
███████╗███████╗██████╗  ██████╗ ████████╗██████╗  █████╗  ██████╗███████╗
╚══███╔╝██╔════╝██╔══██╗██╔═══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
  ███╔╝ █████╗  ██████╔╝██║   ██║   ██║   ██████╔╝███████║██║     █████╗  
 ███╔╝  ██╔══╝  ██╔══██╗██║   ██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
███████╗███████╗██║  ██║╚██████╔╝   ██║   ██║  ██║██║  ██║╚██████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
[/bold][/luffy_red]

[gold]                   「 FIND THE PIECE OF DATA 」[/gold]
[sea_blue]                   Recon • Exposure • No Mercy[/sea_blue]
"""
    console.print(Align.center(banner))


# -------------------------------
#  LOGGING
# -------------------------------
def log_pose(message, type="info"):
    icons = {"info": "⛵", "success": "🍖", "danger": "🏴‍☠️", "warn": "⚠️"}
    colors = {"info": "sea_blue", "success": "success", "danger": "danger", "warn": "warn"}
    console.print(f"[{colors[type]}]{icons[type]} {message}[/{colors[type]}]")


# -------------------------------
#  SUBDOMAIN DISCOVERY
# -------------------------------
def discover_subdomains(domain):
    found = []
    log_pose("Starting subdomain discovery...", "info")
    try:
        with open("wordlist.txt") as f:
            words = f.read().splitlines()
    except:
        log_pose("wordlist.txt missing!", "danger")
        return []

    for word in words:
        sub = f"{word}.{domain}"
        try:
            requests.get(f"http://{sub}", timeout=1)
            found.append(sub)
            log_pose(f"Land Ho! {sub}", "success")
        except:
            pass
    return found


# -------------------------------
#  PORT SCANNING
# -------------------------------
def scan_port(ip, port, open_ports):
    try:
        sock = socket.socket()
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))
        open_ports.append(port)
    except:
        pass
    finally:
        sock.close()


def port_scan(ip):
    log_pose("Scanning common ports...", "info")
    open_ports = []
    q = Queue()
    for p in COMMON_PORTS:
        q.put(p)

    def worker():
        while not q.empty():
            port = q.get()
            scan_port(ip, port, open_ports)
            q.task_done()

    for _ in range(THREADS):
        threading.Thread(target=worker, daemon=True).start()

    q.join()
    return sorted(open_ports)


# -------------------------------
#  TECHNOLOGY & MISCONFIG CHECK
# -------------------------------
def detect_tech(domain):
    log_pose("Detecting technologies...", "info")
    tech = {}
    url = f"http://{domain}"
    try:
        r = requests.get(url, timeout=3)
        headers = r.headers
        if headers.get("Server"):
            tech["server"] = headers["Server"]
        if headers.get("X-Powered-By"):
            tech["powered_by"] = headers["X-Powered-By"]
    except:
        pass
    return tech


def misconfig_check(domain):
    log_pose("Checking for misconfigurations...", "info")
    issues = []
    url = f"http://{domain}"

    dirs = ["/", "/test/", "/uploads/", "/images/", "/backup/", "/old/", "/files/"]
    for d in dirs:
        try:
            r = requests.get(url + d, timeout=3)
            if "Index of" in r.text and "<a href=" in r.text:
                issues.append(f"Directory listing enabled at {d}")
        except:
            pass

    try:
        r = requests.get(url, timeout=3)
        headers = r.headers
        required_headers = {
            "X-Frame-Options": "Clickjacking protection missing",
            "X-Content-Type-Options": "MIME-sniffing protection missing",
            "Content-Security-Policy": "CSP header missing",
            "Strict-Transport-Security": "HSTS missing"
        }
        for h, msg in required_headers.items():
            if h not in headers:
                issues.append(msg)
        if headers.get("Access-Control-Allow-Origin") == "*":
            issues.append("CORS misconfiguration: wildcard '*' allowed")
    except:
        pass

    try:
        r = requests.request("TRACE", url, timeout=3)
        if r.status_code == 200:
            issues.append("TRACE HTTP method enabled")
    except:
        pass

    try:
        r = requests.get(url, timeout=3)
        signatures = [
            "Apache2 Debian Default Page",
            "Welcome to nginx",
            "Test Page for Apache Installation",
            "IIS Windows Server"
        ]
        for sig in signatures:
            if sig.lower() in r.text.lower():
                issues.append("Default server installation page exposed")
    except:
        pass

    return issues


# -------------------------------
#  SHOW BOUNTY
# -------------------------------
def show_bounty(domain, report_file, subdomains, ports, tech, misconfigs):
    text = f"""
[bounty]DEAD OR ALIVE[/bounty]
[luffy_red][bold]TARGET: {domain}[/bold][/luffy_red]

[gold]ISLANDS FOUND:[/gold]
{chr(10).join('• ' + s for s in subdomains) or 'None'}

[gold]OPEN PORTS:[/gold]
{', '.join(map(str, ports)) or 'None'}

[gold]TECHNOLOGIES:[/gold]
{chr(10).join(f'• {k}: {v}' for k,v in tech.items()) or 'None'}

[luffy_red]WEAKNESSES:[/luffy_red]
{chr(10).join('• ' + i for i in misconfigs) or 'None'}

[sea_blue]📜 Report saved as:[/sea_blue]
[gold]{report_file}[/gold]
"""
    console.print(Panel(Align.center(text), border_style="gold"))


# -------------------------------
#  MAIN
# -------------------------------
if __name__ == "__main__":
    print_banner()
    domain = console.input("[gold]Which island are we raiding, Captain?: [/gold]").strip()
    if not domain:
        log_pose("No destination set!", "danger")
        exit()

    try:
        ip = socket.gethostbyname(domain)
        log_pose(f"Log Pose locked on {domain} ({ip})", "info")

        subdomains = discover_subdomains(domain)
        ports = port_scan(ip)
        tech = detect_tech(domain)
        misconfigs = misconfig_check(domain)

        report_file = f"{domain.replace('.', '_')}_bounty_report.json"
        report = {
            "ip": ip,
            "subdomains": subdomains,
            "open_ports": ports,
            "technologies": tech,
            "misconfigurations": misconfigs
        }
        with open(report_file, "w") as f:
            json.dump(report, f, indent=4)

        log_pose(f"Report saved as {report_file}", "success")
        show_bounty(domain, report_file, subdomains, ports, tech, misconfigs)

    except Exception as e:
        log_pose(f"Shipwrecked! {e}", "danger")
