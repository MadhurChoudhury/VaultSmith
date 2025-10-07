# vaultsmith/cli.py
import click
import json
import time
import pyperclip
import threading
import secrets
import string
import datetime
from getpass import getpass
from pathlib import Path

from vaultsmith.crypto import create_vault_envelope, open_vault_envelope


VAULT_FILE = Path("vault.json")  # the encrypted file we’ll store passwords in


@click.group()
def cli():
    """VaultSmith - a minimal password manager."""
    pass


@cli.command()
def init():
    """Initialize a new encrypted vault."""
    if VAULT_FILE.exists():
        click.echo("Vault already exists! Delete it first if you want to re-init.")
        return

    password = getpass("Create a master password: ")
    confirm = getpass("Confirm master password: ")
    if password != confirm:
        click.echo("Passwords do not match.")
        return

    # create an empty vault structure
    vault_data = {"created": "2025-10-05", "entries": []}
    plaintext = json.dumps(vault_data).encode("utf-8")

    envelope = create_vault_envelope(password, plaintext)
    VAULT_FILE.write_text(envelope)
    click.echo(f"Vault created and encrypted at {VAULT_FILE}")


@cli.command()
def unlock():
    """Unlock the vault (for testing only: shows decrypted data)."""
    if not VAULT_FILE.exists():
        click.echo("No vault found! Run 'vault init' first.")
        return

    password = getpass("Enter your master password: ")
    envelope = VAULT_FILE.read_text()

    try:
        plaintext = open_vault_envelope(password, envelope)
        data = json.loads(plaintext)
        click.echo(json.dumps(data, indent=2))
    except Exception as e:
        click.echo(f"Decryption failed: {e}")
@cli.command()
def add():
    """Add a new password entry to the vault."""
    if not VAULT_FILE.exists():
        click.echo("No vault found! Run 'vault init' first.")
        return

    password = getpass("Enter your master password: ")
    envelope = VAULT_FILE.read_text()

    try:
        plaintext = open_vault_envelope(password, envelope)
        data = json.loads(plaintext)
    except Exception:
        click.echo("❌ Wrong password or vault corrupted.")
        return

    # ask for entry details
    site = click.prompt("Site / Service name")
    username = click.prompt("Username / Email")
    secret = getpass("Password for this site")

    new_entry = {
    "name": site,
    "username": username,
    "password": secret,
    "created_at": datetime.datetime.now().isoformat(timespec="seconds"),
    "updated_at": datetime.datetime.now().isoformat(timespec="seconds"),
}
    data["entries"].append(new_entry)

    # re-encrypt vault
    new_plaintext = json.dumps(data, indent=2).encode("utf-8")
    new_envelope = create_vault_envelope(password, new_plaintext)
    VAULT_FILE.write_text(new_envelope)
    click.echo(f"✅ Added entry for {site}")

@cli.command()
def list():
    """List all saved accounts (site + username)."""
    if not VAULT_FILE.exists():
        click.echo("No vault found! Run 'vault init' first.")
        return

    password = getpass("Enter your master password: ")
    envelope = VAULT_FILE.read_text()

    try:
        plaintext = open_vault_envelope(password, envelope)
        data = json.loads(plaintext)
    except Exception:
        click.echo("❌ Wrong password or vault corrupted.")
        return

    entries = data.get("entries", [])
    if not entries:
        click.echo("No entries found.")
        return

    click.echo("\nStored accounts:")
    click.echo("----------------")
    for i, entry in enumerate(entries, start=1):
        click.echo(f"{i}. {entry['name']}  ({entry['username']})")

@cli.command()
@click.argument("site")
@click.option("--timeout", default=10, help="Seconds before the clipboard clears.")
def get(site, timeout):
    """Copy the password for a given site to clipboard (auto-clears after a few seconds)."""
    if not VAULT_FILE.exists():
        click.echo("No vault found! Run 'vault init' first.")
        return

    password = getpass("Enter your master password: ")
    envelope = VAULT_FILE.read_text()

    try:
        plaintext = open_vault_envelope(password, envelope)
        data = json.loads(plaintext)
    except Exception:
        click.echo("❌ Wrong password or vault corrupted.")
        return

    entries = data.get("entries", [])
    match = next((e for e in entries if e["name"].lower() == site.lower()), None)

    if not match:
        click.echo(f"No entry found for '{site}'.")
        return

    secret = match["password"]
    pyperclip.copy(secret)

    def clear_clipboard_after_delay():
        time.sleep(timeout)
        # Only clear if the clipboard still contains the same password
        if pyperclip.paste() == secret:
            pyperclip.copy("")
        click.echo(f"\n🔒 Clipboard cleared after {timeout} seconds.")

    threading.Thread(target=clear_clipboard_after_delay, daemon=True).start()

    click.echo(f"✅ Password for '{site}' copied to clipboard! (auto-clears in {timeout}s)")    

@cli.command()
@click.argument("site", required=False)
@click.option("--length", default=16, help="Length of the generated password.")
@click.option("--update", is_flag=True, help="Update the vault entry for this site with the new password.")
def generate(site, length, update):
    """
    Generate a strong random password.
    Optionally update an existing vault entry with it.
    """
    # 1. create the password
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))

    # 2. show it (user can copy manually if not saving)
    click.echo(f"\n🔐 Generated password ({length} chars): {password}")

    # 3. if no site or no update flag, we stop here
    if not site or not update:
        click.echo("\nUse '--update' and specify a site to store it in the vault.")
        return

    # 4. otherwise update the vault entry
    if not VAULT_FILE.exists():
        click.echo("No vault found! Run 'vault init' first.")
        return

    master_password = getpass("Enter your master password: ")
    envelope = VAULT_FILE.read_text()

    try:
        plaintext = open_vault_envelope(master_password, envelope)
        data = json.loads(plaintext)
    except Exception:
        click.echo("❌ Wrong password or vault corrupted.")
        return

    entries = data.get("entries", [])
    match = next((e for e in entries if e["name"].lower() == site.lower()), None)
    if not match:
        click.echo(f"No entry found for '{site}'. Use 'vault add' first.")
        return

    match["password"] = password
    match["updated_at"] = datetime.datetime.now().isoformat(timespec="seconds")
    
    new_plaintext = json.dumps(data, indent=2).encode("utf-8")
    new_envelope = create_vault_envelope(master_password, new_plaintext)
    VAULT_FILE.write_text(new_envelope)

    click.echo(f"✅ Updated password for '{site}' in vault.")

if __name__ == "__main__":
    cli()