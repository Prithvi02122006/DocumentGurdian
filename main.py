"""
DOCUMENT GUARDIAN: Secure Personal Document Management System
Application Entry Point.
"""

import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.database import get_db
from database.schema import verify_schema
from security.authentication import AuthenticationService
from ui.app import DocumentGuardianApp


def display_banner():
    banner = """
================================================================================
       DOCUMENT GUARDIAN : Secure Personal Document Management System
================================================================================
 [DISCLAIMER] Academic Project Notice:
 This software is a student-developed desktop utility. It is NOT an official
 Government of India application and is not affiliated with any government agency.
================================================================================
"""
    print(banner)


def run_smoke_test():
    display_banner()
    print("[*] Running Document Guardian integrity verification...")
    db = get_db()
    db.init_db()

    with db.get_connection() as conn:
        schema = verify_schema(conn)

    print(f"[+] Database location: {db.db_path}")
    print("[+] Verified Tables:")
    for table_name, cols in schema.items():
        print(f"    - {table_name}: ({len(cols)} columns: {', '.join(cols[:4])}...)")

    print("\n[*] Verifying Authentication & Envelope Encryption subsystem...")
    auth = AuthenticationService(db)
    demo_user = "student_demo"
    demo_pass = "DemoStudent#2026"

    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (demo_user,))
        exists = cursor.fetchone()

    if not exists:
        reg_res = auth.register(demo_user, demo_pass, demo_pass)
        if reg_res.success:
            print(f"[+] Created fictional demo account: {demo_user} (DEK generated & wrapped)")
    else:
        login_res = auth.login(demo_user, demo_pass)
        if login_res.success:
            print(f"[+] Verified login for account: {demo_user} (DEK unwrapped: {len(login_res.dek)} bytes)")

    print("\n[+] Verification Complete. All systems operational.")
    return 0


def main():
    if "--smoke-test" in sys.argv:
        sys.exit(run_smoke_test())
    else:
        app = DocumentGuardianApp()
        app.mainloop()


if __name__ == "__main__":
    main()
