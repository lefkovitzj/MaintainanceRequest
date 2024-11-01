import secrets
import hashlib

def sha_hash(string_to_hash):
    """ Wrapper function for hashlib's SHA-512 hash. """
    m = hashlib.sha3_512()
    m.update(bytes(string_to_hash, "utf-8"))
    return m.hexdigest()

fields = [("SECRET_KEY", None, secrets.token_hex()),
            ("SQLALCHEMY_DATABASE_URI", None, "sqlite:///db.sqlite"),
            ("MAIL_DEFAULT_SENDER", input("GMail address: ")),
            ("MAIL_SERVER", None, "smtp.gmail.com"),
            ("MAIL_PORT", None, "465"),
            ("MAIL_USERNAME", input("GMail address: ")),
            ("MAIL_PASSWORD", input("GMail App Password: ")),
            ("MAIL_USE_SSL", None, "true"),
            ("OWNER_NAME", input("Owner username: ")),
            ("OWNER_PASS_HASH", sha_hash(input("Owner password: "))),
            ("MAX_RECENT_TASKS", input("Maximum recent tasks on dashboard: ")),
            ("MAX_RECENT_ACTIONS", input("Maximum recent actions on dashboard: "))
        ]

if __name__ == "__main__":
    with open(".env", "w") as env_file:
        for field in fields:
            env_file.write(f"{field[0]} = {field[-1]}")
        env_file.save()