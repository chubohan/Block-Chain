import bcrypt
import hashlib
import base64

# 生成 bcrypt hash
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

# 檢查密碼，並返回是否驗證成功
# 兼容舊 scrypt hash，自動升級到 bcrypt
def verify_and_upgrade_password(password: str, stored_hash: str):
    if stored_hash.startswith('$2b$') or stored_hash.startswith('$2a$'):
        # bcrypt
        valid = bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        return valid, stored_hash  # 已經是 bcrypt，不需升級
    elif stored_hash.startswith('scrypt:'):
        # 舊 scrypt hash
        try:
            algo, params, salt_b64, hash_hex = stored_hash.split('$')
            N, r, p = map(int, params.split(':'))
            salt = base64.b64decode(salt_b64)
            hash_bytes = bytes.fromhex(hash_hex)
            derived = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=N, r=r, p=p, dklen=len(hash_bytes))
            valid = derived == hash_bytes
            if valid:
                # 升級到 bcrypt
                new_hash = hash_password(password)
                return True, new_hash
        except Exception:
            return False, stored_hash
        return False, stored_hash
    else:
        # werkzeug hash 或其他，直接用 check_password_hash
        from werkzeug.security import check_password_hash
        valid = check_password_hash(stored_hash, password)
        if valid:
            # 升級到 bcrypt
            new_hash = hash_password(password)
            return True, new_hash
        return False, stored_hash