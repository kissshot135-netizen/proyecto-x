import oracledb
import hashlib
import os

DB_USER = 'sgap'
DB_PASSWORD = 'inacap123'
DB_DSN = 'localhost:1521/XEPDB1'
PASSWORD_ITERATIONS = 200_000

def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)

try:
    with oracledb.connect(user=DB_USER, password=DB_PASSWORD, dsn=DB_DSN) as conn:
        with conn.cursor() as cursor:
            # 1. Ver qué usuarios hay actualmente
            cursor.execute("SELECT correo FROM usuarios")
            print("Usuarios actuales en la BD:", cursor.fetchall())

            # 2. Generar un hash nuevo y seguro para "demo123"
            salt = os.urandom(16)
            pwd_hash = _hash_password("demo123", salt)
            hash_to_store = f"{salt.hex()}:{pwd_hash.hex()}"

            # 3. Borrar el admin si ya existía (para evitar duplicados)
            cursor.execute("DELETE FROM usuarios WHERE correo = 'admin@sgap.local'")
            
            # 4. Insertar el usuario con el hash correcto
            cursor.execute(
                "INSERT INTO usuarios (correo, nombre, rol, password_hash, activo) VALUES ('admin@sgap.local', 'Administrador Demo', 'Administrador', :1, 1)",
                [hash_to_store]
            )
            conn.commit()
            print("✅ Usuario admin@sgap.local creado/reseteado exitosamente con contraseña 'demo123'")
            
except Exception as e:
    print("Error:", e)
