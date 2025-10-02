import os
from dotenv import load_dotenv
import mysql.connector

# Carregar variáveis do .env
load_dotenv()

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASS", ""),
        database=os.getenv("DB_NAME", "controle_estoque")
    )

def query(sql, params=None, fetchone=False, commit=False):
    """
    Executa comandos SQL no banco.

    - SELECT (padrão): retorna lista de dicionários
    - fetchone=True → retorna apenas 1 registro
    - commit=True → usado em INSERT, UPDATE, DELETE
    """
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute(sql, params or ())

    data = None
    if commit:
        conn.commit()
    else:
        data = cur.fetchone() if fetchone else cur.fetchall()

    cur.close()
    conn.close()
    return data

