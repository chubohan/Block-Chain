import pymysql
from threading import Lock
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

DB_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': '123456789',
    'database': 'project',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}
_db_lock = Lock()
def get_connection():
    with _db_lock:
        try:
            conn = pymysql.connect(**DB_CONFIG)
            logger.debug("数据库连接成功")
            return conn
        except Exception as e:
            logger.error(f"数据库连接失败: {e}")
            raise
print(get_connection())