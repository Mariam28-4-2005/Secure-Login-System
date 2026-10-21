import os
import mysql.connector

def get_db_connection():
    connection = mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password=os.environ["MYSQL_PASSWORD"],
        database="secure_login_db"
    )
    return connection
