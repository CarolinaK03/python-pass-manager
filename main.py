import psycopg2
from config import config
import hashlib
import bcrypt

#connect = psycopg.connect(host="localhost", port="5433", database="master", user="postgres", password="572579")
#connect creates a new database session & returns a new instance of the connection class
#This is one method, but not the most robust one. Another method will be implemented

def connect():
    connection = None

    try:
        params = config()
        print("Connecting to the postgresql database...")
        connection = psycopg2.connect(**params)

        #create a cursr
        crsr = connection.cursor()
        print("Postgresql Database Version: ")
        crsr.execute('SELECT Version()')
        db_version = crsr.fetchone()
        print(db_version)
        crsr.close()
        #Always close this cus the crsr and the connection are the communitcaiton ebtween the db
        #and the pyhton file
    except(Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally: 
        if connection is not None:
            connection.close()
            print('Database connection terminated.')
    return connection

def add_new_user() :
    conn = connect()
    if conn is not None:
        try:
            salt = bcrypt.gensalt()
            user_username_input = input('Enter a username.')
            user_password_input = input('Enter a secure, unique master password that you will remember. This will be used access your password vault, and it will not be stored. ')
            user_salted_password = user_password_input.encode() + salt
            h = hashlib.new("SHA256")
            h.update(user_salted_password)
            hashed_password = h.hexdigest()

            crsr = conn.cursor()

            crsr.execute("SELECT COUNT(*) FROM users;")
            user_count = crsr.fetchone()[0]
            generated_id = user_count + 1000

            sql = """INSERT INTO users (user_id, username, masterpassword) VALUES (%s, %s);"""
            crsr.execute(sql, (user_id, username, masterpassword))
            conn.commit()
            crsr.close()
            print("User added successfully.")
        except (Exception, psycopg2.DatabaseError) as error:
            print(f"Error: {error}")
        finally:
            if conn is not None:
                conn.close()
            
if __name__ == "__main__" :
    connect()
        


"""
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE passwords (
    password_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL, 
    service_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE keys (
    key_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    password_id INTEGER NOT NULL,
    key_value VARCHAR(255) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (password_id) REFERENCES passwords(password_id)
);

CREATE TABLE password_history (
    history_id SERIAL PRIMARY KEY,
    password_id INTEGER NOT NULL ,
    old_password VARCHAR(255) NULL,
    changed_at TIMESTAMP NULL,
    FOREIGN KEY (password_id) REFERENCES passwords(password_id)
);

"""