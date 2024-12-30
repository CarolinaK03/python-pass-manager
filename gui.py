import psycopg2
from config import config
import hashlib
import bcrypt
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
import sys

class MainWindow(QMainWindow):
    def __init__(self, *args, **kwargs):
        super(MainWindow, self).__init__(*args, **kwargs)

        #Set up for the window
        self.setWindowTitle("Welcome to your password manager")
        self.setGeometry(200, 200, 800, 600)

        #Set up for the vertical layout
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        vbox = QVBoxLayout()

        label = QLabel("Login to an existing account or create a new account")
        label.setAlignment(Qt.AlignCenter)

        #Login Button Set Up
        self.login_button = QPushButton("Sign Up", self)
        self.login_button.setCheckable(True)
        self.login_button.clicked.connect(self.login_button_clicked)

        #Sign Up Set Up
        self.signup_button = QPushButton("Sign Up", self)
        self.signup_button.setCheckable(True)
        self.signup_button.clicked.connect(self.signup_button_clicked)

        vbox.addWidget(label)
        vbox.addWidget(self.login_button)
        vbox.addWidget(self.signup_button)
        central_widget.setLayout(vbox)

#Login Button Capabilities
    def login_button_clicked(self):
        self.login_window = LoginWindow()
        self.login_window.show()
        
#Sign Up Button Capabilities
    def signup_button_clicked(self):
        self.signup_window = SignUpWindow()
        self.signup_window.show()



class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login")
        self.setGeometry(150, 150, 300, 200)
        
        layout = QVBoxLayout()
        label = QLabel("")
        layout.addWidget(label)
        self.setLayout(layout)

class SignUpWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sign Up")
        self.setGeometry(150, 150, 300, 200)
        
        layout = QVBoxLayout()
        label = QLabel("")
        layout.addWidget(label)
        self.setLayout(layout)
        

        


app = QApplication(sys.argv)

window= MainWindow()
window.show() #important

app.exec_()

#connect = psycopg.connect(host="localhost", port="5433", database="master", user="postgres", password="572579")
#connect creates a new database session & returns a new instance of the connection class
#This is one method, but not the most robust one. ppper method will be implemented

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
            query = "SELECT COUNT(*) FROM users;"  
            user_count = get_rows(query)
            if user_count == -1:
                print("Failed to get user count. Cannot generate user ID.")
                return
            generated_id = user_count + 1000 

            sql = """INSERT INTO users (user_id, username, masterpassword) VALUES (%s, %s);"""
            crsr.execute(sql, (generated_id, user_username_input, hashed_password))
            conn.commit()
            crsr.close()
            print("User added successfully with user_id: {generated_id}")
        except (Exception, psycopg2.DatabaseError) as error:
            print(f"Error: {error}")
        finally:
            conn.close()
    else:
        print("Database connection failed.")



def get_rows(query):
    conn = connect()
    if conn is not None:
        try: 
            with conn.cursor() as crsr:
                crsr.execute(query)
                rows = crsr.fetchall()
                return len(rows)
        except (Exception, psycopg2.DatabaseError) as error:
            print(f"Error: {error}")
            return -1
        finally:
            conn.close()
    else:
        print("Error: Failed to connect to the database.")
        return -1

def add_new_password():
    conn = connect()
    if conn is not None:
        try:
            service_input = input('Enter the service for this password. ')
            password_input = input('Enter password to be stored. ')

            crsr = conn.cursor()
            query = "SELECT COUNT(*) FROM passwords;"  
            pass_count = get_rows(query)
            if pass_count == -1:
                print("Failed to get pass count. Cannot generate pass ID.")
                return
            
            sql = """INSERT INTO passwords (user_id, username, masterpassword) VALUES (%s, %s);"""
            crsr.execute(sql, (pass_count, service_input, password_input, ))
            conn.commit()
            crsr.close()
            print("User added successfully with user_id: {generated_id}")

        except (Exception, psycopg2.DatabaseError) as error:
            print(f"Error: {error}")
            return -1








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