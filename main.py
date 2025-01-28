import psycopg2
from config import config
from cryptography.fernet import Fernet
import bcrypt


import hashlib
import bcrypt
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
import sys
from datetime import datetime

class MainWindow(QMainWindow):
    def __init__(self, *args, **kwargs):
        super(MainWindow, self).__init__(*args, **kwargs)
        self.setWindowTitle("Welcome to your password manager")
        self.setGeometry(200, 200, 800, 600)

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        vbox = QVBoxLayout()

        label = QLabel("Login to an existing account or create a new account")
        label.setAlignment(Qt.AlignCenter)

        self.login_button = QPushButton("Login ", self)
        self.login_button.setCheckable(True)
        self.login_button.clicked.connect(self.login_button_clicked)

        self.signup_button = QPushButton("Sign Up", self)
        self.signup_button.setCheckable(True)
        self.signup_button.clicked.connect(self.sign_button_clicked)
        vbox.addWidget(label)
        vbox.addWidget(self.login_button)
        vbox.addWidget(self.signup_button)
        central_widget.setLayout(vbox)

    #Login Button Capabilities
    def login_button_clicked(self):
        self.login_window = LoginWindow(self)   
        self.login_window.show()
        self.close()

    #Sign Up Button Capabilities
    def sign_button_clicked(self):
        self.signup_window = SignUpWindow(self)
        self.signup_window.show()
        self.close()

class SignUpWindow(QWidget): #Inside paranthesis is what it inherits from
    def __init__(self, parent=None):
        #the constructor method of the class; init is called automatically when an instance of SignUpWindow is created.
        super().__init__()
        self.parent = parent  
        self.setWindowTitle("Sign Up")
        self.setGeometry(200, 200, 800, 600)

        layout = QVBoxLayout()

        #Username
        username_label = QLabel("Create a username:")
        self.user_available_label = QLabel("") 
        layout.addWidget(self.user_available_label)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        layout.addWidget(username_label)
        layout.addWidget(self.username_input)
        self.username_input.textChanged.connect(self.check_username_avail)

        #Password
        password_label = QLabel("Enter a secure master password")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(password_label)
        layout.addWidget(self.password_input)

        #Sign Up Button
        self.sign_button = QPushButton("Sign Up", self)
        self.sign_button.setEnabled(False)  
        self.password_input.textChanged.connect(self.validate_inputs)  
        self.sign_button.clicked.connect(self.sign_button_clicked)
        layout.addWidget(self.sign_button)

        #Home Button
        self.home_button = QPushButton("Home", self)
        self.home_button.clicked.connect(self.home_button_clicked)
        layout.addWidget(self.home_button)

        self.setLayout(layout)

    def check_username_avail(self):
        text = self.username_input.text().strip()
        if not text:
            return False
            
        conn = None
        try:
            params = config()
            conn = psycopg2.connect(**params)
            crsr = conn.cursor()
            query = "SELECT 1 FROM users WHERE username = %s;"
            crsr.execute(query, (text,))
            result = crsr.fetchone()

            if result:
                self.user_available_label.setText("Username is unavailable")                
                return False
            else:                   
                self.user_available_label.setText("Username is available!")                
                return True

        except (Exception, psycopg2.DatabaseError) as error:
            print(f"Error: {error}")
            return False  
        finally:
            if conn:
                conn.close()

    def validate_inputs(self):
        self.user_set = bool(self.username_input.text().strip())  
        self.password_set = bool(self.password_input.text().strip())  

        self.sign_button.setEnabled(self.user_set and self.password_set)

    def home_button_clicked(self):
        if self.parent:
            self.parent.show()
        self.close()

    def hash_password(self, password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode(), salt).decode()
        return hashed_password, salt.decode()  
    
    def sign_button_clicked(self):
        username = self.username_input.text().strip()
        if not self.check_username_avail(): 
            QMessageBox.warning(self, "Error", "Username is unavailable.")
            return
        password = self.password_input.text().strip()
        if not password:
            QMessageBox.warning(self, "Error", "Password cannot be empty.")
            return

        hashed_password, salt = self.hash_password(password)
        created_at = datetime.now()

        conn = None
        try:
            params = config()
            conn = psycopg2.connect(**params)
            crsr = conn.cursor()
            query = "INSERT INTO users (username, masterpassword, created_at, salt) VALUES (%s, %s, %s, %s);"
            crsr.execute(query, (username, hashed_password, created_at, salt))
            conn.commit()
            QMessageBox.information(self, "Success", "Account created successfully")
            self.open_home_window()
            self.close()  
        except (Exception, psycopg2.DatabaseError) as error:
            QMessageBox.warning(self, "Error", f"Database error: {error}")
        finally:
            if conn:
                conn.close()

    def open_home_window(self):
        self.home_window = PassManagerWindow(parent=self)
        self.home_window.show()
        self.close()

class LoginWindow(QWidget):
    def __init__(self, parent=None): 
        super().__init__()
        self.parent = parent  
        self.setWindowTitle("Login")
        self.setGeometry(200, 200, 800, 600)
        
        layout = QVBoxLayout()

        username_label2 = QLabel("Username:")
        self.username_input2 = QLineEdit()
        self.username_input2.setPlaceholderText("Enter your username")
        layout.addWidget(username_label2)
        layout.addWidget(self.username_input2)

        password_label2 = QLabel("Master Password:")
        self.password_input2 = QLineEdit()
        self.password_input2.setPlaceholderText("Enter your master password")
        self.password_input2.setEchoMode(QLineEdit.Password)
        layout.addWidget(password_label2)
        layout.addWidget(self.password_input2)

        self.enter_system_button = QPushButton("Log in", self)
        self.enter_system_button.clicked.connect(self.enter_system_button_clicked)
        layout.addWidget(self.enter_system_button)

        self.home_button = QPushButton("Home", self)
        self.home_button.clicked.connect(self.home_button_clicked)
        layout.addWidget(self.home_button)

        self.setLayout(layout)

    def decrypt(self):
        username = self.username_input2.text().strip()
        entered_password = self.password_input2.text().strip()
        user_id =""

        conn = None
        try:
            params = config()
            conn = psycopg2.connect(**params)
            crsr = conn.cursor()
            crsr.execute("SELECT masterpassword, salt FROM users WHERE username = %s;", (username,))
            result = crsr.fetchone()  

            if result:
                stored_hashed_password, stored_salt = result
                if bcrypt.checkpw(entered_password.encode(), stored_hashed_password.encode()):
                    QMessageBox.information(self, "Success", "You have been successfully logged in")
                    if self.parent:
                        self.parent.current_user_id = user_id
                    return True
                

                else:
                    QMessageBox.warning(self, "Error", "Your master password is incorrect. Please try again.")
                    return False
            else:
                QMessageBox.warning(self, "Error", "This username does not exist in our database.")
                return False
        finally:
            if conn:
                conn.close()

    def enter_system_button_clicked(self):
        if self.decrypt():
            QMessageBox.information(self, "Success", "Welcome!")
            self.open_home_window()
        else:
            QMessageBox.warning(self, "Error", "This username or password is incorrect.")
            return False

    def open_home_window(self):
        self.home_window = PassManagerWindow(parent=self, user_id=self.parent.current_user_id)
        self.home_window.show()
        self.close()

    def home_button_clicked(self):
        if self.parent:
            self.parent.show()
        self.close()

class PassManagerWindow(QWidget):
    def __init__(self, parent=None, user_id=None):
        super().__init__()
        self.parent = parent  
        self.user_id = user_id

        self.setWindowTitle("Password Manager Menu")
        self.setGeometry(200, 200, 800, 600)
        
        layout = QVBoxLayout()

        self.home_button = QPushButton("Add an account", self)
        self.home_button.setCheckable(True)
        self.home_button.clicked.connect(self.add_account_clicked)
        layout.addWidget(self.home_button)

        """self.home_button = QPushButton("Check stored accounts", self)
        self.home_button.setCheckable(True)
        self.home_button.clicked.connect(self.check_accounts_clicked)
        layout.addWidget(self.home_button)"""

        self.logout_button = QPushButton("Log out", self)
        self.logout_button.setCheckable(True)
        self.logout_button.clicked.connect(self.logout_clicked)
        layout.addWidget(self.logout_button)
        self.setLayout(layout)

    def decrypt_password(self, encrypted_password, service_name):
        if not encrypted_password or not service_name:
            print("Service does not exist, or has no password")
            return None
        
      

        
        conn = None
        try:
            params = config()
            conn = psycopg2.connect(**params)
            crsr = conn.cursor()

            crsr.execute("SELECT key_value FROM keys WHERE user_id = %s AND service_name = %s;",
                (self.user_id, service_name))
            key_result = crsr.fetchone()

            if not key_result:
                print("Error: A key does not exist for this service")
                return None
            
            encryption_key = key_result[0].encode()  
            cipher = Fernet(encryption_key)  
            decrypted_password = cipher.decrypt(encrypted_password.encode()).decode()
            return decrypted_password
        
        except (Exception, psycopg2.DatabaseError) as error:
            print(f"Error: {error}")
            return None  

        finally:
            if conn:
                conn.close() 
    
    def add_account_clicked(self):
        self.addAcc_window = AddAccountWindow(parent=self)
        self.addAcc_window.show()
        self.close()

    def check_account_clicked(self):
        self.addAcc_window = CheckAccountsWindow(parent=self)
        self.addAcc_window.show()
        self.close()

    def logout_clicked(self):
        if self.parent:
            self.parent.show()
        self.close()

class AddAccountWindow(QWidget):
    def __init__(self, parent=None, user_id=None): 
        super().__init__()
        self.parent = parent  
        self.user_id = user_id
        self.setWindowTitle("Add an account")
        self.setGeometry(200, 200, 800, 600)
        
        layout = QVBoxLayout()

        service_input = QLabel("Enter a name for the service you would like to store information for:")
        self.service_input = QLineEdit()
        self.service_input.setPlaceholderText("Service Name ex. Facebook")
        layout.addWidget(service_input)
        layout.addWidget(self.service_input)

        """Might do something with this later so when you open the service password manager can auto input your passsword?"""
        service_link_input = QLabel("Enter a link to the serivce (Optional)")
        self.service_link_input = QLineEdit()
        self.service_link_input.setPlaceholderText("Service Name ex. Facebook")
        layout.addWidget(service_link_input)
        layout.addWidget(self.service_link_input)

        service_username = QLabel("Username:")
        self.service_username = QLineEdit()
        self.service_username.setPlaceholderText("Enter your username")
        layout.addWidget(service_username)
        layout.addWidget(self.service_username)

        service_password = QLabel("Password:")
        self.service_password = QLineEdit()
        self.service_password.setPlaceholderText("Password")
        self.service_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(service_password)
        layout.addWidget(self.service_password)

        self.addAcc_button = QPushButton("Add Account", self)
        self.addAcc_button.clicked.connect(self.addAcc_button_clicked)

        layout.addWidget(self.addAcc_button)
        self.setLayout(layout)

    
    def check_for_service(self):
        service_name = self.service_input.text().strip()

        if not service_name:
            return False
            
        conn = None
        try:
            params = config()
            conn = psycopg2.connect(**params)
            crsr = conn.cursor()
            query = "SELECT 1 FROM accounts WHERE service_name = %s AND user_id = %s;"
            crsr.execute(query, (service_name, self.user_id))
            result = crsr.fetchone()

            if result:
                QMessageBox.warning(self, "This service already added, would you like to edit its stored information?")
                return False
            else:                   
                return True

        except (Exception, psycopg2.DatabaseError) as error:
            print(f"Error: {error}")
            return False  
        finally:
            if conn:
                conn.close()

    def generate_key(self):
        service_name = self.service_input.text().strip()

        if not service_name:
            print("Error; No service name")
            return False
        
        ENCRYPTION_KEY = Fernet.generate_key()

        conn = None
        try:
            params = config()
            conn = psycopg2.connect(**params)
            crsr = conn.cursor()
            query = "SELECT service_id FROM accounts WHERE service_name = %s AND user_id = %s;"
            crsr.execute(query, (service_name, self.user_id))
            result = crsr.fetchone()
            service_id = result[0]  
            query = """INSERT INTO keys (user_id, service_id, key_value) VALUES (%s, %s, %s)"""
            crsr.execute(query, (self.user_id, service_id, ENCRYPTION_KEY.decode()))  
            conn.commit()  
            return True
        except (Exception, psycopg2.DatabaseError) as error:
            print(f"Error: {error}")
            return False  
        finally:
            if conn:
                conn.close() 

    def encrypt_password(self):
        service_password = self.service_password.text().strip()
        service_name = self.service_input.text().strip()
        if not service_password:
            print("Password cant be empty")
            return None  

        conn = None
        try:
            params = config()
            conn = psycopg2.connect(**params)
            crsr = conn.cursor()

            crsr.execute("SELECT key_value FROM keys WHERE user_id = %s AND service_name = %s;",
                     (self.user_id, service_name))
            key_result = crsr.fetchone()

            if not key_result:
                print("No encryption key found for this service")

            encryption_key = key_result[0].encode()  
            cipher = Fernet(encryption_key)  
            encrypted_password = cipher.encrypt(service_password.encode()).decode()
            return encrypted_password

        except (Exception, psycopg2.DatabaseError) as error:
            print(f"Error: {error}")
            return None  

        finally:
            if conn:
                conn.close() 

    def addAcc_button_clicked(self):
        conn = None
        try:
            params = config()
            conn = psycopg2.connect(**params)
            crsr = conn.cursor()

            if self.check_for_service(): 
                query = "INSERT INTO accounts (user_id, username, service_name, service_password) VALUES (%s, %s, %s, %s);"
                encrypted_password = self.encrypt_password()  

                if not encrypted_password:
                    print("Error: Could not encrypt password")
                    return

                crsr.execute(query, (self.user_id, self.service_username.text().strip(), self.service_input.text().strip(), encrypted_password))
                conn.commit()

                QMessageBox.information(self, "Success", "Account successfully added.")
                
        except (Exception, psycopg2.DatabaseError) as error:
            print(f"Error: {error}")

        finally:
            if conn:
                conn.close()
    
   




        

    




        


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
        print("Connected to the database")
        db_version = crsr.fetchone()
        print(db_version)
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

            sql = """INSERT INTO users (user_id, user_id, masterpassword) VALUES (%s, %s);"""
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

CREATE TABLE accounts (
    service_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    service_name VARCHAR(255) NOT NULL,
    service_username VARCHAR(255) NOT NULL,
    link VARCHAR(255) NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
"""