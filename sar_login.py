import streamlit as s

def signup():
    st.write("Create a new account\n")
    username = st.text_input("New_Username")
    password = st.text_input("New_Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    if st.button("Signup"):
        if password == confirm_password:
            with open("users.json", "r") as f:
                users = json.load(f)

            if username in users:
                st.error("Username already exists")
            else:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                users[username] = password_hash
                with open("users.json", "w") as f:
                    json.dump(users, f)
                os.makedirs(f"user_data/{username}")
                st.success("Account created!")
                st.info("Go to Login Menu to login")
        else:
            st.error("Passwords do not match")  
                   
                     
def login():
    st.write("Login to your account\n")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        with open("users.json", "r") as f:
            users = json.load(f)

        if username in users:
            # Hash the user-provided password using SHA-256
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            if users[username] == password_hash:
                st.success("Logged in!")
                st.write(f"Welcome, {username}!")
                st.experimental_set_query_params(Login=True, username=username, original_url=st.experimental_get_query_params().get("original_url", [""])[0])  
            else:
                st.error("Invalid password")
        else:
            st.error("Invalid username")
     
    return None

menu=["Login","Signup"]

if "Login" not in s.experimental_get_query_params():
    choice= s.sidebar.selectbox("Select an option", menu)

    if choice == "Login":
        login_()
    else:
        signup_()
# with s.expander:
#     if(s.button(text='Login')):
        
