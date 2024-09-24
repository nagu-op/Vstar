import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from streamlit_option_menu import option_menu
import bcrypt
import re  # Import regular expressions module

# ----- Advanced Login Section -----

# Function to load credentials from a text file
def load_credentials(file_path):
    credentials = {}
    try:
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if line:  # Ignore empty lines
                    username, hashed_password = line.split(':', 1)
                    credentials[username] = hashed_password
    except FileNotFoundError:
        return {}
    return credentials

# Function to save credentials to a text file
def save_credentials(file_path, credentials):
    with open(file_path, 'w') as file:
        for username, hashed_password in credentials.items():
            file.write(f"{username}:{hashed_password}\n")

# Function to hash a password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Function to verify a password
def verify_password(stored_hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

# Function to validate a password
def validate_password(password):
    min_length = 8
    if len(password) < min_length:
        return False, f"Password must be at least {min_length} characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."
    return True, "Password is valid."

# Load credentials
credentials_file = 'credentials.txt'
credentials = load_credentials(credentials_file)

# Function to handle the login process
def login():
    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    login_button = st.button("Login")
    
    if login_button:
        if username in credentials and verify_password(credentials[username], password):
            st.success("Login successful!")
            st.session_state['logged_in'] = True
            st.session_state['username'] = username
        else:
            st.error("Invalid username or password")

# Function to handle the signup process
def signup():
    st.title("Signup")
    new_username = st.text_input("New Username")
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    signup_button = st.button("Sign Up")
    
    if signup_button:
        if new_username in credentials:
            st.error("Username already exists")
        elif new_password != confirm_password:
            st.error("Passwords do not match")
        else:
            is_valid, message = validate_password(new_password)
            if not is_valid:
                st.error(message)
            else:
                hashed_password = hash_password(new_password)
                credentials[new_username] = hashed_password
                save_credentials(credentials_file, credentials)
                st.success("Signup successful! You can now log in.")

# Function to handle the forgot password process
def forgot_password():
    st.title("Forgot Password")
    username = st.text_input("Enter your username")
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm New Password", type="password")
    reset_button = st.button("Reset Password")
    
    if reset_button:
        if username not in credentials:
            st.error("Username not found")
        elif new_password != confirm_password:
            st.error("Passwords do not match")
        else:
            is_valid, message = validate_password(new_password)
            if not is_valid:
                st.error(message)
            else:
                hashed_password = hash_password(new_password)
                credentials[username] = hashed_password
                save_credentials(credentials_file, credentials)
                st.success("Password reset successful! You can now log in with your new password.")

# Function to handle account deletion
def delete_account():
    st.title("Delete Account")
    username = st.text_input("Enter your username")
    password = st.text_input("Enter your password", type="password")
    delete_button = st.button("Delete Account")
    
    if delete_button:
        if username not in credentials:
            st.error("Username not found")
        elif not verify_password(credentials[username], password):
            st.error("Incorrect password")
        else:
            del credentials[username]
            save_credentials(credentials_file, credentials)
            st.success("Account deleted successfully!")

# Streamlit app configuration
st.set_page_config(page_title="Sales Analysis and Forecasting", page_icon=":bar_chart:", layout="wide")

# Authentication State
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False

# Use option menu to switch between Login, Signup, Forgot Password, and Delete Account
if not st.session_state['logged_in']:
    view_option = option_menu(
        menu_title=None, 
        options=["Login", "Signup", "Forgot Password", "Delete Account"], 
        icons=["person", "person-add", "key", "trash"], 
        menu_icon="cast", 
        default_index=0, 
        orientation="horizontal"
    )

    if view_option == "Login":
        login()
    elif view_option == "Signup":
        signup()
    elif view_option == "Forgot Password":
        forgot_password()
    elif view_option == "Delete Account":
        delete_account()

# ----- Sales Analysis and Forecasting Section -----

else:
    st.sidebar.header(f"Welcome, {st.session_state['username']}!")
    
    if st.sidebar.button("Log out"):
        st.session_state['logged_in'] = False
        st.experimental_rerun()

    uploaded_file = st.file_uploader("Upload Excel File", type="xlsx")

    if uploaded_file is not None:
        df = pd.read_excel(uploaded_file)

        view_option = option_menu(
            menu_title=None, 
            options=["Sales Details", "Forecasting", "Manage Products", "Budget Allocation"], 
            icons=["bar-chart-fill", "graph-up-arrow", "box", "currency-dollar"], 
            menu_icon="cast", 
            default_index=0, 
            orientation="horizontal"
        )

        if view_option == "Sales Details":
            st.header("Sales Details")

            # Add a slider for limiting the number of rows displayed
            num_rows = st.slider(
                "Select the number of rows to display",
                min_value=1, max_value=len(df), value=10, step=1
            )

            # Filter data based on the number of rows selected
            filtered_df = df.head(num_rows)

            # Store filtered DataFrame in session state
            st.session_state['filtered_data'] = filtered_df

            # Display the selected number of rows
            st.dataframe(filtered_df)

            # Show product statistics
            product_sales_count = filtered_df['Product'].value_counts().reset_index()
            product_sales_count.columns = ['Product', 'Number of Sales']

            if len(product_sales_count) > 0:
                top_product = product_sales_count.iloc[0]
                st.write(f"**Top Product:** {top_product['Product']} with {top_product['Number of Sales']} sales")

                # Plot sales count by product
                fig, ax = plt.subplots()
                product_sales_count.plot(kind='bar', x='Product', y='Number of Sales', ax=ax, color='skyblue', legend=False)
                ax.set_title('Number of Sales per Product')
                ax.set_ylabel('Number of Sales')
                plt.xticks(rotation=45, ha='right')
                st.pyplot(fig)

                # Additional Graphs (using only filtered data)
                # Sales by Size
                st.subheader("Sales by Size")
                if 'Size' in filtered_df.columns:
                    size_sales_count = filtered_df['Size'].value_counts().reset_index()
                    size_sales_count.columns = ['Size', 'Number of Sales']

                    fig, ax = plt.subplots()
                    size_sales_count.plot(kind='bar', x='Size', y='Number of Sales', ax=ax, color='lightgreen', legend=False)
                    ax.set_title('Number of Sales per Size')
                    ax.set_ylabel('Number of Sales')
                    plt.xticks(rotation=45, ha='right')
                    st.pyplot(fig)

                # Sales by Party
                st.subheader("Sales by Party")
                if 'Party' in filtered_df.columns:
                    party_sales_count = filtered_df['Party'].value_counts().reset_index()
                    party_sales_count.columns = ['Party', 'Number of Sales']

                    fig, ax = plt.subplots()
                    party_sales_count.plot(kind='bar', x='Party', y='Number of Sales', ax=ax, color='lightblue', legend=False)
                    ax.set_title('Number of Sales per Party')
                    ax.set_ylabel('Number of Sales')
                    plt.xticks(rotation=45, ha='right')
                    st.pyplot(fig)

        elif view_option == "Forecasting":
            st.header("Forecasting Details")

            # Retrieve filtered DataFrame from session state
            filtered_df = st.session_state.get('filtered_data', df.head(10))  # Fallback to the first 10 rows if not set

            # Select top 6 selling products from filtered data
            top_products = filtered_df['Product'].value_counts().head(6).reset_index()
            top_products.columns = ['Product', 'Number of Sales']

            current_stock = {}
            for product in top_products['Product']:
                stock = st.number_input(f"Current stock for {product}:", min_value=0, step=1, key=product)
                current_stock[product] = stock

            output_data = []
            for _, row in top_products.iterrows():
                product = row['Product']
                sales = row['Number of Sales']
                stock_needed = sales
                additional_units_needed = max(stock_needed - current_stock.get(product, 0), 0)
                output_data.append({
                    'Product': product,
                    'Last Month Sales': sales,
                    'Current Stock': current_stock.get(product, 0),
                    'Stock Needed': stock_needed,
                    'Additional Units Needed': additional_units_needed
                })

            output_df = pd.DataFrame(output_data)
            st.dataframe(output_df)

        elif view_option == "Manage Products":
            st.header("Manage Products")
            current_products = df['Product'].unique().tolist()
            st.write("Current Products:", current_products)

            # Add or remove products
            new_product = st.text_input("Add a new product:")
            if st.button("Add Product") and new_product:
                new_row = pd.DataFrame([[new_product, 0]], columns=['Product', 'Number of Sales'])
                df = pd.concat([df, new_row], ignore_index=True)
                st.success(f"{new_product} added successfully!")

            remove_product = st.selectbox("Select a product to remove:", current_products)
            if st.button("Remove Product") and remove_product:
                df = df[df['Product'] != remove_product]
                st.success(f"{remove_product} removed successfully!")

        elif view_option == "Budget Allocation":
            st.header("Budget Allocation")

            target_amount = st.number_input("Enter the target amount to distribute:", min_value=0.0)
            product_sales_count = df['Product'].value_counts().reset_index()
            product_sales_count.columns = ['Product', 'Number of Sales']
            total_sales = product_sales_count['Number of Sales'].sum()

            allocation_data = []
            for _, row in product_sales_count.iterrows():
                product = row['Product']
                sales = row['Number of Sales']
                distribution = (sales / total_sales) * target_amount if total_sales > 0 else 0
                allocation_data.append({'Product': product, 'Distribution Amount': distribution})

            allocation_df = pd.DataFrame(allocation_data)
            st.dataframe(allocation_df)

            # Explanation of budget allocation
            st.subheader("How Budget Allocation Works")
            st.write("""
                The target amount is distributed among products based on their total sales. The share each product receives
                is proportional to its contribution to the total sales. For example, if a product accounts for 10% of total
                sales, it will receive 10% of the target budget. This allows the budget to be allocated based on product
                performance, ensuring that high-performing products receive the necessary resources to maintain or increase their sales.
            """)

        # Handle any exceptions
        try:
            pass  # Any additional error handling can be placed here
        except Exception as e:
            st.error(f"An error occurred: {e}")
