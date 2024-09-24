How to Run the Program

1. Install Python and Libraries:
   - Ensure Python is installed on your system.
   - Open your terminal and run the following commands to install the necessary libraries:
     pip install streamlit pandas matplotlib bcrypt streamlit-option-menu openpyxl

2. Create the Program File:
   - Copy and paste the code into a file named app.py.

3. Create Credentials File:
   - In the same folder as app.py, create a file called credentials.txt.
   - Leave this file empty initially (new users will be added via the signup process).

4. Prepare the Sales Excel File:
   - You need to have an Excel file named `sales.xlsx` which contains sales data. This file must be uploaded through the Streamlit interface when the app runs.

5. Run the Streamlit App:
   - Open your terminal in the folder where app.py is located.
   - Run the following command:
     streamlit run app.py

6. Usage:
   - The app will open in your default browser.
   - You will be able to log in, sign up, manage products, analyze sales, and upload the `sales.xlsx` file to visualize and forecast data.
