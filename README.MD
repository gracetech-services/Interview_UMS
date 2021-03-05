# User Management System

### Task

You're asked to write a simple user management web app.

After it's finished, please provide the following:

1. A demo video/gif of the working system
2. Your cloned GitHub repository link that has all implementation
3. Summary of what you've done, thoughts/ideas on the development experience

### Requirements

1. Please implement 4 pages: LoginPage, SignUpPage, UserHomePage, ChangePasswordPage
2. LoginPage is the default page (home page), it has two input boxes (Email and Password) and two buttons (Login and SignUp).
    - When user clicks Login button, validate the email address and password (>=3 chars), if validation passes, call server API "/login" to verify the Email/password, if server returns OK, store the access token and navigate to UserHomePage, otherwise show error and ask user to re-enter email/password
    - When user clicks SignUp button, navigate to SignUpPage
3. SignUpPage has three input boxes (Email, Password and Password again), one button (CreateAccount) and one link (GoBack).
    - When user clicks CreateAccount button, validate the email address and password (two passwords match and >=3 chars), if validation passes, call server API "/create", if server returns OK, store the access token and navigate to UserHomePage, otherwise show error and ask user to re-enter email/password.
    - When user clicks GoBack link, navigate to LoginPage
4. UserHomePage has one label (show user Email) and two links (ChangePassword and Logout)
    - When user clicks ChangePassword button, navigate to ChangePasswordPage
    - When user clicks Logout button, clear the access token and navigate to LoginPage
5. ChangePasswordPage has two input boxes (Password and PasswordAgain), one button (ChangePassword) and one link (GoBack)
    - When user clicks ChangePassword button, validate two passwords match and >=3 chars, call server API "/changePassword", if server returns OK, navigate to UserHome page, otherwise show error and ask user to re-enter password
    - When user clicks GoBack link, navigate to UserHomePage
6. When user is not logged in, directly accessing UserHomePage or ChangePasswordPage will automatically navigate to LoginPage
7. Please do your best to make the UI look good and easy to use

### Service

Service is written in NodeJS under "service" folder. Please run it locally for development.

It provides 3 APIs, please read the code to understand how webapp should call each API.
- create
- login
- changePassword

### WebApp

WebApp is written in React under "web" folder.

Please use material-ui (https://material-ui.com) and react-router-dom (https://reactrouter.com/web/guides/quick-start)

## Tools

Please check out the following to help develop & debug

- NodeJS - https://nodejs.org
- React - https://reactjs.org
- Material-ui - https://material-ui.com
- VSCode - main source code editor/debugger (open in root folder and install the recommended extensions, press Alt+Shift+F to prettify the code as needed)
- DB Browser for SQLite - a tool to view the sqlite3 database (users.db)
