# Authentication and Authorization using ASP.NET Identity

## Description
This project showcases a comprehensive implementation of authentication and authorization mechanisms within an ASP.NET application, leveraging ASP.NET Identity for user management. It includes robust examples of various authentication methods such as JWT, Cookie, and Refresh Token-based authentication, ensuring secure access to resources.

### Purpose
This project aims to serve as a comprehensive reference and learning resource for developers seeking to implement robust authentication and authorization mechanisms in their ASP.NET applications. Whether you're building a small-scale application or a large-scale enterprise solution, this project provides valuable insights and best practices for ensuring the security of your application's resources.

## Table of Contents
- [Installation](#installation)
- [Database](#database)
- [Usage](#usage)
- [Key Features](#key-features)
- [Technologies](#technologies)


## Installation
To get a local copy up and running follow these simple steps:

1. Clone the repository:
    ```sh
    git clone https://github.com/srivarshabachu/Authentication.git
    cd Authentication
    ```

2. Set up the database:
    ```sh
    dotnet ef database update
    ```

3. Run the application:
    ```sh
    dotnet run
    ```

## Database
To set up the database using Azure Data Studio:
1. Open Azure Data Studio.
2. Connect to your database server.
3. Create a new database and name it `your-database-name`.
4. Execute the SQL scripts provided in the `database` folder of this repository to create the necessary tables and schema.

## Key Features
- **User Registration and Management**: Seamlessly register new users and manage their accounts, including password management and email verification.
- **Authentication Methods**:
  - **JWT (JSON Web Tokens)**: Secure API endpoints using JWT tokens for authentication, providing stateless and scalable authentication.
  - **Cookie Authentication**: Implement session-based authentication with secure cookie management, ideal for web applications.
  - **Refresh Tokens**: Enable automatic token renewal and enhance security by leveraging refresh tokens for long-lived sessions.
- **Role-Based Authorization**: Implement role-based access control (RBAC) to restrict access to resources based on user roles, ensuring fine-grained control over permissions.
- **Database Integration**: Utilize Azure Data Studio for database management, with scripts provided for easy setup and configuration.

## Technologies
- **ASP.NET Core**: A cross-platform, high-performance framework for building modern web applications.
- **ASP.NET Identity**: A membership system that adds login functionality to ASP.NET applications, with support for user registration, authentication, and role-based authorization.
- **JWT (JSON Web Tokens)**: A compact, URL-safe means of representing claims to be transferred between two parties, used for secure authentication.
- **Azure Data Studio**: A cross-platform database tool for developers using the Microsoft data platform.
- **C#**: The programming language used for developing the ASP.NET application.

## Usage
Here are some examples of how to use the application:

### Register a new user
Send a POST request to `/api/auth/Register` with the following JSON body:
json
<!--{
  "username": "string",
  "email": "user@example.com",
  "password": "string",
  "roles": [
    "string"
  ]
}-->
### Login to existing user
Send a POST request to `/api/auth/Login` with the following JSON body:
<!--{
  "userName": "string",
  "password": "string"
}-->
