Project Overview:
The system provides a secure identity management service that allows users to register, authenticate, and view their profile information. Sensitive user data such as Aadhaar/ID number is encrypted at rest using symmetric encryption, and authentication is handled using JWT-based stateless security.
The project is built with a Python backend and a web-based frontend, following secure coding and clean architecture practices.

Setup & Run Instructions:

Backend Setup:
cd backend

python -m venv venv

venv\Scripts\activate

pip install -r requirements.txt

python run.py

Backend will start at:
http://127.0.0.1:5000

Frontend Setup:
Simply open the frontend in a browser:
cd frontend

open index.html

API Documentation:

Authentication APIs

POST /register

Registers a new user with encrypted Aadhaar/ID number.

POST /login

Authenticates user and returns a JWT token.

Profile API (Protected)

GET /profile

Requires JWT token in Authorization header
Decrypts Aadhaar/ID number before sending response

Database Schema:
User Table
| Field Name | Description                 |
| ---------- | --------------------------- |
| id         | Unique user ID              |
| name       | User name                   |
| email      | User email                  |
| password   | Hashed password             |
| aadhaar    | Encrypted Aadhaar/ID number |

AI Tool Usage Log:
Generated AES encryption and decryption utility functions in Python
Assisted in implementing JWT token generation and validation logic
Helped structure Flask backend and authentication flow
Assisted in debugging encryption and authentication issues
Helped draft unit-test logic for encryption/decryption

Effectiveness Score: 4 / 5

