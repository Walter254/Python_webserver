# Python_webserver

This project develops a simple web server in Python utilizing the socket library to communicate via the HTTP 1.1 protocol. It's designed to run on ports 1024-65535 to avoid needing special privileges. The server interacts with web browsers to display pages based on URL requests, including a basic form for color selection and dynamic content rendering using template engines.

## Overview

The server architecture incorporates Flask for handling HTTP requests, Jinja2 for server-side template rendering, and MongoDB for data storage. Security enhancements include SSL/TLS for encrypted communication, JWT for authentication, and protective measures against common web vulnerabilities. The user interface benefits from CSS frameworks and AJAX for a responsive, dynamic experience, while WebSocket integration supports real-time bi-directional communication.

## Features

- **Color Selection**: Users can select between two colors (red, green), and the server responds with a corresponding colored page.
- **Secure User Authentication**: Registration and login pages, with password hashing and token-based authentication.
- **SSL/TLS Encryption**: Secures data transmission between the server and clients.
- **Dynamic Content Management**: Utilizes Jinja2 for dynamic web page rendering.
- **Real-time Interaction**: WebSockets enable features like live chat and notifications.
- **Course Information**: Displays details about the EE129 course, including schedule, textbook, and instructor contact information.

## Getting started

### Requirements

- Python 3
- Flask
- MongoDB
- OpenSSL for SSL/TLS

### Quickstart

1. Clone the repository.
2. Install dependencies: `pip install flask flask_bcrypt flask_jwt_extended flask_pymongo OpenSSL`
3. Set up MongoDB and obtain a connection URI.
4. Generate SSL certificates and place them in the project root.
5. Run the server: `python app.py`

### License

Copyright (c) 2024.