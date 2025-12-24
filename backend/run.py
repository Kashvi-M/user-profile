#!/usr/bin/env python
"""
Simple script to run the Flask application
"""
from app import app

if __name__ == '__main__':
    print("Starting Flask server...")
    print("Backend API will be available at http://localhost:5000")
    print("Make sure to start the frontend server separately")
    app.run(debug=True, port=5000, host='0.0.0.0')

