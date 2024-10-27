#!/bin/bash


#!/bin/bash

# Step 1: Install Flask
pip install Flask

# Step 2: Install Gunicorn
pip install gunicorn
sudo apt install gunicorn


# Step 3: Run the Flask application using Gunicorn
# Replace 'webserver' with the name of your Python module (without .py extension)
# Replace 'app' with the Flask application instance
gunicorn -w 4 -b 0.0.0.0:5000 webserver:app
