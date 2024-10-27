from flask import Flask, request, jsonify
import json
import jwt 
app = Flask(__name__)
import hashlib
import hmac
import datetime
import os
from werkzeug.datastructures import MultiDict

HARDCODED_API_KEY = "my_secret_key"
SECRET_KEY = "my_secret_key"
NOTION_KEY = "secret_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
UNKEY="ab12cd34ef56gh78ij90klmnopqr23stuv45wxyz"
API_KEY = "secret_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

def create_canonical_query_string(params):
    # Sort the parameters alphabetically and format them
    sorted_params = sorted(params.items())
    return '&'.join([f"{k}={v}" for k, v in sorted_params])

def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def get_signature_key(key, date_stamp, region_name, service_name):
    k_date = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region_name)
    k_service = sign(k_region, service_name)
    k_signing = sign(k_service, 'aws4_request')
    return k_signing

def create_canonical_headers(headers, signed_headers):
    canonical_headers = ''
    for header in signed_headers.split(';'):
        canonical_headers += f'{header}:{headers[header].strip()}\n'
    return canonical_headers

def parse_authorization_header(auth_header):
    parts = auth_header.split(',')
    credential, signed_headers_part, signature_part = parts
    access_key = credential.split('=')[1].split('/')[0]
    signed_headers = signed_headers_part.split('=')[1]
    signature = signature_part.split('=')[1]
    return access_key, signed_headers, signature

def validate_signature(request, aws_secret_key, aws_region):
    method = request.method
    headers = request.headers
    
    host = headers['Host']
    canonical_uri = request.path

    query_params = MultiDict(request.args)
    canonical_query_string = create_canonical_query_string(query_params)

    # Extract AWS headers
    request_date = headers.get('X-Amz-Date', '')
    auth_header = headers.get('Authorization', '')

    access_key, signed_headers, request_signature = parse_authorization_header(auth_header)
    # Create payload hash
    payload_hash = hashlib.sha256(request.data).hexdigest()
    # Create canonical headers
    canonical_headers = create_canonical_headers(headers, signed_headers)
    # Create canonical request
    param=""
    canonical_request = f"{method}\n{canonical_uri}\n{param}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    # Create string to sign
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = f"{request_date[:8]}/{aws_region}/s3/aws4_request"
    string_to_sign = f"{algorithm}\n{request_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"

    # Calculate the signature
    signing_key = get_signature_key(aws_secret_key, request_date[:8], aws_region, "s3")
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    # Compare the signature from the request with the calculated signature
    return request_signature == signature


@app.route('/verify-key', methods=['GET'])
def unkey_webserver():
        if 'Ukey-Key' in request.headers:
            
            notion_key = request.headers['Ukey-Key']
            if notion_key == UNKEY:
                return send_json_content()

            else:
                return jsonify({"message": "Invalid API key", "status": "failed"}), 500
        elif 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                if token == API_KEY:
                    return send_json_content()
                else:
                    return jsonify({"message": "Invalid token format", "status": "failed"}), 500
            else:
                return jsonify({"message": "Invalid token format", "status": "failed"}), 500
        else:
            return jsonify({"message": "API key not provided", "status": "failed"}), 400       
                
@app.route('/get-file', methods=['GET'])
def get_file():
    return send_text_content()
    
    
@app.route('/get-data', methods=['POST'])
def get_data():
    return send_json_content()

@app.route('/post-response', methods=['POST'])
def post_response():
    try:
        data = request.get_json()
        username = data.get('username', 'No username provided')
        password = data.get('password', 'No password provided')
        if password !='vTSAexmZuW~0':
            return jsonify({"message": "Password is incorrect!", "status": "failed"}), 500
        return jsonify({"message": "Data received and processed successfully", "status": "success"}), 200
    except Exception as e:
        return jsonify({"message": str(e), "status": "failed"}), 500
    
def send_text_content():
    file_path = 'http_response_1.txt'
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, 'r') as file:
            data = file.read()
        return data, 200
    except Exception as e:
        return str(e), 500
    
    
@app.route('/search', methods=['POST'])
def notion_webserver():
        if 'api-key' in request.headers:
            api_key = request.headers['api-key']
            if api_key == API_KEY:
                data=request.get_json()
                ancestorId=data["ancestorId"]
                if ancestorId=='1e0c644c-0caf-40b6-9fa3-8107ff6a82ed':
                    return send_json_content()
                else:
                    return jsonify({"message": "Invalid ancestorId", "status": "failed"}), 401
            else:
                return jsonify({"message": "Invalid API key", "status": "failed"}), 401

@app.route('/uploadfile.txt', methods=['POST'])
def check_sign():
    if 'Authorization' in request.headers:
        # Extracting the token from the header
        token = request.headers['Authorization']
        if 'AWS4-HMAC-SHA256' in token:
            validate=validate_signature(request, 'bMDhAvCWMwu/7IhhnziifKKdcf0/c5EAjXk463Lg', 'us-east-1')
            if validate:
              return send_json_content()
            else:
              return jsonify({"message": "Sign is not valid", "status": "failed"}), 401
            
@app.route('/check-header', methods=['POST'])
def check_header():
    request_data = request.data
    print(request.headers)
    if 'Authorization' in request.headers:
        token = request.headers['Authorization']
        if 'AWS4-HMAC-SHA256' in token:
            validate=validate_signature(request, 'bMDhAvCWMwu/7IhhnziifKKdcf0/c5EAjXk463Lg', 'us-east-1')
            if validate:
              return send_text_content()
            else:
              return jsonify({"message": "Sign is not valid", "status": "failed"}), 401
        else:
          token = request.headers['Authorization'].split(" ")[1]  
          try:
              data=request.data
              jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
              return jsonify({"message": "Token is valid!", "status": "Information uploaded"}), 200
          except jwt.ExpiredSignatureError:
              return jsonify({"message": "Token has expired", "status": "failed"}), 401
          except jwt.InvalidTokenError:
              return jsonify({"message": "Invalid token", "status": "failed"}), 401

    elif 'api-key' in request.headers:
        api_key = request.headers['api-key']
        if api_key == HARDCODED_API_KEY:
            return send_json_content()
        else:
            return jsonify({"message": "Invalid API key", "status": "failed"}), 401
    
    

    else:
        return send_json_content()

    
def send_text_content():
    try:
        with open('http_response_1.txt', 'r') as file:
            data = file.read()
        return data, 200
    except Exception as e:
        return str(e), 500
    
def send_json_content():
    try:
        with open('open_charge_map_sample.json', 'r') as file:
            data = json.load(file)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"message": str(e), "status": "failed"}), 500

if __name__ == '__main__':
    app.run(threaded=True, debug=True)
