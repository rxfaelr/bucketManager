from flask import Flask, request, jsonify, send_file, render_template, redirect, url_for, session
import boto3
import os
import zipfile
from io import BytesIO
from datetime import datetime
import pytz
from dotenv import load_dotenv
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
import requests
import hashlib
import functools
from flask_wtf.csrf import CSRFProtect
import pyotp
import logging
import qrcode
import io
import time

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

# Admin credentials
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
PASSWORD_SALT = os.getenv('PASSWORD_SALT')

# S3 credentials from environment variables
S3_ENDPOINT = os.getenv('S3_ENDPOINT')
S3_ACCESS_KEY = os.getenv('S3_ACCESS_KEY')
S3_SECRET_KEY = os.getenv('S3_SECRET_KEY')
BUCKET_NAME = os.getenv('BUCKET_NAME')

csrf = CSRFProtect(app)

logging.basicConfig(
    filename='admin_access.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def get_s3_client():
    return boto3.client(
        's3',
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY
    )

def format_size(size):
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size/1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size/(1024*1024):.1f} MB"
    else:
        return f"{size/(1024*1024*1024):.1f} GB"

def encode_folder_path(folder_data, custom_iv=None):
    try:
        original_key = os.getenv('ENCRYPTION_KEY')
        
        key = hashlib.sha256(original_key.encode('utf-8')).digest()
        
        if custom_iv:
            iv = binascii.unhexlify(custom_iv)
        else:
            from Crypto.Random import get_random_bytes
            iv = get_random_bytes(16)
            
        mode = "AES-256"
            
        data_bytes = folder_data.encode('utf-8')
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data_bytes, AES.block_size)
        
        encrypted_data = cipher.encrypt(padded_data)
        
        iv_hex = binascii.hexlify(iv).decode('utf-8')
        encrypted_hex = binascii.hexlify(encrypted_data).decode('utf-8')
        
        return f"{iv_hex}.{encrypted_hex}"
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return None

def decode_folder_path(encrypted_url):
    try:
        parts = encrypted_url.split('.', 1)
        if len(parts) != 2:
            return None
            
        iv_hex, encrypted_hex = parts
        
        original_key = os.getenv('ENCRYPTION_KEY')
        
        key = hashlib.sha256(original_key.encode('utf-8')).digest()
        
        try:
            iv = binascii.unhexlify(iv_hex)
            if len(iv) != 16:
                return None
        except binascii.Error as e:
            return None
            

        if not encrypted_hex or len(encrypted_hex) % 2 != 0:
            return None
            
        encrypted_data = binascii.unhexlify(encrypted_hex)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        decrypted_data = cipher.decrypt(encrypted_data)
        
        try:
            unpadded_data = unpad(decrypted_data, AES.block_size)
            result = unpadded_data.decode('utf-8')
        except Exception as padding_error:
            result = decrypted_data.decode('utf-8').rstrip()
            
        return result
    except Exception as e:
        return None

def extract_url_components(decoded_data):
    try:
        if not decoded_data:
            return None, None, None
            
        parts = decoded_data.split('-', 1)
        
        folder_name = parts[0] if len(parts) > 0 else None
        course_id = folder_name  # They are the same
        user_id = parts[1] if len(parts) > 1 else None
        
        return folder_name, course_id, user_id
    except Exception as e:
        return None, None, None

@app.template_filter('b64encode')
def b64encode_filter(s):
    return base64.urlsafe_b64encode(s.encode()).decode()

@app.template_filter('aesencrypt')
def aesencrypt_filter(s):
    if '/' in s:
        return encode_folder_path(s)
    else:

        return encode_folder_path(s)

@app.route('/')
def index():
    return render_template('error.html')

@app.route('/<path:encoded_path>')
def folder_view(encoded_path):
    try:
        if encoded_path == 'favicon.ico':
            return '', 204
            
        decoded_data = decode_folder_path(encoded_path)
        if not decoded_data:
            return render_template('error.html')
        
        folder_name, course_id, user_id = extract_url_components(decoded_data)
        
        if not folder_name:
            return render_template('error.html')
            
        
        if course_id and user_id:
            has_permission = check_editor_permission(course_id, user_id)
            if not has_permission:
                return render_template('no_permission.html', 
                                      course_id=course_id, 
                                      user_id=user_id)
            
        s3_client = get_s3_client()
        response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=folder_name + '/',
            MaxKeys=1
        )
        
        if 'Contents' in response:
            return handle_folder_view(folder_name, encoded_main_folder=encoded_path, 
                                     course_id=course_id, user_id=user_id)
        else:
            return render_template('error.html')
            
    except Exception as e:
        return render_template('error.html')

def handle_folder_view(folder_path, encoded_main_folder=None, course_id=None, user_id=None):
    try:
        s3_client = get_s3_client()
        
        folder_prefix = folder_path + '/' if not folder_path.endswith('/') else folder_path
        
        response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=folder_prefix,
            Delimiter='/'
        )
        
        folders = []
        files = []
        
        for prefix in response.get('CommonPrefixes', []):
            prefix_path = prefix.get('Prefix', '')
            folder_name = prefix_path.rstrip('/').split('/')[-1]
            
            encoded_path = encode_folder_path(prefix_path.rstrip('/'))
            
            folders.append({
                'name': folder_name,
                'path': prefix_path,
                'encoded_path': encoded_path
            })
        
        for obj in response.get('Contents', []):
            key = obj.get('Key', '')
            
            if key == folder_prefix:
                continue
                
            if '/' in key[len(folder_prefix):]:
                continue
                
            file_name = key.split('/')[-1]
            size = format_size(obj.get('Size', 0))
            last_modified = obj.get('LastModified', datetime.now(pytz.UTC))
            
            if isinstance(last_modified, datetime):
                last_modified = last_modified.strftime('%d/%m/%Y %H:%M')
                
            encoded_path = encode_folder_path(key)
            
            files.append({
                'name': file_name,
                'key': key,
                'size': size,
                'last_modified': last_modified,
                'encoded_path': encoded_path
            })
        
        folders.sort(key=lambda x: x['name'].lower())
        files.sort(key=lambda x: x['name'].lower())
        
        breadcrumbs = []
        path_parts = folder_path.split('/')
        current_path = ""
        
        for i, part in enumerate(path_parts):
            if not part:
                continue
                
            if current_path:
                current_path += "/"
            current_path += part
            
            encoded_path = encode_folder_path(current_path)
            
            breadcrumbs.append({
                'name': part,
                'path': current_path,
                'encoded_path': encoded_path,
                'is_last': i == len(path_parts) - 1
            })
        
        return render_template('folder.html', 
                              folders=folders, 
                              files=files, 
                              breadcrumbs=breadcrumbs,
                              folder_path=folder_path,
                              encoded_main_folder=encoded_main_folder,
                              course_id=course_id,
                              user_id=user_id)
                              
    except Exception as e:
        return render_template('error.html')

@app.route('/download/<encoded_path>')
def download_file(encoded_path):
    try:
        # Decode the encrypted path
        decoded_path = decode_folder_path(encoded_path)
        if not decoded_path:
            return jsonify({"error": "Invalid path"}), 404
            
        
        # For file downloads, we don't need to extract components or check permissions
        file_path = decoded_path
        
        
        s3_client = get_s3_client()
        try:
            response = s3_client.head_object(Bucket=BUCKET_NAME, Key=file_path)
            file_size = response['ContentLength']
            
            file_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=file_path)
            
            def generate():
                for chunk in file_obj['Body'].iter_chunks(chunk_size=8192):
                    yield chunk
            
            return app.response_class(
                generate(),
                mimetype='application/octet-stream',
                headers={
                    'Content-Disposition': f'attachment; filename={os.path.basename(file_path)}',
                    'Content-Length': str(file_size)
                }
            )
        except Exception as e:
            
            try:
                folder_path = os.path.dirname(file_path)
                if not folder_path:
                    folder_path = file_path
                
                filename = os.path.basename(file_path)
                
                
                response = s3_client.list_objects_v2(
                    Bucket=BUCKET_NAME,
                    Prefix=folder_path + '/'
                )
                
                if 'Contents' in response:
                    for obj in response.get('Contents', []):
                        obj_key = obj['Key']
                        obj_name = os.path.basename(obj_key)
                        
                        
                        # If we find a matching flename
                        if obj_name == filename or obj_key == file_path:
                            
                            file_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=obj_key)
                            file_size = file_obj['ContentLength']
                            
                            def generate():
                                for chunk in file_obj['Body'].iter_chunks(chunk_size=8192):
                                    yield chunk
                            
                            return app.response_class(
                                generate(),
                                mimetype='application/octet-stream',
                                headers={
                                    'Content-Disposition': f'attachment; filename={obj_name}',
                                    'Content-Length': str(file_size)
                                }
                            )
                
            except Exception as search_error:
                pass  # This is a placeholder, you can add logging or other handling here
            
            return jsonify({"error": "File not found"}), 404
    except Exception as e:
        print(f"Error in download_file: {str(e)}")
        return jsonify({"error": str(e)}), 404

def find_file_in_folder(s3_client, folder_path, filename):
    try:
        if not folder_path.endswith('/'):
            folder_path += '/'
            
        print(f"Searching in folder: {folder_path}")
        
        response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=folder_path
        )
        
        if 'Contents' in response:
            for obj in response.get('Contents', []):
                obj_key = obj['Key']
                obj_name = os.path.basename(obj_key)
                
                print(f"Checking object: {obj_key} (name: {obj_name})")
                
                if obj_name == filename:
                    print(f"Found file: {obj_key}")
                    return obj_key
                    
        response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=folder_path,
            Delimiter='/'
        )
        
        for prefix in response.get('CommonPrefixes', []):
            prefix_path = prefix.get('Prefix', '')
            
            found_key = find_file_in_folder(s3_client, prefix_path, filename)
            if found_key:
                return found_key
                
        return None
    except Exception as e:
        print(f"Error searching for file: {str(e)}")
        return None

@app.route("/list_folders", methods=["GET"])
def list_folders():
    s3_client = get_s3_client()
    response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Delimiter='/')
    folders = [prefix['Prefix'] for prefix in response.get('CommonPrefixes', [])]
    return jsonify(folders)

@app.route("/list_files", methods=["POST"])
def list_files():
    encoded_folder = request.form.get("folder", "")
    folder = decode_folder_path(encoded_folder)
    if not folder:
        return jsonify({"error": "Invalid folder path"}), 400
        
    s3_client = get_s3_client()
    response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Prefix=folder)
    
    brazil_tz = pytz.timezone('America/Sao_Paulo')
    
    files = []
    for obj in response.get("Contents", []):
        if obj['Key'] != folder:
            size = obj['Size']
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024 * 1024:
                size_str = f"{size/1024:.1f} KB"
            elif size < 1024 * 1024 * 1024:
                size_str = f"{size/(1024*1024):.1f} MB"
            else:
                size_str = f"{size/(1024*1024*1024):.1f} GB"

            utc_time = obj['LastModified']
            local_time = utc_time.astimezone(brazil_tz)
            formatted_date = local_time.strftime('%d/%m/%Y %H:%M:%S')

            files.append({
                'key': obj['Key'],
                'size': size_str,
                'last_modified': formatted_date
            })
    
    return jsonify(files)

@app.route('/download-folder/<encoded_path>')
def download_folder(encoded_path):
    folder_path = decode_folder_path(encoded_path)
    if not folder_path:
        return jsonify({"error": "Invalid path"}), 404
        
    try:
        s3_client = get_s3_client()
        response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Prefix=folder_path)
        
        if 'Contents' not in response:
            return "Pasta vazia ou não encontrada", 404
        
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for obj in response.get("Contents", []):
                if obj["Key"] != folder_path:
                    file_key = obj["Key"]
                    file_data = s3_client.get_object(Bucket=BUCKET_NAME, Key=file_key)["Body"].read()
                    relative_path = file_key[len(folder_path):]
                    zip_file.writestr(relative_path, file_data)
        
        zip_buffer.seek(0)
        folder_name = os.path.basename(folder_path.rstrip('/'))
        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f"{folder_name}.zip"
        )
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/delete_file", methods=["POST"])
def delete_file():
    file_key = request.form.get("file")
    try:
        s3_client = get_s3_client()
        s3_client.delete_object(
            Bucket=BUCKET_NAME,
            Key=file_key
        )
        return jsonify({"message": "Arquivo deletado com sucesso!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/get_folder_files", methods=["GET"])
def get_folder_files():
    folder = request.args.get("folder")
    s3_client = get_s3_client()
    response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Prefix=folder)
    
    files = []
    for obj in response.get("Contents", []):
        if obj['Key'] != folder:
            files.append({
                'key': obj['Key'],
                'size': obj['Size']
            })
    
    return jsonify(files)

@app.route('/list-folder-files/<encoded_path>')
def list_folder_files(encoded_path):
    try:
        folder_path = decode_folder_path(encoded_path)
        if not folder_path:
            print(f"Failed to decode folder path for listing: {encoded_path}")
            return jsonify([])
            
        # Extract the folder name from the decoded data
        folder_name, _, _ = extract_url_components(folder_path)
        if not folder_name:
            print(f"Failed to extract folder name for listing")
            return jsonify([])
            
        print(f"Listing files in folder: {folder_name}")
        
        s3_client = get_s3_client()
        
        folder_prefix = folder_name + '/' if not folder_name.endswith('/') else folder_name
        
        response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=folder_prefix
        )
        
        if 'Contents' not in response:
            print(f"No contents found in folder: {folder_name}")
            return jsonify([])
        
        files = []
        for obj in response.get("Contents", []):
            obj_key = obj["Key"]
            
            if obj_key == folder_prefix:
                continue
                
            files.append({
                'key': obj_key,
                'name': os.path.basename(obj_key)
            })
        
        print(f"Found {len(files)} files in folder: {folder_name}")
        return jsonify(files)
        
    except Exception as e:
        print(f"Error in list_folder_files: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/encode_folder', methods=['POST'])
def encode_folder():
    try:
        data = request.get_json()
        folder = data.get('folder')
        user_id = data.get('userId', '')
        custom_iv = data.get('iv') 
        
        if not folder:
            return jsonify({'error': 'No folder provided'}), 400
        
        folder_data = f"{folder}-{user_id}"
        
        encoded = encode_folder_path(folder_data, custom_iv)
        if encoded is None:
            return jsonify({'error': 'Encoding failed'}), 500
            
        return jsonify({'encoded': encoded})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/generate_test_url')
def generate_test_url():
    folder = request.args.get('folder', '')
    user_id = request.args.get('user_id', '')
    
    if not folder:
        return jsonify({"error": "Folder name is required"}), 400
        
    folder_data = f"{folder}-{user_id}"
    
    encoded = encode_folder_path(folder_data)
    if encoded is None:
        return jsonify({"error": "Encryption failed"}), 500
        
    base_url = request.host_url.rstrip('/')
    full_url = f"{base_url}/{encoded}"
    
    return jsonify({
        "folder": folder,
        "course_id": folder,
        "user_id": user_id,
        "encoded": encoded,
        "url": full_url
    })

@app.route('/url_generator')
def url_generator_form():
    return render_template('url_generator.html')

@app.route('/batch-download', methods=['POST'])
def batch_download():
    try:
        data = request.get_json()
        folder = data.get('folder')
        user_id = data.get('userId', '')
        
        if not folder:
            return jsonify({'error': 'No folder provided'}), 400
            

        
        folder_name = folder
        
        print(f"Batch download for folder: {folder_name}, userId: {user_id}")
        
        s3_client = get_s3_client()
        
        folder_prefix = folder_name + '/' if not folder_name.endswith('/') else folder_name
        
        response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=folder_prefix
        )
        
        if 'Contents' not in response:
            return jsonify({'error': 'No files found in folder'}), 404
            
        files = []
        for obj in response.get("Contents", []):
            obj_key = obj["Key"]
            
            if obj_key == folder_prefix:
                continue


            encoded_path = encode_folder_path(obj_key)
            
            test_decode = decode_folder_path(encoded_path)
            print(f"File: {obj_key}, Encoded: {encoded_path[:20]}..., Decoded: {test_decode[:30]}...")
            
            files.append({
                'key': obj_key,
                'name': os.path.basename(obj_key),
                'encoded': encoded_path
            })
            
        return jsonify({'files': files})
    except Exception as e:
        print(f"Error in batch_download: {str(e)}")
        return jsonify({'error': str(e)}), 500

def check_editor_permission(course_id, user_id):
    try:
        if not course_id or not user_id or course_id == 'None' or user_id == 'None':
            print(f"Missing course_id or user_id for permission check: {course_id}, {user_id}")
            return False
            
        #request to the permission API
        url = f"https://api-v3.cefis.com.br/course-video-editing/check-editor-permission"
        params = {
            "courseId": course_id,
            "editorId": user_id
        }
        
        print(f"Checking permission for courseId: {course_id}, editorId: {user_id}")
        response = requests.get(url, params=params, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            has_permission = data.get('hasPermission', False)
            print(f"Permission check result: {has_permission}")
            return has_permission
        else:
            print(f"Permission API returned status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"Error checking permission: {str(e)}")
        return False

@app.route('/test-encryption')
def test_encryption():
    try:
        test_data = "test-folder-123-456"
        
        encrypted = encode_folder_path(test_data)
        if not encrypted:
            return jsonify({"error": "Encryption failed"}), 500
            
        decrypted = decode_folder_path(encrypted)
        if not decrypted:
            return jsonify({"error": "Decryption failed"}), 500
            
        return jsonify({
            "original": test_data,
            "encrypted": encrypted,
            "decrypted": decrypted,
            "success": test_data == decrypted
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def admin_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session or not session['admin_logged_in']:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/admin')
def admin_redirect():
    return redirect(url_for('admin_login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = None
    
    if request.method == 'POST':
        auth_token = request.form.get('auth_token', '')
        
        if not auth_token or ':' not in auth_token:
            error = 'Invalid authentication'
            logging.warning(f"Invalid auth token format from IP: {request.remote_addr}")
            return render_template('admin_login.html', error=error)
            
        token_parts = auth_token.split(':', 1)
        if len(token_parts) != 2:
            error = 'Invalid authentication'
            logging.warning(f"Invalid auth token format from IP: {request.remote_addr}")
            return render_template('admin_login.html', error=error)
            
        received_hash, timestamp = token_parts
        
        try:
            timestamp_int = int(timestamp)
            current_time = int(time.time() * 1000)  # Current time in milliseconds
            if current_time - timestamp_int > 300000:  # 5 minutes in milliseconds
                error = 'Authentication expired'
                logging.warning(f"Expired auth attempt from IP: {request.remote_addr}")
                return render_template('admin_login.html', error=error)
        except ValueError:
            error = 'Invalid authentication'
            logging.warning(f"Invalid timestamp in auth token from IP: {request.remote_addr}")
            return render_template('admin_login.html', error=error)
        
        expected_string = ADMIN_USERNAME + ":" + ADMIN_PASSWORD + ":" + timestamp
        expected_hash = hashlib.sha256(expected_string.encode()).hexdigest()
        
        if received_hash == expected_hash:
            session['admin_logged_in'] = True
            logging.info(f"Successful login for user: {ADMIN_USERNAME} from IP: {request.remote_addr}")
            return redirect(url_for('admin_dashboard'))
        else:
            error = 'Invalid username or password'
            logging.warning(f"Failed login attempt from IP: {request.remote_addr}")
    
    return render_template('admin_login.html', error=error)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/api/folders')
@admin_required
def admin_api_folders():
    try:
        s3_client = get_s3_client()
        response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Delimiter='/'
        )
        
        folders = []
        for prefix in response.get('CommonPrefixes', []):
            prefix_path = prefix.get('Prefix', '')
            folder_name = prefix_path.rstrip('/')
            
            encoded_path = encode_folder_path(folder_name)
            
            folders.append({
                'name': folder_name,
                'path': prefix_path,
                'encoded': encoded_path
            })
        
        folders.sort(key=lambda x: x['name'].lower())
        return jsonify(folders)
        
    except Exception as e:
        print(f"Error listing folders: {str(e)}")
        return jsonify([])

@app.route('/admin/view/<path:encoded_path>')
@admin_required
def admin_view_folder(encoded_path):
    try:
        decoded_path = decode_folder_path(encoded_path)
        if not decoded_path:
            return render_template('error.html')
        
        s3_client = get_s3_client()
        
        folder_prefix = decoded_path + '/' if not decoded_path.endswith('/') else decoded_path
        
        response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=folder_prefix,
            Delimiter='/'
        )
        
        folders = []
        files = []
        
        for prefix in response.get('CommonPrefixes', []):
            prefix_path = prefix.get('Prefix', '')
            folder_name = prefix_path.rstrip('/').split('/')[-1]
            
            encoded_path = encode_folder_path(prefix_path.rstrip('/'))
            
            folders.append({
                'name': folder_name,
                'path': prefix_path,
                'encoded_path': encoded_path
            })
        
        for obj in response.get('Contents', []):
            key = obj.get('Key', '')
            
            if key == folder_prefix:
                continue
                
            if '/' in key[len(folder_prefix):]:
                continue
                
            file_name = key.split('/')[-1]
            size = format_size(obj.get('Size', 0))
            last_modified = obj.get('LastModified', datetime.now(pytz.UTC))
            
            if isinstance(last_modified, datetime):
                last_modified = last_modified.strftime('%d/%m/%Y %H:%M')
                
            encoded_path = encode_folder_path(key)
            
            files.append({
                'name': file_name,
                'key': key,
                'size': size,
                'last_modified': last_modified,
                'encoded_path': encoded_path
            })
        
        folders.sort(key=lambda x: x['name'].lower())
        files.sort(key=lambda x: x['name'].lower())
        
        breadcrumbs = []
        path_parts = decoded_path.split('/')
        current_path = ""
        
        for i, part in enumerate(path_parts):
            if not part:
                continue
                
            if current_path:
                current_path += "/"
            current_path += part
            
            encoded_path = encode_folder_path(current_path)
            
            breadcrumbs.append({
                'name': part,
                'path': current_path,
                'encoded_path': encoded_path,
                'is_last': i == len(path_parts) - 1
            })
        
        return render_template('admin_folder_view.html', 
                              folders=folders, 
                              files=files, 
                              breadcrumbs=breadcrumbs,
                              folder_path=decoded_path,
                              encoded_path=encoded_path)
                              
    except Exception as e:
        print(f"Error in admin_view_folder: {str(e)}")
        return render_template('error.html')

@app.route('/admin/download/<path:encoded_path>')
@admin_required
def admin_download_folder(encoded_path):
    folder_path = decode_folder_path(encoded_path)
    if not folder_path:
        return jsonify({"error": "Invalid path"}), 404
        
    try:
        s3_client = get_s3_client()
        response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Prefix=folder_path)
        
        if 'Contents' not in response:
            return "Folder empty or not found", 404
        
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for obj in response.get("Contents", []):
                if obj["Key"] != folder_path:
                    file_key = obj["Key"]
                    file_data = s3_client.get_object(Bucket=BUCKET_NAME, Key=file_key)["Body"].read()
                    relative_path = file_key[len(folder_path):] if folder_path.endswith('/') else file_key[len(folder_path)+1:]
                    zip_file.writestr(relative_path, file_data)
        
        zip_buffer.seek(0)
        folder_name = os.path.basename(folder_path.rstrip('/'))
        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f"{folder_name}.zip"
        )
        
    except Exception as e:
        print(f"Error in admin_download_folder: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/admin/download-file/<path:encoded_path>')
@admin_required
def admin_download_file(encoded_path):
    try:
        decoded_path = decode_folder_path(encoded_path)
        if not decoded_path:
            return jsonify({"error": "Invalid path"}), 404
            
        s3_client = get_s3_client()
        
        try:
            file_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=decoded_path)
            file_size = file_obj['ContentLength']
            file_name = os.path.basename(decoded_path)
            
            def generate():
                for chunk in file_obj['Body'].iter_chunks(chunk_size=8192):
                    yield chunk
            
            return app.response_class(
                generate(),
                mimetype='application/octet-stream',
                headers={
                    'Content-Disposition': f'attachment; filename={file_name}',
                    'Content-Length': str(file_size)
                }
            )
        except Exception as e:
            print(f"Error downloading file: {str(e)}")
            return jsonify({"error": "File not found"}), 404
            
    except Exception as e:
        print(f"Error in admin_download_file: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/admin/api/folder-files/<path:encoded_path>')
@admin_required
def admin_api_folder_files(encoded_path):
    try:
        folder_path = decode_folder_path(encoded_path)
        if not folder_path:
            return jsonify({"error": "Invalid path"}), 404
            
        s3_client = get_s3_client()
        
        folder_prefix = folder_path + '/' if not folder_path.endswith('/') else folder_path
        
        response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=folder_prefix
        )
        
        if 'Contents' not in response:
            return jsonify({"files": []})
            
        files = []
        for obj in response.get("Contents", []):
            obj_key = obj["Key"]
            
            if obj_key == folder_prefix:
                continue
                
            file_name = os.path.basename(obj_key)
            encoded_path = encode_folder_path(obj_key)
            
            files.append({
                'key': obj_key,
                'name': file_name,
                'encoded': encoded_path
            })
        
        return jsonify({"files": files})
        
    except Exception as e:
        print(f"Error in admin_api_folder_files: {str(e)}")
        return jsonify({"error": str(e)}), 500

def verify_password(stored_password, provided_password):
    salt = os.getenv('PASSWORD_SALT', 'default_salt')
    hashed_provided = hashlib.sha256((provided_password + salt).encode()).hexdigest()
    return hashed_provided == stored_password

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)