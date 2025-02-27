from flask import Flask, request, jsonify, send_file, render_template
import boto3
import os
import zipfile
from io import BytesIO
from datetime import datetime
import pytz
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# S3 credentials from environment variables
S3_ENDPOINT = os.getenv('S3_ENDPOINT')
S3_ACCESS_KEY = os.getenv('S3_ACCESS_KEY')
S3_SECRET_KEY = os.getenv('S3_SECRET_KEY')
BUCKET_NAME = os.getenv('BUCKET_NAME')

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

@app.route('/')
def index():
    return render_template('error.html')

@app.route('/<path:folder>')
def folder_view(folder):
    folder_path = f"{folder}/" if not folder.endswith('/') else folder
    
    try:
        s3_client = get_s3_client()
        
        response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=folder_path
        )
        
        subdirectories = set()
        files = []
        brazil_tz = pytz.timezone('America/Sao_Paulo')
        
        if 'Contents' in response:
            for obj in response['Contents']:
                key = obj['Key']
                
                if key == folder_path:
                    continue
                
                relative_path = key[len(folder_path):]
                if not relative_path:
                    continue
                
                parts = relative_path.rstrip('/').split('/')
                
                if len(parts) > 1:
                    subdirectories.add(parts[0])
                else:
                    utc_time = obj['LastModified']
                    local_time = utc_time.astimezone(brazil_tz)
                    
                    files.append({
                        'name': parts[0],
                        'key': key,
                        'size': format_size(obj['Size']),
                        'last_modified': local_time.strftime('%d/%m/%Y %H:%M:%S')
                    })
        
        dir_response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=folder_path,
            Delimiter='/'
        )
        
        for prefix in dir_response.get('CommonPrefixes', []):
            prefix_path = prefix.get('Prefix', '')
            if prefix_path != folder_path:
                dir_name = prefix_path[len(folder_path):].rstrip('/')
                if dir_name:
                    subdirectories.add(dir_name)
        
        subdirs_list = [
            {
                'name': subdir,
                'path': f"{folder_path}{subdir}/"
            }
            for subdir in subdirectories
        ]
        
        subdirs_list.sort(key=lambda x: x['name'].lower())
        files.sort(key=lambda x: x['name'].lower())
        
        if subdirs_list or files or folder_path == '':
            return render_template('folder.html',
                                folder_name=folder,
                                current_path=folder_path,
                                subdirectories=subdirs_list,
                                files=files)
        else:
            return render_template('error.html')
            
    except Exception as e:
        print(f"Error accessing path {folder_path}: {str(e)}")
        return render_template('error.html')

@app.route('/download/<path:file_path>')
def download_file(file_path):
    try:
        s3_client = get_s3_client()
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
        return jsonify({"error": str(e)}), 404

@app.route("/list_folders", methods=["GET"])
def list_folders():
    s3_client = get_s3_client()
    response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Delimiter='/')
    folders = [prefix['Prefix'] for prefix in response.get('CommonPrefixes', [])]
    return jsonify(folders)

@app.route("/list_files", methods=["POST"])
def list_files():
    folder = request.form.get("folder", "")
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

@app.route('/download-folder/<path:folder_path>')
def download_folder(folder_path):
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

@app.route('/list-folder-files/<path:folder_path>')
def list_folder_files(folder_path):
    try:
        s3_client = get_s3_client()
        response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=folder_path,
            Delimiter='/'
        )
        
        if 'Contents' not in response:
            return jsonify([])
        
        files = []
        for obj in response.get("Contents", []):
            if obj["Key"] != folder_path:
                relative_path = obj["Key"][len(folder_path):]
                if '/' not in relative_path:
                    files.append({
                        'key': obj['Key'],
                        'name': os.path.basename(obj['Key'])
                    })
        
        return jsonify(files)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)
