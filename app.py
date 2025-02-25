from flask import Flask, request, jsonify, send_file, render_template, session
import boto3
import os
import zipfile
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route("/")
def home():
    return render_template("index.html")
@app.route("/save_credentials", methods=["POST"])
def save_credentials():
    session['s3_endpoint'] = request.form.get("s3_endpoint")
    session['s3_access_key'] = request.form.get("s3_access_key")
    session['s3_secret_key'] = request.form.get("s3_secret_key")
    session['bucket_name'] = request.form.get("bucket_name")
    return jsonify({"message": "Credenciais salvas com sucesso!"})

@app.route("/list_folders", methods=["GET"])
def list_folders():
    s3_client = boto3.client(
        's3',
        endpoint_url=session.get('s3_endpoint'),
        aws_access_key_id=session.get('s3_access_key'),
        aws_secret_access_key=session.get('s3_secret_key')
    )
    response = s3_client.list_objects_v2(Bucket=session.get('bucket_name'), Delimiter='/')
    folders = [prefix['Prefix'] for prefix in response.get('CommonPrefixes', [])]
    return jsonify(folders)

@app.route("/list_files", methods=["POST"])
def list_files():
    folder = request.form.get("folder", "")
    s3_client = boto3.client(
        's3',
        endpoint_url=session.get('s3_endpoint'),
        aws_access_key_id=session.get('s3_access_key'),
        aws_secret_access_key=session.get('s3_secret_key')
    )
    response = s3_client.list_objects_v2(Bucket=session.get('bucket_name'), Prefix=folder)
    files = [obj['Key'] for obj in response.get("Contents", []) if obj['Key'] != folder]
    return jsonify(files)

@app.route("/download_file", methods=["GET"])
def download_file():
    file_key = request.args.get("file")
    s3_client = boto3.client(
        's3',
        endpoint_url=session.get('s3_endpoint'),
        aws_access_key_id=session.get('s3_access_key'),
        aws_secret_access_key=session.get('s3_secret_key')
    )
    
    
    response = s3_client.head_object(Bucket=session.get('bucket_name'), Key=file_key)
    file_size = response['ContentLength']
    
    
    file_obj = s3_client.get_object(Bucket=session.get('bucket_name'), Key=file_key)
    
    def generate():
        chunk_size = 8192  # 8KB chunks
        downloaded = 0
        for chunk in file_obj['Body'].iter_chunks(chunk_size):
            downloaded += len(chunk)
            yield chunk
    
    headers = {
        'Content-Disposition': f'attachment; filename={os.path.basename(file_key)}',
        'Content-Length': str(file_size)
    }
    
    return app.response_class(
        generate(),
        mimetype='application/octet-stream',
        headers=headers
    )

@app.route("/download_folder", methods=["GET"])
def download_folder():
    folder = request.args.get("folder")
    s3_client = boto3.client(
        's3',
        endpoint_url=session.get('s3_endpoint'),
        aws_access_key_id=session.get('s3_access_key'),
        aws_secret_access_key=session.get('s3_secret_key')
    )
    response = s3_client.list_objects_v2(Bucket=session.get('bucket_name'), Prefix=folder)
    
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for obj in response.get("Contents", []):
            file_key = obj["Key"]
            file_data = s3_client.get_object(Bucket=session.get('bucket_name'), Key=file_key)["Body"].read()
            zip_file.writestr(file_key[len(folder):], file_data)
    
    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name=f"{folder.strip('/')}.zip")

@app.route("/delete_file", methods=["POST"])
def delete_file():
    file_key = request.form.get("file")
    try:
        s3_client = boto3.client(
            's3',
            endpoint_url=session.get('s3_endpoint'),
            aws_access_key_id=session.get('s3_access_key'),
            aws_secret_access_key=session.get('s3_secret_key')
        )
        
        s3_client.delete_object(
            Bucket=session.get('bucket_name'),
            Key=file_key
        )
        return jsonify({"message": "Arquivo deletado com sucesso!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
