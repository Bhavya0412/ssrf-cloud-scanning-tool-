# Placeholder for gcp.py
# gcp.py
from google.cloud import storage

def list_buckets():
    client = storage.Client()
    return [bucket.name for bucket in client.list_buckets()]

def upload_file_to_gcs(bucket_name, blob_name, filename):
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)
    blob.upload_from_filename(filename)
