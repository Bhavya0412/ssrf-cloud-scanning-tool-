# Placeholder for aws.py
# aws.py
import boto3

# Initialize AWS client (credentials can be managed via environment variables or IAM roles)
def connect_s3():
    s3 = boto3.client('s3')
    return s3

def list_buckets():
    s3 = connect_s3()
    return s3.list_buckets()

def upload_file_to_s3(bucket, key, filename):
    s3 = boto3.client('s3')
    s3.upload_file(filename, bucket, key)
