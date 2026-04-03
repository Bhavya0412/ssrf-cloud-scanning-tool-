import sys
from aws import upload_file_to_s3
from gcp import upload_file_to_gcs
from azure import upload_file_to_azure

def main():
    print("Universal Cloud Replicator")
    # Example config – replace with your paths, names, and keys
    filename = "test.txt"  # Local file to upload

    # AWS S3
    aws_bucket = "your-s3-bucket-name"
    aws_key = "test.txt"
    upload_file_to_s3(aws_bucket, aws_key, filename)

    # Google Cloud Storage
    gcp_bucket = "your-gcs-bucket-name"
    gcp_blob = "test.txt"
    upload_file_to_gcs(gcp_bucket, gcp_blob, filename)

    # Azure Blob Storage
    azure_container = "your-azure-container"
    azure_blob = "test.txt"
    azure_connection_string = "your-azure-connection-string"
    upload_file_to_azure(azure_container, azure_blob, filename, azure_connection_string)

if __name__ == "__main__":
    main()
