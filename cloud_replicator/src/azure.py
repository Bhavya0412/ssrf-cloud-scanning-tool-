from azure.storage.blob import BlobServiceClient

def upload_file_to_azure(container_name, blob_name, filename, connection_string):
    """
    Uploads a file to Azure Blob Storage.
    """
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
    with open(filename, "rb") as data:
        blob_client.upload_blob(data, overwrite=True)
    print(f"File '{filename}' uploaded to Azure container '{container_name}' as blob '{blob_name}'")
