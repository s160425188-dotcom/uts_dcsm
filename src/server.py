import os
import sys
import hashlib
import grpc
from concurrent import futures

sys.path.append(os.path.join(os.path.dirname(__file__), 'generated'))
import storage_pb2
import storage_pb2_grpc
from auth import verify_token
from logger import audit_logger
from interceptors import SecurityInterceptor

STORAGE_DIR = "./storage_data"
os.makedirs(STORAGE_DIR, exist_ok=True)
FILE_METADATA = {}

def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class SecureStorageServicer(storage_pb2_grpc.SecureStorageServiceServicer):

    def _get_user_info(self, context):
        metadata = dict(context.invocation_metadata())
        token = metadata.get("authorization", "")
        payload = verify_token(token)
        return payload.get("sub", "unknown"), payload.get("role", "GUEST")

    def UploadFile(self, request, context):
        user, role = self._get_user_info(context)

        if request.label == storage_pb2.SECRET and role != "ADMIN":
            audit_logger.log(user, role, "UPLOAD", request.filename, "DENY", "Role tidak berhak mengunggah berkas SECRET")
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "Akses Ditolak: Hanya ADMIN yang boleh mengunggah berkas SECRET.")

        checksum = compute_sha256(request.content)
        file_path = os.path.join(STORAGE_DIR, request.filename)

        with open(file_path, "wb") as f:
            f.write(request.content)

        FILE_METADATA[request.filename] = {
            "label": request.label,
            "expected_hash": checksum
        }

        audit_logger.log(user, role, "UPLOAD", request.filename, "ALLOW", f"SHA256: {checksum}")
        return storage_pb2.UploadResponse(
            filename=request.filename,
            sha256_checksum=checksum,
            message="File berhasil disimpan."
        )

    def DownloadFile(self, request, context):
        user, role = self._get_user_info(context)
        file_path = os.path.join(STORAGE_DIR, request.filename)

        if not os.path.exists(file_path):
            audit_logger.log(user, role, "DOWNLOAD", request.filename, "DENY", "Berkas tidak ditemukan")
            context.abort(grpc.StatusCode.NOT_FOUND, "File tidak ditemukan.")

        meta = FILE_METADATA.get(request.filename, {"label": storage_pb2.PUBLIC, "expected_hash": ""})

        if meta["label"] == storage_pb2.SECRET and role != "ADMIN":
            audit_logger.log(user, role, "DOWNLOAD", request.filename, "DENY", "User tidak berhak mengunduh berkas SECRET")
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "Akses Ditolak: Dokumen berlabel SECRET.")

        with open(file_path, "rb") as f:
            content = f.read()

        current_checksum = compute_sha256(content)

        if meta["expected_hash"] and current_checksum != meta["expected_hash"]:
            audit_logger.log(user, role, "DOWNLOAD", request.filename, "DENY", "File Integrity Compromised (Tampered!)")
            context.abort(grpc.StatusCode.DATA_LOSS, "Peringatan Keamanan: File di server telah diubah secara ilegal (SHA-256 Mismatch)!")

        audit_logger.log(user, role, "DOWNLOAD", request.filename, "ALLOW", f"SHA256 Valid: {current_checksum}")
        return storage_pb2.DownloadResponse(
            filename=request.filename,
            content=content,
            sha256_checksum=current_checksum,
            label=meta["label"]
        )

def serve():
    with open("certs/server.key", "rb") as f: private_key = f.read()
    with open("certs/server.crt", "rb") as f: cert_chain = f.read()
    with open("certs/ca.crt", "rb") as f: ca_cert = f.read()

    credentials = grpc.ssl_server_credentials(
        [(private_key, cert_chain)],
        root_certificates=ca_cert,
        require_client_auth=True
    )

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10), interceptors=[SecurityInterceptor()])
    storage_pb2_grpc.add_SecureStorageServiceServicer_to_server(SecureStorageServicer(), server)
    server.add_secure_port('[::]:50051', credentials)
    print("🔒 Secure Storage Server running on port 50051 (mTLS Enabled)...")
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()
