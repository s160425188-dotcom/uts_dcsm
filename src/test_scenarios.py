import os
import sys
import grpc

sys.path.append(os.path.join(os.path.dirname(__file__), 'generated'))
import storage_pb2
import storage_pb2_grpc
from auth import generate_token

SERVER_HOST = os.getenv("SERVER_HOST", "localhost") + ":50051"

def get_channel(cert_prefix="client"):
    with open(f"certs/{cert_prefix}.key", "rb") as f: private_key = f.read()
    with open(f"certs/{cert_prefix}.crt", "rb") as f: cert_chain = f.read()
    with open("certs/ca.crt", "rb") as f: ca_cert = f.read()

    creds = grpc.ssl_channel_credentials(
        root_certificates=ca_cert,
        private_key=private_key,
        certificate_chain=cert_chain
    )

    # Override SSL target name agar gRPC mencocokkan dengan CN sertifikat (/CN=storage-server)
    options = (('grpc.ssl_target_name_override', 'storage-server'),)
    return grpc.secure_channel(SERVER_HOST, creds, options=options)

def run_tests():
    token_admin = generate_token("alice_admin", "ADMIN")
    token_user = generate_token("bob_user", "USER")

    print("\n=======================================================")
    print("--- [TC-RPL-01] Upload & Download File Valid (mTLS + SHA256) ---")
    print("=======================================================")
    channel = get_channel("client")
    stub = storage_pb2_grpc.SecureStorageServiceStub(channel)
    
    upload_res = stub.UploadFile(
        storage_pb2.UploadRequest(filename="doc_public.txt", content=b"Dokumen Publik Komputasi Terdistribusi", label=storage_pb2.PUBLIC),
        metadata=[("authorization", token_user)]
    )
    print(f"[OK] Upload Response: {upload_res.message}")
    print(f"[OK] SHA-256 Checksum: {upload_res.sha256_checksum}")

    download_res = stub.DownloadFile(
        storage_pb2.DownloadRequest(filename="doc_public.txt"),
        metadata=[("authorization", token_user)]
    )
    print(f"[OK] Download Success. SHA-256 Valid: {download_res.sha256_checksum}")

    print("\n=======================================================")
    print("--- [TC-RPL-02] Otorisasi RBAC & Security Labeling ---")
    print("=======================================================")
    # Admin upload file SECRET
    stub.UploadFile(
        storage_pb2.UploadRequest(filename="doc_secret.txt", content=b"Rencana Nilai UTS DCSM", label=storage_pb2.SECRET),
        metadata=[("authorization", token_admin)]
    )
    print("[OK] Admin berhasil upload dokumen SECRET.")

    # Regular USER mencoba download dokumen SECRET
    try:
        stub.DownloadFile(
            storage_pb2.DownloadRequest(filename="doc_secret.txt"),
            metadata=[("authorization", token_user)]
        )
        print("[FAIL] Harusnya ditolak!")
    except grpc.RpcError as e:
        print(f"[SUCCESS - RBAC DENY] Akses ditolak sesuai ekspektasi: {e.details()}")

    print("\n=======================================================")
    print("--- [TC-RPL-03] Koneksi Tanpa Sertifikat Sah (Untrusted Client) ---")
    print("=======================================================")
    try:
        bad_channel = get_channel("bad_client") # Memakai sertifikat yang tidak di-sign Root CA
        bad_stub = storage_pb2_grpc.SecureStorageServiceStub(bad_channel)
        bad_stub.DownloadFile(
            storage_pb2.DownloadRequest(filename="doc_public.txt"),
            metadata=[("authorization", token_user)]
        )
        print("[FAIL] Harusnya handshake mTLS gagal!")
    except grpc.RpcError as e:
        print(f"[SUCCESS - mTLS REJECT] Request ditolak saat SSL/mTLS Handshake: {e.details()}")

    print("\n=======================================================")
    print("--- [TC-RPL-04] Verifikasi Integritas File Tampered ---")
    print("=======================================================")
    # Manipulasi isi file secara langsung di folder storage server (Simulasi Tampering)
    file_disk_path = "./storage_data/doc_public.txt"
    if os.path.exists(file_disk_path):
        with open(file_disk_path, "a") as f:
            f.write("\n[TAMPERED BY ATTACKER]")
        print("[INFO] Berkas 'doc_public.txt' di server telah diubah secara manual.")

    try:
        stub.DownloadFile(
            storage_pb2.DownloadRequest(filename="doc_public.txt"),
            metadata=[("authorization", token_user)]
        )
        print("[FAIL] Server gagal mendeteksi tampering!")
    except grpc.RpcError as e:
        print(f"[SUCCESS - TAMPER DETECTED] Server berhasil mendeteksi mismatch SHA-256: {e.details()}")

if __name__ == '__main__':
    run_tests()
