import grpc
from auth import verify_token
from logger import audit_logger

class SecurityInterceptor(grpc.ServerInterceptor):
    def intercept_service(self, continuation, handler_call_details):
        metadata = dict(handler_call_details.invocation_metadata)
        token = metadata.get("authorization")
        method = handler_call_details.method

        if not token:
            audit_logger.log("anonymous", "UNKNOWN", method, "N/A", "DENY", "Token autentikasi tidak ditemukan")
            def deny_unauthenticated(request, context):
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "Akses ditolak: Token tidak ditemukan.")
            return grpc.unary_unary_rpc_method_handler(deny_unauthenticated)

        payload = verify_token(token)
        if not payload:
            audit_logger.log("invalid_user", "UNKNOWN", method, "N/A", "DENY", "Token JWT tidak valid/expired")
            def deny_invalid_token(request, context):
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "Akses ditolak: Token invalid.")
            return grpc.unary_unary_rpc_method_handler(deny_invalid_token)

        return continuation(handler_call_details)
