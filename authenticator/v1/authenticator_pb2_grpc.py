# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

from authenticator.v1 import authenticator_pb2 as authenticator_dot_v1_dot_authenticator__pb2


class AuthenticatorServiceStub(object):
    """AuthenticatorService provides RPCs for authenticating S3 requests.
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.AuthenticateREST = channel.unary_unary(
                '/authenticator.v1.AuthenticatorService/AuthenticateREST',
                request_serializer=authenticator_dot_v1_dot_authenticator__pb2.AuthenticateRESTRequest.SerializeToString,
                response_deserializer=authenticator_dot_v1_dot_authenticator__pb2.AuthenticateRESTResponse.FromString,
                )
        self.AuthenticatePresignedURL = channel.unary_unary(
                '/authenticator.v1.AuthenticatorService/AuthenticatePresignedURL',
                request_serializer=authenticator_dot_v1_dot_authenticator__pb2.AuthenticatePresignedURLRequest.SerializeToString,
                response_deserializer=authenticator_dot_v1_dot_authenticator__pb2.AuthenticatePresignedURLResponse.FromString,
                )
        self.GetSigningKey = channel.unary_unary(
                '/authenticator.v1.AuthenticatorService/GetSigningKey',
                request_serializer=authenticator_dot_v1_dot_authenticator__pb2.GetSigningKeyRequest.SerializeToString,
                response_deserializer=authenticator_dot_v1_dot_authenticator__pb2.GetSigningKeyResponse.FromString,
                )
        self.AssumeRole = channel.unary_unary(
                '/authenticator.v1.AuthenticatorService/AssumeRole',
                request_serializer=authenticator_dot_v1_dot_authenticator__pb2.AssumeRoleRequest.SerializeToString,
                response_deserializer=authenticator_dot_v1_dot_authenticator__pb2.AssumeRoleResponse.FromString,
                )


class AuthenticatorServiceServicer(object):
    """AuthenticatorService provides RPCs for authenticating S3 requests.
    """

    def AuthenticateREST(self, request, context):
        """AuthenticateREST authenticated requests made via the REST API.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def AuthenticatePresignedURL(self, request, context):
        """AuthenticatePresignedURL authenticated requests made via Presigned URLs.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetSigningKey(self, request, context):
        """Request a signing key for the given request.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def AssumeRole(self, request, context):
        """AssumeRole generates temp creds for trusted use.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_AuthenticatorServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'AuthenticateREST': grpc.unary_unary_rpc_method_handler(
                    servicer.AuthenticateREST,
                    request_deserializer=authenticator_dot_v1_dot_authenticator__pb2.AuthenticateRESTRequest.FromString,
                    response_serializer=authenticator_dot_v1_dot_authenticator__pb2.AuthenticateRESTResponse.SerializeToString,
            ),
            'AuthenticatePresignedURL': grpc.unary_unary_rpc_method_handler(
                    servicer.AuthenticatePresignedURL,
                    request_deserializer=authenticator_dot_v1_dot_authenticator__pb2.AuthenticatePresignedURLRequest.FromString,
                    response_serializer=authenticator_dot_v1_dot_authenticator__pb2.AuthenticatePresignedURLResponse.SerializeToString,
            ),
            'GetSigningKey': grpc.unary_unary_rpc_method_handler(
                    servicer.GetSigningKey,
                    request_deserializer=authenticator_dot_v1_dot_authenticator__pb2.GetSigningKeyRequest.FromString,
                    response_serializer=authenticator_dot_v1_dot_authenticator__pb2.GetSigningKeyResponse.SerializeToString,
            ),
            'AssumeRole': grpc.unary_unary_rpc_method_handler(
                    servicer.AssumeRole,
                    request_deserializer=authenticator_dot_v1_dot_authenticator__pb2.AssumeRoleRequest.FromString,
                    response_serializer=authenticator_dot_v1_dot_authenticator__pb2.AssumeRoleResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'authenticator.v1.AuthenticatorService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class AuthenticatorService(object):
    """AuthenticatorService provides RPCs for authenticating S3 requests.
    """

    @staticmethod
    def AuthenticateREST(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/authenticator.v1.AuthenticatorService/AuthenticateREST',
            authenticator_dot_v1_dot_authenticator__pb2.AuthenticateRESTRequest.SerializeToString,
            authenticator_dot_v1_dot_authenticator__pb2.AuthenticateRESTResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def AuthenticatePresignedURL(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/authenticator.v1.AuthenticatorService/AuthenticatePresignedURL',
            authenticator_dot_v1_dot_authenticator__pb2.AuthenticatePresignedURLRequest.SerializeToString,
            authenticator_dot_v1_dot_authenticator__pb2.AuthenticatePresignedURLResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def GetSigningKey(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/authenticator.v1.AuthenticatorService/GetSigningKey',
            authenticator_dot_v1_dot_authenticator__pb2.GetSigningKeyRequest.SerializeToString,
            authenticator_dot_v1_dot_authenticator__pb2.GetSigningKeyResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def AssumeRole(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/authenticator.v1.AuthenticatorService/AssumeRole',
            authenticator_dot_v1_dot_authenticator__pb2.AssumeRoleRequest.SerializeToString,
            authenticator_dot_v1_dot_authenticator__pb2.AssumeRoleResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
