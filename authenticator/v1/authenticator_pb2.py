# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: authenticator/v1/authenticator.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n$authenticator/v1/authenticator.proto\x12\x10\x61uthenticator.v1\"\xae\x04\n\x0eS3ErrorDetails\x12\x39\n\x04type\x18\x01 \x01(\x0e\x32%.authenticator.v1.S3ErrorDetails.TypeR\x04type\x12(\n\x10http_status_code\x18\x02 \x01(\x05R\x0ehttpStatusCode\"\xb6\x03\n\x04Type\x12\x14\n\x10TYPE_UNSPECIFIED\x10\x00\x12\x16\n\x12TYPE_ACCESS_DENIED\x10\x01\x12\'\n#TYPE_AUTHORIZATION_HEADER_MALFORMED\x10\x02\x12\x16\n\x12TYPE_EXPIRED_TOKEN\x10\x03\x12\x17\n\x13TYPE_INTERNAL_ERROR\x10\x04\x12\x1e\n\x1aTYPE_INVALID_ACCESS_KEY_ID\x10\x05\x12\x18\n\x14TYPE_INVALID_REQUEST\x10\x06\x12\x19\n\x15TYPE_INVALID_SECURITY\x10\x07\x12\x16\n\x12TYPE_INVALID_TOKEN\x10\x08\x12\x14\n\x10TYPE_INVALID_URI\x10\t\x12\x1b\n\x17TYPE_METHOD_NOT_ALLOWED\x10\n\x12 \n\x1cTYPE_MISSING_SECURITY_HEADER\x10\x0b\x12 \n\x1cTYPE_REQUEST_TIME_TOO_SKEWED\x10\x0c\x12!\n\x1dTYPE_SIGNATURE_DOES_NOT_MATCH\x10\r\x12\x1f\n\x1bTYPE_TOKEN_REFRESH_REQUIRED\x10\x0e\"\x90\x07\n\x17\x41uthenticateRESTRequest\x12)\n\x0estring_to_sign\x18\x01 \x01(\tH\x00R\x0cstringToSign\x88\x01\x01\x12\x36\n\x14\x61uthorization_header\x18\x02 \x01(\tH\x01R\x13\x61uthorizationHeader\x88\x01\x01\x12U\n\x0bhttp_method\x18\x03 \x01(\x0e\x32\x34.authenticator.v1.AuthenticateRESTRequest.HTTPMethodR\nhttpMethod\x12$\n\x0b\x62ucket_name\x18\x04 \x01(\tH\x02R\nbucketName\x88\x01\x01\x12\"\n\nobject_key\x18\x05 \x01(\tH\x03R\tobjectKey\x88\x01\x01\x12i\n\x10query_parameters\x18\x06 \x03(\x0b\x32>.authenticator.v1.AuthenticateRESTRequest.QueryParametersEntryR\x0fqueryParameters\x12^\n\rx_amz_headers\x18\x07 \x03(\x0b\x32:.authenticator.v1.AuthenticateRESTRequest.XAmzHeadersEntryR\x0bxAmzHeaders\x12*\n\x0etransaction_id\x18\x08 \x01(\tH\x04R\rtransactionId\x88\x01\x01\x1a\x42\n\x14QueryParametersEntry\x12\x10\n\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n\x05value\x18\x02 \x01(\tR\x05value:\x02\x38\x01\x1a>\n\x10XAmzHeadersEntry\x12\x10\n\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n\x05value\x18\x02 \x01(\tR\x05value:\x02\x38\x01\"\x97\x01\n\nHTTPMethod\x12\x1b\n\x17HTTP_METHOD_UNSPECIFIED\x10\x00\x12\x13\n\x0fHTTP_METHOD_GET\x10\x01\x12\x14\n\x10HTTP_METHOD_HEAD\x10\x02\x12\x14\n\x10HTTP_METHOD_POST\x10\x03\x12\x13\n\x0fHTTP_METHOD_PUT\x10\x04\x12\x16\n\x12HTTP_METHOD_DELETE\x10\x05\x42\x11\n\x0f_string_to_signB\x17\n\x15_authorization_headerB\x0e\n\x0c_bucket_nameB\r\n\x0b_object_keyB\x11\n\x0f_transaction_id\"w\n\x18\x41uthenticateRESTResponse\x12\x17\n\x07user_id\x18\x01 \x01(\tR\x06userId\x12-\n\x10original_user_id\x18\x02 \x01(\tH\x00R\x0eoriginalUserId\x88\x01\x01\x42\x13\n\x11_original_user_id\"\xcc\x02\n\x1f\x41uthenticatePresignedURLRequest\x12$\n\x0estring_to_sign\x18\x01 \x01(\tR\x0cstringToSign\x12\x10\n\x03url\x18\x02 \x01(\tR\x03url\x12]\n\x0bhttp_method\x18\x03 \x01(\x0e\x32<.authenticator.v1.AuthenticatePresignedURLRequest.HTTPMethodR\nhttpMethod\x12*\n\x0etransaction_id\x18\x04 \x01(\tH\x00R\rtransactionId\x88\x01\x01\"S\n\nHTTPMethod\x12\x1b\n\x17HTTP_METHOD_UNSPECIFIED\x10\x00\x12\x13\n\x0fHTTP_METHOD_GET\x10\x01\x12\x13\n\x0fHTTP_METHOD_PUT\x10\x02\x42\x11\n\x0f_transaction_id\"\x7f\n AuthenticatePresignedURLResponse\x12\x17\n\x07user_id\x18\x01 \x01(\tR\x06userId\x12-\n\x10original_user_id\x18\x02 \x01(\tH\x00R\x0eoriginalUserId\x88\x01\x01\x42\x13\n\x11_original_user_id\"\x88\x01\n\x14GetSigningKeyRequest\x12\x31\n\x14\x61uthorization_header\x18\x01 \x01(\tR\x13\x61uthorizationHeader\x12*\n\x0etransaction_id\x18\x02 \x01(\tH\x00R\rtransactionId\x88\x01\x01\x42\x11\n\x0f_transaction_id\"8\n\x15GetSigningKeyResponse\x12\x1f\n\x0bsigning_key\x18\x01 \x01(\x0cR\nsigningKey2\xe7\x02\n\x14\x41uthenticatorService\x12i\n\x10\x41uthenticateREST\x12).authenticator.v1.AuthenticateRESTRequest\x1a*.authenticator.v1.AuthenticateRESTResponse\x12\x81\x01\n\x18\x41uthenticatePresignedURL\x12\x31.authenticator.v1.AuthenticatePresignedURLRequest\x1a\x32.authenticator.v1.AuthenticatePresignedURLResponse\x12`\n\rGetSigningKey\x12&.authenticator.v1.GetSigningKeyRequest\x1a\'.authenticator.v1.GetSigningKeyResponseB\xce\x01\n\x14\x63om.authenticator.v1B\x12\x41uthenticatorProtoP\x01ZAbits.linode.com/LinodeApi/obj-endpoint/gen/proto/authenticator/v1\xa2\x02\x03\x41XX\xaa\x02\x10\x41uthenticator.V1\xca\x02\x10\x41uthenticator\\V1\xe2\x02\x1c\x41uthenticator\\V1\\GPBMetadata\xea\x02\x11\x41uthenticator::V1b\x06proto3')



_S3ERRORDETAILS = DESCRIPTOR.message_types_by_name['S3ErrorDetails']
_AUTHENTICATERESTREQUEST = DESCRIPTOR.message_types_by_name['AuthenticateRESTRequest']
_AUTHENTICATERESTREQUEST_QUERYPARAMETERSENTRY = _AUTHENTICATERESTREQUEST.nested_types_by_name['QueryParametersEntry']
_AUTHENTICATERESTREQUEST_XAMZHEADERSENTRY = _AUTHENTICATERESTREQUEST.nested_types_by_name['XAmzHeadersEntry']
_AUTHENTICATERESTRESPONSE = DESCRIPTOR.message_types_by_name['AuthenticateRESTResponse']
_AUTHENTICATEPRESIGNEDURLREQUEST = DESCRIPTOR.message_types_by_name['AuthenticatePresignedURLRequest']
_AUTHENTICATEPRESIGNEDURLRESPONSE = DESCRIPTOR.message_types_by_name['AuthenticatePresignedURLResponse']
_GETSIGNINGKEYREQUEST = DESCRIPTOR.message_types_by_name['GetSigningKeyRequest']
_GETSIGNINGKEYRESPONSE = DESCRIPTOR.message_types_by_name['GetSigningKeyResponse']
_S3ERRORDETAILS_TYPE = _S3ERRORDETAILS.enum_types_by_name['Type']
_AUTHENTICATERESTREQUEST_HTTPMETHOD = _AUTHENTICATERESTREQUEST.enum_types_by_name['HTTPMethod']
_AUTHENTICATEPRESIGNEDURLREQUEST_HTTPMETHOD = _AUTHENTICATEPRESIGNEDURLREQUEST.enum_types_by_name['HTTPMethod']
S3ErrorDetails = _reflection.GeneratedProtocolMessageType('S3ErrorDetails', (_message.Message,), {
  'DESCRIPTOR' : _S3ERRORDETAILS,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.S3ErrorDetails)
  })
_sym_db.RegisterMessage(S3ErrorDetails)

AuthenticateRESTRequest = _reflection.GeneratedProtocolMessageType('AuthenticateRESTRequest', (_message.Message,), {

  'QueryParametersEntry' : _reflection.GeneratedProtocolMessageType('QueryParametersEntry', (_message.Message,), {
    'DESCRIPTOR' : _AUTHENTICATERESTREQUEST_QUERYPARAMETERSENTRY,
    '__module__' : 'authenticator.v1.authenticator_pb2'
    # @@protoc_insertion_point(class_scope:authenticator.v1.AuthenticateRESTRequest.QueryParametersEntry)
    })
  ,

  'XAmzHeadersEntry' : _reflection.GeneratedProtocolMessageType('XAmzHeadersEntry', (_message.Message,), {
    'DESCRIPTOR' : _AUTHENTICATERESTREQUEST_XAMZHEADERSENTRY,
    '__module__' : 'authenticator.v1.authenticator_pb2'
    # @@protoc_insertion_point(class_scope:authenticator.v1.AuthenticateRESTRequest.XAmzHeadersEntry)
    })
  ,
  'DESCRIPTOR' : _AUTHENTICATERESTREQUEST,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.AuthenticateRESTRequest)
  })
_sym_db.RegisterMessage(AuthenticateRESTRequest)
_sym_db.RegisterMessage(AuthenticateRESTRequest.QueryParametersEntry)
_sym_db.RegisterMessage(AuthenticateRESTRequest.XAmzHeadersEntry)

AuthenticateRESTResponse = _reflection.GeneratedProtocolMessageType('AuthenticateRESTResponse', (_message.Message,), {
  'DESCRIPTOR' : _AUTHENTICATERESTRESPONSE,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.AuthenticateRESTResponse)
  })
_sym_db.RegisterMessage(AuthenticateRESTResponse)

AuthenticatePresignedURLRequest = _reflection.GeneratedProtocolMessageType('AuthenticatePresignedURLRequest', (_message.Message,), {
  'DESCRIPTOR' : _AUTHENTICATEPRESIGNEDURLREQUEST,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.AuthenticatePresignedURLRequest)
  })
_sym_db.RegisterMessage(AuthenticatePresignedURLRequest)

AuthenticatePresignedURLResponse = _reflection.GeneratedProtocolMessageType('AuthenticatePresignedURLResponse', (_message.Message,), {
  'DESCRIPTOR' : _AUTHENTICATEPRESIGNEDURLRESPONSE,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.AuthenticatePresignedURLResponse)
  })
_sym_db.RegisterMessage(AuthenticatePresignedURLResponse)

GetSigningKeyRequest = _reflection.GeneratedProtocolMessageType('GetSigningKeyRequest', (_message.Message,), {
  'DESCRIPTOR' : _GETSIGNINGKEYREQUEST,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.GetSigningKeyRequest)
  })
_sym_db.RegisterMessage(GetSigningKeyRequest)

GetSigningKeyResponse = _reflection.GeneratedProtocolMessageType('GetSigningKeyResponse', (_message.Message,), {
  'DESCRIPTOR' : _GETSIGNINGKEYRESPONSE,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.GetSigningKeyResponse)
  })
_sym_db.RegisterMessage(GetSigningKeyResponse)

_AUTHENTICATORSERVICE = DESCRIPTOR.services_by_name['AuthenticatorService']
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\024com.authenticator.v1B\022AuthenticatorProtoP\001ZAbits.linode.com/LinodeApi/obj-endpoint/gen/proto/authenticator/v1\242\002\003AXX\252\002\020Authenticator.V1\312\002\020Authenticator\\V1\342\002\034Authenticator\\V1\\GPBMetadata\352\002\021Authenticator::V1'
  _AUTHENTICATERESTREQUEST_QUERYPARAMETERSENTRY._options = None
  _AUTHENTICATERESTREQUEST_QUERYPARAMETERSENTRY._serialized_options = b'8\001'
  _AUTHENTICATERESTREQUEST_XAMZHEADERSENTRY._options = None
  _AUTHENTICATERESTREQUEST_XAMZHEADERSENTRY._serialized_options = b'8\001'
  _S3ERRORDETAILS._serialized_start=59
  _S3ERRORDETAILS._serialized_end=617
  _S3ERRORDETAILS_TYPE._serialized_start=179
  _S3ERRORDETAILS_TYPE._serialized_end=617
  _AUTHENTICATERESTREQUEST._serialized_start=620
  _AUTHENTICATERESTREQUEST._serialized_end=1532
  _AUTHENTICATERESTREQUEST_QUERYPARAMETERSENTRY._serialized_start=1154
  _AUTHENTICATERESTREQUEST_QUERYPARAMETERSENTRY._serialized_end=1220
  _AUTHENTICATERESTREQUEST_XAMZHEADERSENTRY._serialized_start=1222
  _AUTHENTICATERESTREQUEST_XAMZHEADERSENTRY._serialized_end=1284
  _AUTHENTICATERESTREQUEST_HTTPMETHOD._serialized_start=1287
  _AUTHENTICATERESTREQUEST_HTTPMETHOD._serialized_end=1438
  _AUTHENTICATERESTRESPONSE._serialized_start=1534
  _AUTHENTICATERESTRESPONSE._serialized_end=1653
  _AUTHENTICATEPRESIGNEDURLREQUEST._serialized_start=1656
  _AUTHENTICATEPRESIGNEDURLREQUEST._serialized_end=1988
  _AUTHENTICATEPRESIGNEDURLREQUEST_HTTPMETHOD._serialized_start=1886
  _AUTHENTICATEPRESIGNEDURLREQUEST_HTTPMETHOD._serialized_end=1969
  _AUTHENTICATEPRESIGNEDURLRESPONSE._serialized_start=1990
  _AUTHENTICATEPRESIGNEDURLRESPONSE._serialized_end=2117
  _GETSIGNINGKEYREQUEST._serialized_start=2120
  _GETSIGNINGKEYREQUEST._serialized_end=2256
  _GETSIGNINGKEYRESPONSE._serialized_start=2258
  _GETSIGNINGKEYRESPONSE._serialized_end=2314
  _AUTHENTICATORSERVICE._serialized_start=2317
  _AUTHENTICATORSERVICE._serialized_end=2676
# @@protoc_insertion_point(module_scope)
