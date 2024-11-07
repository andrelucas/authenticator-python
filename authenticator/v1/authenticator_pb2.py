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


from google.protobuf import timestamp_pb2 as google_dot_protobuf_dot_timestamp__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n$authenticator/v1/authenticator.proto\x12\x10\x61uthenticator.v1\x1a\x1fgoogle/protobuf/timestamp.proto\"\x97\x06\n\x0eS3ErrorDetails\x12\x39\n\x04type\x18\x01 \x01(\x0e\x32%.authenticator.v1.S3ErrorDetails.TypeR\x04type\x12(\n\x10http_status_code\x18\x02 \x01(\x05R\x0ehttpStatusCode\x12\x18\n\x07message\x18\x03 \x01(\tR\x07message\x12\x1d\n\nrequest_id\x18\x04 \x01(\tR\trequestId\x12\x17\n\x07host_id\x18\x05 \x01(\tR\x06hostId\x12\x1f\n\x08resource\x18\x06 \x01(\tH\x00R\x08resource\x88\x01\x01\"\x9f\x04\n\x04Type\x12\x14\n\x10TYPE_UNSPECIFIED\x10\x00\x12\x16\n\x12TYPE_ACCESS_DENIED\x10\x01\x12\'\n#TYPE_AUTHORIZATION_HEADER_MALFORMED\x10\x02\x12\x16\n\x12TYPE_EXPIRED_TOKEN\x10\x03\x12\x17\n\x13TYPE_INTERNAL_ERROR\x10\x04\x12\x1e\n\x1aTYPE_INVALID_ACCESS_KEY_ID\x10\x05\x12\x18\n\x14TYPE_INVALID_REQUEST\x10\x06\x12\x19\n\x15TYPE_INVALID_SECURITY\x10\x07\x12\x16\n\x12TYPE_INVALID_TOKEN\x10\x08\x12\x14\n\x10TYPE_INVALID_URI\x10\t\x12\x1b\n\x17TYPE_METHOD_NOT_ALLOWED\x10\n\x12 \n\x1cTYPE_MISSING_SECURITY_HEADER\x10\x0b\x12 \n\x1cTYPE_REQUEST_TIME_TOO_SKEWED\x10\x0c\x12!\n\x1dTYPE_SIGNATURE_DOES_NOT_MATCH\x10\r\x12\x1f\n\x1bTYPE_TOKEN_REFRESH_REQUIRED\x10\x0e\x12\x17\n\x13TYPE_NO_SUCH_BUCKET\x10\x0f\x12\x19\n\x15TYPE_INVALID_ARGUMENT\x10\x10\x12\x18\n\x14TYPE_NOT_IMPLEMENTED\x10\x11\x12\x19\n\x15TYPE_ACCOUT_SUSPENDED\x10\x12\x42\x0b\n\t_resource\"\xe6\t\n\x17\x41uthenticateRESTRequest\x12)\n\x0estring_to_sign\x18\x01 \x01(\tH\x00R\x0cstringToSign\x88\x01\x01\x12\x36\n\x14\x61uthorization_header\x18\x02 \x01(\tH\x01R\x13\x61uthorizationHeader\x88\x01\x01\x12U\n\x0bhttp_method\x18\x03 \x01(\x0e\x32\x34.authenticator.v1.AuthenticateRESTRequest.HTTPMethodR\nhttpMethod\x12$\n\x0b\x62ucket_name\x18\x04 \x01(\tH\x02R\nbucketName\x88\x01\x01\x12\"\n\nobject_key\x18\x05 \x01(\tH\x03R\tobjectKey\x88\x01\x01\x12i\n\x10query_parameters\x18\x06 \x03(\x0b\x32>.authenticator.v1.AuthenticateRESTRequest.QueryParametersEntryR\x0fqueryParameters\x12^\n\rx_amz_headers\x18\x07 \x03(\x0b\x32:.authenticator.v1.AuthenticateRESTRequest.XAmzHeadersEntryR\x0bxAmzHeaders\x12*\n\x0etransaction_id\x18\x08 \x01(\tH\x04R\rtransactionId\x88\x01\x01\x12g\n\x10x_akamai_headers\x18\t \x03(\x0b\x32=.authenticator.v1.AuthenticateRESTRequest.XAkamaiHeadersEntryR\x0exAkamaiHeaders\x12?\n\x19skip_timestamp_validation\x18\n \x01(\x08H\x05R\x17skipTimestampValidation\x88\x01\x01\x12\x32\n\x12skip_authorization\x18\x0b \x01(\x08H\x06R\x11skipAuthorization\x88\x01\x01\x1a\x42\n\x14QueryParametersEntry\x12\x10\n\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n\x05value\x18\x02 \x01(\tR\x05value:\x02\x38\x01\x1a>\n\x10XAmzHeadersEntry\x12\x10\n\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n\x05value\x18\x02 \x01(\tR\x05value:\x02\x38\x01\x1a\x41\n\x13XAkamaiHeadersEntry\x12\x10\n\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n\x05value\x18\x02 \x01(\tR\x05value:\x02\x38\x01\"\x97\x01\n\nHTTPMethod\x12\x1b\n\x17HTTP_METHOD_UNSPECIFIED\x10\x00\x12\x13\n\x0fHTTP_METHOD_GET\x10\x01\x12\x14\n\x10HTTP_METHOD_HEAD\x10\x02\x12\x14\n\x10HTTP_METHOD_POST\x10\x03\x12\x13\n\x0fHTTP_METHOD_PUT\x10\x04\x12\x16\n\x12HTTP_METHOD_DELETE\x10\x05\x42\x11\n\x0f_string_to_signB\x17\n\x15_authorization_headerB\x0e\n\x0c_bucket_nameB\r\n\x0b_object_keyB\x11\n\x0f_transaction_idB\x1c\n\x1a_skip_timestamp_validationB\x15\n\x13_skip_authorization\"\xfc\x01\n\x18\x41uthenticateRESTResponse\x12*\n\x11\x63\x61nonical_user_id\x18\x01 \x01(\tR\x0f\x63\x61nonicalUserId\x12\x19\n\x08user_arn\x18\x03 \x01(\tR\x07userArn\x12/\n\x11\x61ssuming_user_arn\x18\x04 \x01(\tH\x00R\x0f\x61ssumingUserArn\x88\x01\x01\x12\x1f\n\x0b\x61\x63\x63ount_arn\x18\x05 \x01(\tR\naccountArn\x12\x1e\n\x08role_arn\x18\x06 \x01(\tH\x01R\x07roleArn\x88\x01\x01\x42\x14\n\x12_assuming_user_arnB\x0b\n\t_role_arnJ\x04\x08\x02\x10\x03\"\xd2\x06\n\x1f\x41uthenticatePresignedURLRequest\x12$\n\x0estring_to_sign\x18\x01 \x01(\tR\x0cstringToSign\x12\x10\n\x03url\x18\x02 \x01(\tR\x03url\x12]\n\x0bhttp_method\x18\x03 \x01(\x0e\x32<.authenticator.v1.AuthenticatePresignedURLRequest.HTTPMethodR\nhttpMethod\x12*\n\x0etransaction_id\x18\x04 \x01(\tH\x00R\rtransactionId\x88\x01\x01\x12\x66\n\rx_amz_headers\x18\x05 \x03(\x0b\x32\x42.authenticator.v1.AuthenticatePresignedURLRequest.XAmzHeadersEntryR\x0bxAmzHeaders\x12o\n\x10x_akamai_headers\x18\x06 \x03(\x0b\x32\x45.authenticator.v1.AuthenticatePresignedURLRequest.XAkamaiHeadersEntryR\x0exAkamaiHeaders\x12?\n\x19skip_timestamp_validation\x18\x07 \x01(\x08H\x01R\x17skipTimestampValidation\x88\x01\x01\x12\x32\n\x12skip_authorization\x18\x08 \x01(\x08H\x02R\x11skipAuthorization\x88\x01\x01\x1a>\n\x10XAmzHeadersEntry\x12\x10\n\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n\x05value\x18\x02 \x01(\tR\x05value:\x02\x38\x01\x1a\x41\n\x13XAkamaiHeadersEntry\x12\x10\n\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n\x05value\x18\x02 \x01(\tR\x05value:\x02\x38\x01\"S\n\nHTTPMethod\x12\x1b\n\x17HTTP_METHOD_UNSPECIFIED\x10\x00\x12\x13\n\x0fHTTP_METHOD_GET\x10\x01\x12\x13\n\x0fHTTP_METHOD_PUT\x10\x02\x42\x11\n\x0f_transaction_idB\x1c\n\x1a_skip_timestamp_validationB\x15\n\x13_skip_authorization\"\x84\x02\n AuthenticatePresignedURLResponse\x12*\n\x11\x63\x61nonical_user_id\x18\x01 \x01(\tR\x0f\x63\x61nonicalUserId\x12\x19\n\x08user_arn\x18\x03 \x01(\tR\x07userArn\x12/\n\x11\x61ssuming_user_arn\x18\x04 \x01(\tH\x00R\x0f\x61ssumingUserArn\x88\x01\x01\x12\x1f\n\x0b\x61\x63\x63ount_arn\x18\x05 \x01(\tR\naccountArn\x12\x1e\n\x08role_arn\x18\x06 \x01(\tH\x01R\x07roleArn\x88\x01\x01\x42\x14\n\x12_assuming_user_arnB\x0b\n\t_role_arnJ\x04\x08\x02\x10\x03\"\x88\x01\n\x14GetSigningKeyRequest\x12\x31\n\x14\x61uthorization_header\x18\x01 \x01(\tR\x13\x61uthorizationHeader\x12*\n\x0etransaction_id\x18\x02 \x01(\tH\x00R\rtransactionId\x88\x01\x01\x42\x11\n\x0f_transaction_id\"8\n\x15GetSigningKeyResponse\x12\x1f\n\x0bsigning_key\x18\x01 \x01(\x0cR\nsigningKey\"\xb5\x02\n\x11\x41ssumeRoleRequest\x12\x19\n\x08role_arn\x18\x01 \x01(\tR\x07roleArn\x12*\n\x11role_session_name\x18\x02 \x01(\tR\x0froleSessionName\x12\x19\n\x08user_arn\x18\x03 \x01(\tR\x07userArn\x12(\n\rinline_policy\x18\x04 \x01(\tH\x00R\x0cinlinePolicy\x88\x01\x01\x12*\n\x0etransaction_id\x18\x05 \x01(\tH\x01R\rtransactionId\x88\x01\x01\x12.\n\x10\x64uration_seconds\x18\x06 \x01(\rH\x02R\x0f\x64urationSeconds\x88\x01\x01\x42\x10\n\x0e_inline_policyB\x11\n\x0f_transaction_idB\x13\n\x11_duration_seconds\"\x85\x02\n\x12\x41ssumeRoleResponse\x12S\n\x13\x61ssume_role_results\x18\x01 \x01(\x0b\x32#.authenticator.v1.AssumeRoleResultsR\x11\x61ssumeRoleResults\x12?\n\x0b\x63redentials\x18\x02 \x01(\x0b\x32\x1d.authenticator.v1.CredentialsR\x0b\x63redentials\x12Y\n\x11response_metadata\x18\x03 \x01(\x0b\x32,.authenticator.v1.AssumeRoleResponseMetadataR\x10responseMetadata\"\xbe\x01\n\x0b\x43redentials\x12\"\n\raccess_key_id\x18\x01 \x01(\tR\x0b\x61\x63\x63\x65ssKeyId\x12*\n\x11secret_access_key\x18\x02 \x01(\tR\x0fsecretAccessKey\x12#\n\rsession_token\x18\x03 \x01(\tR\x0csessionToken\x12:\n\nexpiration\x18\x04 \x01(\x0b\x32\x1a.google.protobuf.TimestampR\nexpiration\";\n\x1a\x41ssumeRoleResponseMetadata\x12\x1d\n\nrequest_id\x18\x01 \x01(\tR\trequestId\"e\n\x11\x41ssumeRoleResults\x12&\n\x0f\x61ssumed_role_id\x18\x01 \x01(\tR\rassumedRoleId\x12(\n\x10\x61ssumed_role_arn\x18\x02 \x01(\tR\x0e\x61ssumedRoleArn2\xc0\x03\n\x14\x41uthenticatorService\x12i\n\x10\x41uthenticateREST\x12).authenticator.v1.AuthenticateRESTRequest\x1a*.authenticator.v1.AuthenticateRESTResponse\x12\x81\x01\n\x18\x41uthenticatePresignedURL\x12\x31.authenticator.v1.AuthenticatePresignedURLRequest\x1a\x32.authenticator.v1.AuthenticatePresignedURLResponse\x12`\n\rGetSigningKey\x12&.authenticator.v1.GetSigningKeyRequest\x1a\'.authenticator.v1.GetSigningKeyResponse\x12W\n\nAssumeRole\x12#.authenticator.v1.AssumeRoleRequest\x1a$.authenticator.v1.AssumeRoleResponseB\xce\x01\n\x14\x63om.authenticator.v1B\x12\x41uthenticatorProtoP\x01ZAbits.linode.com/LinodeApi/obj-endpoint/gen/proto/authenticator/v1\xa2\x02\x03\x41XX\xaa\x02\x10\x41uthenticator.V1\xca\x02\x10\x41uthenticator\\V1\xe2\x02\x1c\x41uthenticator\\V1\\GPBMetadata\xea\x02\x11\x41uthenticator::V1b\x06proto3')



_S3ERRORDETAILS = DESCRIPTOR.message_types_by_name['S3ErrorDetails']
_AUTHENTICATERESTREQUEST = DESCRIPTOR.message_types_by_name['AuthenticateRESTRequest']
_AUTHENTICATERESTREQUEST_QUERYPARAMETERSENTRY = _AUTHENTICATERESTREQUEST.nested_types_by_name['QueryParametersEntry']
_AUTHENTICATERESTREQUEST_XAMZHEADERSENTRY = _AUTHENTICATERESTREQUEST.nested_types_by_name['XAmzHeadersEntry']
_AUTHENTICATERESTREQUEST_XAKAMAIHEADERSENTRY = _AUTHENTICATERESTREQUEST.nested_types_by_name['XAkamaiHeadersEntry']
_AUTHENTICATERESTRESPONSE = DESCRIPTOR.message_types_by_name['AuthenticateRESTResponse']
_AUTHENTICATEPRESIGNEDURLREQUEST = DESCRIPTOR.message_types_by_name['AuthenticatePresignedURLRequest']
_AUTHENTICATEPRESIGNEDURLREQUEST_XAMZHEADERSENTRY = _AUTHENTICATEPRESIGNEDURLREQUEST.nested_types_by_name['XAmzHeadersEntry']
_AUTHENTICATEPRESIGNEDURLREQUEST_XAKAMAIHEADERSENTRY = _AUTHENTICATEPRESIGNEDURLREQUEST.nested_types_by_name['XAkamaiHeadersEntry']
_AUTHENTICATEPRESIGNEDURLRESPONSE = DESCRIPTOR.message_types_by_name['AuthenticatePresignedURLResponse']
_GETSIGNINGKEYREQUEST = DESCRIPTOR.message_types_by_name['GetSigningKeyRequest']
_GETSIGNINGKEYRESPONSE = DESCRIPTOR.message_types_by_name['GetSigningKeyResponse']
_ASSUMEROLEREQUEST = DESCRIPTOR.message_types_by_name['AssumeRoleRequest']
_ASSUMEROLERESPONSE = DESCRIPTOR.message_types_by_name['AssumeRoleResponse']
_CREDENTIALS = DESCRIPTOR.message_types_by_name['Credentials']
_ASSUMEROLERESPONSEMETADATA = DESCRIPTOR.message_types_by_name['AssumeRoleResponseMetadata']
_ASSUMEROLERESULTS = DESCRIPTOR.message_types_by_name['AssumeRoleResults']
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

  'XAkamaiHeadersEntry' : _reflection.GeneratedProtocolMessageType('XAkamaiHeadersEntry', (_message.Message,), {
    'DESCRIPTOR' : _AUTHENTICATERESTREQUEST_XAKAMAIHEADERSENTRY,
    '__module__' : 'authenticator.v1.authenticator_pb2'
    # @@protoc_insertion_point(class_scope:authenticator.v1.AuthenticateRESTRequest.XAkamaiHeadersEntry)
    })
  ,
  'DESCRIPTOR' : _AUTHENTICATERESTREQUEST,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.AuthenticateRESTRequest)
  })
_sym_db.RegisterMessage(AuthenticateRESTRequest)
_sym_db.RegisterMessage(AuthenticateRESTRequest.QueryParametersEntry)
_sym_db.RegisterMessage(AuthenticateRESTRequest.XAmzHeadersEntry)
_sym_db.RegisterMessage(AuthenticateRESTRequest.XAkamaiHeadersEntry)

AuthenticateRESTResponse = _reflection.GeneratedProtocolMessageType('AuthenticateRESTResponse', (_message.Message,), {
  'DESCRIPTOR' : _AUTHENTICATERESTRESPONSE,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.AuthenticateRESTResponse)
  })
_sym_db.RegisterMessage(AuthenticateRESTResponse)

AuthenticatePresignedURLRequest = _reflection.GeneratedProtocolMessageType('AuthenticatePresignedURLRequest', (_message.Message,), {

  'XAmzHeadersEntry' : _reflection.GeneratedProtocolMessageType('XAmzHeadersEntry', (_message.Message,), {
    'DESCRIPTOR' : _AUTHENTICATEPRESIGNEDURLREQUEST_XAMZHEADERSENTRY,
    '__module__' : 'authenticator.v1.authenticator_pb2'
    # @@protoc_insertion_point(class_scope:authenticator.v1.AuthenticatePresignedURLRequest.XAmzHeadersEntry)
    })
  ,

  'XAkamaiHeadersEntry' : _reflection.GeneratedProtocolMessageType('XAkamaiHeadersEntry', (_message.Message,), {
    'DESCRIPTOR' : _AUTHENTICATEPRESIGNEDURLREQUEST_XAKAMAIHEADERSENTRY,
    '__module__' : 'authenticator.v1.authenticator_pb2'
    # @@protoc_insertion_point(class_scope:authenticator.v1.AuthenticatePresignedURLRequest.XAkamaiHeadersEntry)
    })
  ,
  'DESCRIPTOR' : _AUTHENTICATEPRESIGNEDURLREQUEST,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.AuthenticatePresignedURLRequest)
  })
_sym_db.RegisterMessage(AuthenticatePresignedURLRequest)
_sym_db.RegisterMessage(AuthenticatePresignedURLRequest.XAmzHeadersEntry)
_sym_db.RegisterMessage(AuthenticatePresignedURLRequest.XAkamaiHeadersEntry)

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

AssumeRoleRequest = _reflection.GeneratedProtocolMessageType('AssumeRoleRequest', (_message.Message,), {
  'DESCRIPTOR' : _ASSUMEROLEREQUEST,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.AssumeRoleRequest)
  })
_sym_db.RegisterMessage(AssumeRoleRequest)

AssumeRoleResponse = _reflection.GeneratedProtocolMessageType('AssumeRoleResponse', (_message.Message,), {
  'DESCRIPTOR' : _ASSUMEROLERESPONSE,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.AssumeRoleResponse)
  })
_sym_db.RegisterMessage(AssumeRoleResponse)

Credentials = _reflection.GeneratedProtocolMessageType('Credentials', (_message.Message,), {
  'DESCRIPTOR' : _CREDENTIALS,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.Credentials)
  })
_sym_db.RegisterMessage(Credentials)

AssumeRoleResponseMetadata = _reflection.GeneratedProtocolMessageType('AssumeRoleResponseMetadata', (_message.Message,), {
  'DESCRIPTOR' : _ASSUMEROLERESPONSEMETADATA,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.AssumeRoleResponseMetadata)
  })
_sym_db.RegisterMessage(AssumeRoleResponseMetadata)

AssumeRoleResults = _reflection.GeneratedProtocolMessageType('AssumeRoleResults', (_message.Message,), {
  'DESCRIPTOR' : _ASSUMEROLERESULTS,
  '__module__' : 'authenticator.v1.authenticator_pb2'
  # @@protoc_insertion_point(class_scope:authenticator.v1.AssumeRoleResults)
  })
_sym_db.RegisterMessage(AssumeRoleResults)

_AUTHENTICATORSERVICE = DESCRIPTOR.services_by_name['AuthenticatorService']
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\024com.authenticator.v1B\022AuthenticatorProtoP\001ZAbits.linode.com/LinodeApi/obj-endpoint/gen/proto/authenticator/v1\242\002\003AXX\252\002\020Authenticator.V1\312\002\020Authenticator\\V1\342\002\034Authenticator\\V1\\GPBMetadata\352\002\021Authenticator::V1'
  _AUTHENTICATERESTREQUEST_QUERYPARAMETERSENTRY._options = None
  _AUTHENTICATERESTREQUEST_QUERYPARAMETERSENTRY._serialized_options = b'8\001'
  _AUTHENTICATERESTREQUEST_XAMZHEADERSENTRY._options = None
  _AUTHENTICATERESTREQUEST_XAMZHEADERSENTRY._serialized_options = b'8\001'
  _AUTHENTICATERESTREQUEST_XAKAMAIHEADERSENTRY._options = None
  _AUTHENTICATERESTREQUEST_XAKAMAIHEADERSENTRY._serialized_options = b'8\001'
  _AUTHENTICATEPRESIGNEDURLREQUEST_XAMZHEADERSENTRY._options = None
  _AUTHENTICATEPRESIGNEDURLREQUEST_XAMZHEADERSENTRY._serialized_options = b'8\001'
  _AUTHENTICATEPRESIGNEDURLREQUEST_XAKAMAIHEADERSENTRY._options = None
  _AUTHENTICATEPRESIGNEDURLREQUEST_XAKAMAIHEADERSENTRY._serialized_options = b'8\001'
  _S3ERRORDETAILS._serialized_start=92
  _S3ERRORDETAILS._serialized_end=883
  _S3ERRORDETAILS_TYPE._serialized_start=327
  _S3ERRORDETAILS_TYPE._serialized_end=870
  _AUTHENTICATERESTREQUEST._serialized_start=886
  _AUTHENTICATERESTREQUEST._serialized_end=2140
  _AUTHENTICATERESTREQUEST_QUERYPARAMETERSENTRY._serialized_start=1642
  _AUTHENTICATERESTREQUEST_QUERYPARAMETERSENTRY._serialized_end=1708
  _AUTHENTICATERESTREQUEST_XAMZHEADERSENTRY._serialized_start=1710
  _AUTHENTICATERESTREQUEST_XAMZHEADERSENTRY._serialized_end=1772
  _AUTHENTICATERESTREQUEST_XAKAMAIHEADERSENTRY._serialized_start=1774
  _AUTHENTICATERESTREQUEST_XAKAMAIHEADERSENTRY._serialized_end=1839
  _AUTHENTICATERESTREQUEST_HTTPMETHOD._serialized_start=1842
  _AUTHENTICATERESTREQUEST_HTTPMETHOD._serialized_end=1993
  _AUTHENTICATERESTRESPONSE._serialized_start=2143
  _AUTHENTICATERESTRESPONSE._serialized_end=2395
  _AUTHENTICATEPRESIGNEDURLREQUEST._serialized_start=2398
  _AUTHENTICATEPRESIGNEDURLREQUEST._serialized_end=3248
  _AUTHENTICATEPRESIGNEDURLREQUEST_XAMZHEADERSENTRY._serialized_start=1710
  _AUTHENTICATEPRESIGNEDURLREQUEST_XAMZHEADERSENTRY._serialized_end=1772
  _AUTHENTICATEPRESIGNEDURLREQUEST_XAKAMAIHEADERSENTRY._serialized_start=1774
  _AUTHENTICATEPRESIGNEDURLREQUEST_XAKAMAIHEADERSENTRY._serialized_end=1839
  _AUTHENTICATEPRESIGNEDURLREQUEST_HTTPMETHOD._serialized_start=3093
  _AUTHENTICATEPRESIGNEDURLREQUEST_HTTPMETHOD._serialized_end=3176
  _AUTHENTICATEPRESIGNEDURLRESPONSE._serialized_start=3251
  _AUTHENTICATEPRESIGNEDURLRESPONSE._serialized_end=3511
  _GETSIGNINGKEYREQUEST._serialized_start=3514
  _GETSIGNINGKEYREQUEST._serialized_end=3650
  _GETSIGNINGKEYRESPONSE._serialized_start=3652
  _GETSIGNINGKEYRESPONSE._serialized_end=3708
  _ASSUMEROLEREQUEST._serialized_start=3711
  _ASSUMEROLEREQUEST._serialized_end=4020
  _ASSUMEROLERESPONSE._serialized_start=4023
  _ASSUMEROLERESPONSE._serialized_end=4284
  _CREDENTIALS._serialized_start=4287
  _CREDENTIALS._serialized_end=4477
  _ASSUMEROLERESPONSEMETADATA._serialized_start=4479
  _ASSUMEROLERESPONSEMETADATA._serialized_end=4538
  _ASSUMEROLERESULTS._serialized_start=4540
  _ASSUMEROLERESULTS._serialized_end=4641
  _AUTHENTICATORSERVICE._serialized_start=4644
  _AUTHENTICATORSERVICE._serialized_end=5092
# @@protoc_insertion_point(module_scope)
