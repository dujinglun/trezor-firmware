# Automatically generated by pb2py
from protobuf import protobuf as p
t = p.MessageType()
t.wire_type = 25
t.add_field(1, 'language', p.UnicodeType)
t.add_field(2, 'label', p.UnicodeType)
t.add_field(3, 'use_passphrase', p.BoolType)
t.add_field(4, 'homescreen', p.BytesType)
ApplySettings = t