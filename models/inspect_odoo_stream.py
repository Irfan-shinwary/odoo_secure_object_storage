import inspect

import odoo
from odoo.http import Stream
from odoo.addons.base.models.ir_attachment import IrAttachment
from odoo.addons.base.models.ir_binary import IrBinary

print("=" * 70)
print("ODOO VERSION")
print("=" * 70)
print(odoo.release.version)

print("\n" + "=" * 70)
print("STREAM CLASS")
print("=" * 70)
print("Module:", inspect.getmodule(Stream).__file__)
print("Constructor:", inspect.signature(Stream))
print("\nStream implementation:")
print(inspect.getsource(Stream))

print("\n" + "=" * 70)
print("ATTACHMENT CREATE IMPLEMENTATION")
print("=" * 70)
print(inspect.getsource(IrAttachment.create))

print("\n" + "=" * 70)
print("ATTACHMENT STORAGE IMPLEMENTATION")
print("=" * 70)
print(inspect.getsource(IrAttachment._get_datas_related_values))

print("\n" + "=" * 70)
print("BINARY STREAM IMPLEMENTATION")
print("=" * 70)
print(inspect.getsource(IrBinary._record_to_stream))