(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(update|fill|forceFill|increment|decrement|incrementEach|setAttribute|save|inc|dec|setInc|setDec)$")
  (#match? @args "['\"](status|state|amount|balance|price|total|role|credit|points|quantity|paid|is_admin|approved|level|discount)['\"]")) @call
(nullsafe_member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(update|fill|forceFill|increment|decrement|incrementEach|setAttribute|save|inc|dec|setInc|setDec)$")
  (#match? @args "['\"](status|state|amount|balance|price|total|role|credit|points|quantity|paid|is_admin|approved|level|discount)['\"]")) @call
