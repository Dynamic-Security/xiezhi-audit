(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(where|whereOr|order|field|having|group|join|whereExp|orderRaw|fieldRaw|whereRaw)$")) @call
(nullsafe_member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(where|whereOr|order|field|having|group|join|whereExp|orderRaw|fieldRaw|whereRaw)$")) @call
(scoped_call_expression
  scope: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(where|whereOr|order|field|whereRaw|orderRaw)$")) @call
