(call
  function: (attribute object: (_) @receiver attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#match? @method "^(redirect|HttpResponseRedirect|HttpResponsePermanentRedirect|RedirectResponse)$")) @call
(call
  function: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(redirect|HttpResponseRedirect|HttpResponsePermanentRedirect|RedirectResponse)$")) @call
