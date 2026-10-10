[(annotation name: (identifier) @ann) @annotation
 (marker_annotation name: (identifier) @ann) @annotation]
(#match? @ann "^(PreAuthorize|PostAuthorize|Secured|RolesAllowed|RequiresPermissions|RequiresRoles|SaCheckLogin|SaCheckPermission|SaCheckRole)$")
