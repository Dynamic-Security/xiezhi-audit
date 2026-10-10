((echo_statement) @call
  (#match? @call "\\$_(GET|POST|REQUEST|COOKIE|SERVER)")
  (#not-match? @call "htmlspecialchars|htmlentities|intval|\\(int\\)|json_encode|strip_tags|urlencode|\\be\\("))
