import type { LanguageRegistration } from 'shiki';

/** A compact TextMate grammar for the Common Expression Language, tuned for Sekisho's variables. */
export const celGrammar = {
  name: 'cel',
  scopeName: 'source.cel',
  displayName: 'CEL',
  aliases: ['CEL'],
  patterns: [
    { name: 'comment.line.double-slash.cel', match: '//.*$' },
    { name: 'string.quoted.double.cel', match: '[rRbB]?"(?:[^"\\\\]|\\\\.)*"' },
    { name: 'string.quoted.single.cel', match: "[rRbB]?'(?:[^'\\\\]|\\\\.)*'" },
    {
      name: 'constant.numeric.cel',
      match: '\\b(?:0x[0-9a-fA-F]+u?|\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?u?)\\b',
    },
    { name: 'constant.language.cel', match: '\\b(?:true|false|null)\\b' },
    { name: 'keyword.operator.word.cel', match: '\\bin\\b' },
    {
      name: 'variable.language.cel',
      match:
        '\\b(?:claims|headers|query|path_params|body|body_bytes|body_text|method|path|host|operation|operation_id|config|params|userinfo|introspection)\\b',
    },
    { name: 'entity.name.function.cel', match: '\\b[A-Za-z_][A-Za-z0-9_]*(?=\\s*\\()' },
    { name: 'variable.other.property.cel', match: '(?<=\\.)[A-Za-z_][A-Za-z0-9_]*' },
    { name: 'keyword.operator.cel', match: '&&|\\|\\||==|!=|<=|>=|[<>!?:+\\-*/%]' },
  ],
  repository: {},
} satisfies LanguageRegistration;
