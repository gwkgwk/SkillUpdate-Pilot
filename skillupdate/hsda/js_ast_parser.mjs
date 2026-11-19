import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const parser = require(process.argv[2]);
const request = JSON.parse(fs.readFileSync(0, "utf8"));
const source = request.source;
const filename = request.filename;
const plugins = ["jsx", "typescript", "topLevelAwait", "dynamicImport"];
const ast = parser.parse(source, {
  sourceType: "unambiguous",
  sourceFilename: filename,
  plugins,
  errorRecovery: false,
  attachComment: true,
});

const facts = [];
const counters = new Map();
function ordinal(key) {
  const value = counters.get(key) || 0;
  counters.set(key, value + 1);
  return value;
}
function nodeText(node) {
  return source.slice(node.start ?? 0, node.end ?? 0);
}
function nameOf(node) {
  if (!node) return "<unknown>";
  if (node.type === "Identifier" || node.type === "PrivateName") return node.name || nameOf(node.id);
  if (node.type === "ThisExpression") return "this";
  if (node.type === "Super") return "super";
  if (node.type === "StringLiteral") return JSON.stringify(node.value);
  if (node.type === "MemberExpression" || node.type === "OptionalMemberExpression") {
    return `${nameOf(node.object)}.${nameOf(node.property)}`;
  }
  return node.type;
}
function add(kind, key, value, node, attributes = {}) {
  facts.push({
    kind,
    key,
    value,
    start_line: node.loc?.start.line || 1,
    end_line: node.loc?.end.line || node.loc?.start.line || 1,
    attributes,
  });
}
function visit(node, parent = null) {
  if (!node || typeof node !== "object") return;
  if (node.type === "ImportDeclaration") {
    add("IMPORT", `import:${node.source.value}`, nodeText(node), node, { source: node.source.value });
  } else if (node.type === "CallExpression" || node.type === "OptionalCallExpression" || node.type === "NewExpression") {
    const target = nameOf(node.callee);
    add("FUNCTION_CALL", `call:${target}:${ordinal(`call:${target}`)}`, nodeText(node), node, { target });
  } else if (["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression", "ClassMethod", "ObjectMethod"].includes(node.type)) {
    const inferred = node.id?.name || node.key?.name || (parent?.type === "VariableDeclarator" ? nameOf(parent.id) : "<anonymous>");
    add("FUNCTION_DEFINITION", `function:${inferred}`, nodeText(node).split("{")[0].trim(), node, { name: inferred, async: Boolean(node.async) });
  } else if (["StringLiteral", "TemplateElement"].includes(node.type)) {
    const value = node.value?.cooked ?? node.value ?? "";
    add("STRING_LITERAL", `string:${ordinal("string")}`, String(value), node);
  }
  for (const [key, value] of Object.entries(node)) {
    if (["loc", "start", "end", "extra", "comments", "errors", "tokens"].includes(key)) continue;
    if (Array.isArray(value)) value.forEach((child) => visit(child, node));
    else if (value && typeof value === "object" && typeof value.type === "string") visit(value, node);
  }
}
visit(ast.program);
for (const comment of ast.comments || []) {
  add("COMMENT", `comment:${ordinal("comment")}`, comment.value, comment);
}
process.stdout.write(JSON.stringify({ facts }));
