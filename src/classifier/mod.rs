/// Maps SQL function names to their known semantics (role-threshold, current-user accessor, etc.).
pub mod function_registry;
// `expansion` documents itself in the file.
pub mod expansion;
// `oracle` documents itself in the file. A second doc here would merge with it and
// resolve its intra-doc links in this file's scope.
pub mod oracle;
/// Pattern enums, confidence levels, and classified expression/policy types.
pub mod patterns;
/// Top-level policy classification: walks each policy's USING/WITH CHECK expression tree.
pub mod policy_classifier;
/// Individual pattern recognizers (P1 to P6) that probe a single AST expression node.
pub mod recognizers;
