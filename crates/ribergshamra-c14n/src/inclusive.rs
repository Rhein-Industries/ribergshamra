#![forbid(unsafe_code)]

//! Inclusive Canonical XML 1.0 (C14N 1.0).
//!
//! Algorithm URI: `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`
//! With comments: `http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments`
//!
//! Per the spec, the canonical form:
//! - Outputs namespace declarations sorted by prefix (default first)
//! - Outputs attributes sorted by (namespace-URI, local-name)
//! - Escapes text and attribute values per C14N rules
//! - Optionally preserves or strips comments
//! - Supports document-subset canonicalization via NodeSet

use crate::render::{write_sorted_attributes, Attr, NsDecl};
use crate::{escape, C14nSink};
use ribergshamra_core::Error;
use ribergshamra_xml::nodeset::NodeSet;
use std::collections::BTreeMap;
use uppsala::{Document, NodeId, NodeKind};

/// Canonicalize a document using Inclusive C14N 1.0.
///
/// Pass `with_comments = true` for
/// `http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments`.
/// `node_set` controls document-subset canonicalization; `None` makes every
/// node visible.
///
/// # Errors
///
/// Returns an error if document-subset C14N needs unsupported state.
pub fn canonicalize(
    doc: &Document<'_>,
    with_comments: bool,
    node_set: Option<&NodeSet>,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    canonicalize_to(doc, with_comments, node_set, &mut output)?;
    Ok(output)
}

/// Canonicalize a document into a byte sink using Inclusive C14N 1.0.
///
/// This writes the same byte stream as [`canonicalize`] without first
/// allocating the full output buffer. The caller owns the sink and can append
/// to an existing buffer or feed the bytes into a digest.
///
/// # Errors
///
/// Returns the same errors as [`canonicalize`].
pub fn canonicalize_to<W: C14nSink>(
    doc: &Document<'_>,
    with_comments: bool,
    node_set: Option<&NodeSet>,
    output: &mut W,
) -> Result<(), Error> {
    canonicalize_with_options_to(doc, with_comments, node_set, false, output)
}

/// Canonicalize with optional C14N 1.1 `xml:base` handling.
///
/// `c14n11_mode` enables the C14N 1.1 rule that can inherit or absolutize
/// `xml:base` for visible elements whose parent is outside the node set.
///
/// # Errors
///
/// Returns an error if canonicalization cannot be completed.
pub fn canonicalize_with_options(
    doc: &Document<'_>,
    with_comments: bool,
    node_set: Option<&NodeSet>,
    c14n11_mode: bool,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    canonicalize_with_options_to(doc, with_comments, node_set, c14n11_mode, &mut output)?;
    Ok(output)
}

/// Canonicalize with optional C14N 1.1 `xml:base` handling into a byte sink.
///
/// This is the streaming form of [`canonicalize_with_options`].
///
/// # Errors
///
/// Returns the same errors as [`canonicalize_with_options`].
pub fn canonicalize_with_options_to<W: C14nSink>(
    doc: &Document<'_>,
    with_comments: bool,
    node_set: Option<&NodeSet>,
    c14n11_mode: bool,
    output: &mut W,
) -> Result<(), Error> {
    ribergshamra_xml::limits::validate_document(doc)?;
    let mut ctx = C14nContext {
        doc,
        with_comments,
        node_set,
        c14n11_mode,
    };
    let mut limited = crate::LimitedSink::new(output);
    ctx.process_node(doc.root(), &mut limited, &BTreeMap::new())?;
    limited.finish()
}

struct C14nContext<'a, 'doc> {
    doc: &'a Document<'doc>,
    with_comments: bool,
    node_set: Option<&'a NodeSet>,
    c14n11_mode: bool,
}

impl<'a, 'doc> C14nContext<'a, 'doc> {
    /// Return whether `id` is visible according to the optional document
    /// subset. Visibility controls whether the node itself is serialized; even
    /// invisible elements may still have visible descendants that must be
    /// processed.
    fn is_visible(&self, id: NodeId) -> bool {
        match self.node_set {
            None => true,
            Some(ns) => ns.contains_id(id),
        }
    }

    /// Process a node in document order, passing along the namespace
    /// declarations inherited from the nearest visible ancestor.
    ///
    /// The inherited map represents namespaces that have already been rendered
    /// on visible ancestor elements, which lets `process_element` emit only the
    /// declarations that C14N requires at the current position.
    fn process_node<W: C14nSink>(
        &mut self,
        id: NodeId,
        output: &mut W,
        inherited_ns: &BTreeMap<String, String>,
    ) -> Result<(), Error> {
        output.check()?;
        match self.doc.node_kind(id) {
            Some(NodeKind::Document) => {
                for child in self.doc.children_iter(id) {
                    self.process_node(child, output, inherited_ns)?;
                }
            }
            Some(NodeKind::Element(_)) => {
                self.process_element(id, output, inherited_ns)?;
            }
            Some(NodeKind::Text(text)) | Some(NodeKind::CData(text)) if self.is_visible(id) => {
                escape::escape_text_into(output, text);
            }
            Some(NodeKind::Comment(text)) if self.with_comments && self.is_visible(id) => {
                let text = text.clone();
                // Top-level comments are separated from the document element by
                // newlines. Comments inside elements are emitted without those
                // synthetic separators.
                let parent_is_root = self
                    .doc
                    .parent(id)
                    .is_some_and(|p| matches!(self.doc.node_kind(p), Some(NodeKind::Document)));

                if parent_is_root {
                    // Before document element: comment\n
                    // After document element: \ncomment
                    let has_preceding_element = has_preceding_element(self.doc, id);
                    if has_preceding_element {
                        output.write_byte(b'\n');
                    }
                }

                output.write(b"<!--");
                output.write(text.as_bytes());
                output.write(b"-->");

                if parent_is_root {
                    let has_following_element = has_following_element(self.doc, id);
                    if has_following_element {
                        output.write_byte(b'\n');
                    }
                }
            }
            Some(NodeKind::ProcessingInstruction(pi)) if self.is_visible(id) => {
                let target = pi.target.clone();
                let data = pi.data.clone();

                let parent_is_root = self
                    .doc
                    .parent(id)
                    .is_some_and(|p| matches!(self.doc.node_kind(p), Some(NodeKind::Document)));

                if parent_is_root {
                    let has_preceding_element = has_preceding_element(self.doc, id);
                    if has_preceding_element {
                        output.write_byte(b'\n');
                    }
                }

                output.write(b"<?");
                output.write(target.as_bytes());
                if let Some(value) = &data {
                    if !value.is_empty() {
                        output.write_byte(b' ');
                        escape::escape_pi_into(output, value);
                    }
                }
                output.write(b"?>");

                if parent_is_root {
                    let has_following_element = has_following_element(self.doc, id);
                    if has_following_element {
                        output.write_byte(b'\n');
                    }
                }
            }
            _ => {}
        }
        output.check()
    }

    /// Process an element and its descendants.
    ///
    /// Visible elements emit a start tag, namespace declarations, attributes,
    /// child content, and an end tag. Invisible elements do not emit their own
    /// tag, but their children must still be visited because a document subset
    /// may select descendants without selecting the ancestor.
    fn process_element<W: C14nSink>(
        &mut self,
        id: NodeId,
        output: &mut W,
        inherited_ns: &BTreeMap<String, String>,
    ) -> Result<(), Error> {
        output.check()?;
        let visible = self.is_visible(id);

        if visible {
            // Collect all namespace declarations that are "in scope" at this element.
            // For inclusive C14N, this means all namespaces declared on this element
            // and all ancestors that haven't been overridden.
            let current_ns = collect_inscope_namespaces(self.doc, id);

            // If the node set has namespace node visibility filtering,
            // restrict in-scope namespaces to only those whose namespace
            // node is in the node-set (per C14N spec section 2.3).
            let has_ns_filter = self.node_set.is_some_and(|ns| ns.has_ns_visible());
            let visible_ns: BTreeMap<String, String> = if has_ns_filter {
                let eid = id.index();
                let ns = self.node_set.unwrap();
                current_ns
                    .into_iter()
                    .filter(|(prefix, _)| ns.is_ns_visible(eid, prefix))
                    .collect()
            } else {
                current_ns
            };

            // Determine which namespace declarations to output:
            // Output a namespace declaration if:
            // 1. It's not the xml namespace (never output xmlns:xml=...)
            // 2. It's new or different from what was inherited
            let mut ns_decls: Vec<NsDecl> = Vec::new();
            for (prefix, uri) in &visible_ns {
                // Skip xml namespace
                if prefix == "xml" {
                    continue;
                }
                // Only output if different from inherited
                let inherited_val = inherited_ns.get(prefix);
                if inherited_val != Some(uri) {
                    // C14N spec step 3e: if the prefix is not in the
                    // inherited/rendered set and the URI is empty,
                    // do nothing (don't output xmlns="" when no ancestor
                    // had a default namespace to undeclare).
                    if uri.is_empty() && inherited_val.is_none() {
                        continue;
                    }
                    ns_decls.push(NsDecl {
                        prefix: prefix.clone(),
                        uri: uri.clone(),
                    });
                }
            }

            // C14N spec: if the nearest visible ancestor had a non-empty
            // default namespace but this element's default namespace node
            // is NOT in the node set, output xmlns="" to undeclare it.
            if has_ns_filter {
                if let Some(inherited_default) = inherited_ns.get("") {
                    if !inherited_default.is_empty() && !visible_ns.contains_key("") {
                        ns_decls.push(NsDecl {
                            prefix: String::new(),
                            uri: String::new(),
                        });
                    }
                }
            }

            ns_decls.sort();

            // Collect attributes (non-namespace)
            // Skip if the node set excludes attribute nodes entirely.
            let attrs_excluded = self.node_set.is_some_and(|ns| ns.excludes_attrs());
            let mut attrs: Vec<Attr> = Vec::new();
            // Whole-document C14N can borrow attributes directly from the DOM.
            // Keep owned attributes for subsets, whose xml:* inheritance and
            // C14N 1.1 xml:base handling may synthesize or replace values.
            if self.node_set.is_some() && !attrs_excluded {
                let elem = self.doc.element(id).unwrap();
                for attr in &elem.attributes {
                    let ns_uri = attr.name.namespace_uri.as_deref().unwrap_or("");
                    // Build qualified name
                    let qname = if let Some(prefix) = find_attr_prefix(attr) {
                        format!("{}:{}", prefix, attr.name.local_name)
                    } else {
                        attr.name.local_name.to_string()
                    };
                    attrs.push(Attr {
                        ns_uri: ns_uri.to_owned(),
                        local_name: attr.name.local_name.to_string(),
                        qualified_name: qname,
                        value: attr.value.to_string(),
                    });
                }
            }
            attrs.sort();

            // Also check for xml:* attributes that need to be inherited.
            // Per C14N 1.0 spec (and libxml2): xml:* inheritance only happens
            // when the element is visible but its immediate parent is NOT
            // visible in the node set. If the parent IS visible, it will
            // output its own xml:* attrs, so no inheritance is needed.
            // Skip when attribute nodes are excluded from the node set.
            if self.node_set.is_some() && !attrs_excluded {
                let parent_not_visible = self
                    .doc
                    .parent(id)
                    .is_none_or(|p| self.doc.element(p).is_none() || !self.is_visible(p));
                if parent_not_visible {
                    let extra = self.collect_inherited_xml_attrs(id, &attrs);
                    attrs.extend(extra);

                    // C14N 1.1 joins only bases on contiguously omitted
                    // ancestors, stopping at the nearest visible ancestor.
                    if self.c14n11_mode {
                        let xml_ns = "http://www.w3.org/XML/1998/namespace";
                        if let Some(base) = self.omitted_base_uri(id) {
                            attrs.retain(|attr| {
                                !(attr.ns_uri == xml_ns && attr.local_name == "base")
                            });
                            if !base.is_empty() {
                                attrs.push(Attr {
                                    ns_uri: xml_ns.to_owned(),
                                    local_name: "base".to_owned(),
                                    qualified_name: "xml:base".to_owned(),
                                    value: base,
                                });
                            }
                        }
                    }
                }
            }
            // Re-sort after possible additions
            attrs.sort();

            // Build qualified element name
            let elem_name = qualified_element_name(self.doc, id);

            // Output: <name ns-decls attrs>
            output.write_byte(b'<');
            output.write(elem_name.as_bytes());
            output.check()?;
            for ns_decl in &ns_decls {
                ns_decl.write_to(output);
                output.check()?;
            }
            if self.node_set.is_none() {
                write_sorted_attributes(&self.doc.element(id).unwrap().attributes, output)?;
            } else {
                for attr in &attrs {
                    attr.write_to(output);
                    output.check()?;
                }
            }
            output.write_byte(b'>');
            output.check()?;

            // Process children with updated namespace context.
            // Per C14N spec (section 2.3): the "nearest ancestor element in
            // the node-set" check for namespace output means children should
            // only see namespace declarations that this element has in its
            // namespace node-set. When ns filtering is active, child_ns is
            // set to this element's visible_ns (not accumulated from ancestors).
            let child_ns = if has_ns_filter {
                // With namespace node filtering: children see only this
                // element's visible namespace nodes. This ensures that when
                // a child has a namespace node in its set that the parent
                // didn't, it correctly outputs a new declaration.
                let mut cn = BTreeMap::new();
                for (prefix, uri) in &visible_ns {
                    if prefix != "xml" {
                        cn.insert(prefix.clone(), uri.clone());
                    }
                }
                cn
            } else {
                let mut cn = inherited_ns.clone();
                for (prefix, uri) in &visible_ns {
                    if prefix != "xml" {
                        cn.insert(prefix.clone(), uri.clone());
                    }
                }
                cn
            };

            for child in self.doc.children_iter(id) {
                self.process_node(child, output, &child_ns)?;
            }

            // Close tag
            output.write(b"</");
            output.write(elem_name.as_bytes());
            output.write_byte(b'>');
        } else {
            // Element not visible, but per C14N 1.0 spec (section 2.3):
            // "If the element is not in the node-set, then the result is
            // obtained by processing the namespace axis, then the attribute
            // axis, then the child nodes of the element that are in the
            // node-set."
            //
            // When namespace node filtering is active, visible namespace
            // nodes on invisible elements are output as text (not attached
            // to an element tag). This produces the ` xmlns:prefix="URI"`
            // text that appears "floating" in the canonical form.
            let has_ns_filter = self.node_set.is_some_and(|ns| ns.has_ns_visible());
            if has_ns_filter {
                let eid = id.index();
                let ns = self.node_set.unwrap();

                // Collect this element's in-scope namespaces
                let current_ns = collect_inscope_namespaces(self.doc, id);

                // Filter by ns_visible
                let visible_ns: BTreeMap<String, String> = current_ns
                    .into_iter()
                    .filter(|(prefix, _)| ns.is_ns_visible(eid, prefix))
                    .collect();

                // Output namespace declarations for visible ns nodes
                // that differ from what was inherited (nearest visible ancestor).
                let mut ns_decls: Vec<NsDecl> = Vec::new();
                for (prefix, uri) in &visible_ns {
                    if prefix == "xml" {
                        continue;
                    }
                    let inherited_val = inherited_ns.get(prefix);
                    if inherited_val != Some(uri) {
                        // C14N spec step 3e: skip empty URI when not
                        // previously rendered
                        if uri.is_empty() && inherited_val.is_none() {
                            continue;
                        }
                        ns_decls.push(NsDecl {
                            prefix: prefix.clone(),
                            uri: uri.clone(),
                        });
                    }
                }
                ns_decls.sort();
                for ns_decl in &ns_decls {
                    ns_decl.write_to(output);
                    output.check()?;
                }
            }

            // Children inherit the SAME inherited_ns (not the invisible
            // element's visible_ns). Per C14N spec, the "nearest ancestor
            // element in the node-set" check is based on visible ancestors
            // only. Invisible element ns output does not affect what
            // visible descendants render.
            for child in self.doc.children_iter(id) {
                self.process_node(child, output, inherited_ns)?;
            }
        }
        output.check()
    }

    /// For document-subset C14N 1.0: collect xml:* attributes inherited from
    /// ancestors. Called only when the element's immediate parent is NOT
    /// visible. Per the spec and libxml2, we walk ALL ancestors (regardless
    /// of visibility) collecting xml:* attrs, then remove any already
    /// present on the element's own attribute axis.
    fn collect_inherited_xml_attrs(&self, id: NodeId, existing_attrs: &[Attr]) -> Vec<Attr> {
        let xml_ns = "http://www.w3.org/XML/1998/namespace";
        let mut inherited_xml: BTreeMap<String, String> = BTreeMap::new();

        let mut current = self.doc.parent(id);
        while let Some(ancestor) = current {
            if let Some(elem) = self.doc.element(ancestor) {
                for attr in &elem.attributes {
                    if attr.name.namespace_uri.as_deref() == Some(xml_ns) {
                        let name = &*attr.name.local_name;
                        if self.c14n11_mode && !matches!(name, "lang" | "space") {
                            continue;
                        }
                        // Nearest ancestor value wins (first occurrence)
                        if !inherited_xml.contains_key(name) {
                            inherited_xml.insert(name.to_owned(), attr.value.to_string());
                        }
                    }
                }
            }
            current = self.doc.parent(ancestor);
        }

        let mut result = Vec::new();
        for (name, value) in &inherited_xml {
            let already_present = existing_attrs
                .iter()
                .any(|a| a.ns_uri == xml_ns && a.local_name == *name);
            if !already_present {
                result.push(Attr {
                    ns_uri: xml_ns.to_owned(),
                    local_name: name.clone(),
                    qualified_name: format!("xml:{name}"),
                    value: value.clone(),
                });
            }
        }
        result
    }

    fn omitted_base_uri(&self, id: NodeId) -> Option<String> {
        let base = |node| {
            self.doc.element(node).and_then(|element| {
                element
                    .attributes
                    .iter()
                    .find(|attr| {
                        attr.name.namespace_uri.as_deref()
                            == Some("http://www.w3.org/XML/1998/namespace")
                            && attr.name.local_name.as_ref() == "base"
                    })
                    .map(|attr| attr.value.to_string())
            })
        };
        let mut bases = Vec::new();
        if let Some(value) = base(id) {
            bases.push(value);
        }
        let mut omitted_base = false;
        let mut current = self.doc.parent(id);
        while let Some(ancestor) = current {
            if self.doc.element(ancestor).is_some() && self.is_visible(ancestor) {
                break;
            }
            if let Some(value) = base(ancestor) {
                bases.push(value);
                omitted_base = true;
            }
            current = self.doc.parent(ancestor);
        }
        if !omitted_base {
            return None;
        }
        let mut values = bases.into_iter();
        let mut joined = values.next().unwrap_or_default();
        for ancestor in values {
            joined = resolve_uri_reference(&ancestor, &joined);
        }
        Some(joined)
    }
}

/// Check if any preceding sibling is an element.
fn has_preceding_element(doc: &Document<'_>, id: NodeId) -> bool {
    let mut sib = doc.previous_sibling(id);
    while let Some(s) = sib {
        if doc.element(s).is_some() {
            return true;
        }
        sib = doc.previous_sibling(s);
    }
    false
}

/// Check if any following sibling is an element.
fn has_following_element(doc: &Document<'_>, id: NodeId) -> bool {
    let mut sib = doc.next_sibling(id);
    while let Some(s) = sib {
        if doc.element(s).is_some() {
            return true;
        }
        sib = doc.next_sibling(s);
    }
    false
}

/// Collect all in-scope namespaces for an element.
///
/// This walks up the ancestor chain and collects all namespace declarations,
/// with closer declarations overriding more distant ones.
fn collect_inscope_namespaces(doc: &Document<'_>, id: NodeId) -> BTreeMap<String, String> {
    let mut ns_stack: Vec<BTreeMap<String, String>> = Vec::new();

    // Walk up to root, collecting namespaces at each level
    let mut current = Some(id);
    while let Some(n) = current {
        if let Some(elem) = doc.element(n) {
            let mut level = BTreeMap::new();
            for (prefix, uri) in &elem.namespace_declarations {
                level.insert(prefix.to_string(), uri.to_string());
            }
            ns_stack.push(level);
        }
        current = doc.parent(n);
    }

    // Merge from root down (root is last in stack)
    let mut result = BTreeMap::new();
    for level in ns_stack.into_iter().rev() {
        for (prefix, uri) in level {
            if uri.is_empty() && prefix.is_empty() {
                // xmlns="" undeclares the default namespace.
                // Keep it as an empty-string entry so C14N can emit xmlns=""
                // when the inherited default was non-empty.
                result.insert(prefix, uri);
            } else if uri.is_empty() {
                // Undeclaration of a prefixed namespace (only valid in XML 1.1)
                result.remove(&prefix);
            } else {
                result.insert(prefix, uri);
            }
        }
    }
    result
}

/// Get the qualified element name (prefix:local or just local).
fn qualified_element_name(doc: &Document<'_>, id: NodeId) -> String {
    let elem = doc.element(id).unwrap();
    if let Some(prefix) = &elem.name.prefix {
        format!("{}:{}", prefix, elem.name.local_name)
    } else {
        elem.name.local_name.to_string()
    }
}

/// Find the prefix for an attribute's namespace.
fn find_attr_prefix(attr: &uppsala::Attribute<'_>) -> Option<String> {
    if let Some(ns_uri) = &attr.name.namespace_uri {
        if &**ns_uri == "http://www.w3.org/XML/1998/namespace" {
            return Some("xml".to_owned());
        }
        attr.name.prefix.as_ref().map(|p| p.to_string())
    } else {
        None
    }
}

/// C14N 1.1 join-URI-References: RFC 3986 component resolution with
/// relative bases, retained leading parent segments, collapsed slashes,
/// trailing parent-directory handling, and ignored fragments (§2.4).
fn resolve_uri_reference(base: &str, reference: &str) -> String {
    let base = UriParts::parse(base);
    let base_path = if base.path.rsplit('/').next() == Some("..") {
        format!("{}/", base.path)
    } else {
        base.path.to_owned()
    };
    let base = UriParts {
        path: &base_path,
        ..base
    };
    let reference = UriParts::parse(reference);
    let (scheme, authority, path, query) = if reference.scheme.is_some() {
        (
            reference.scheme,
            reference.authority,
            remove_base_dot_segments(reference.path),
            reference.query,
        )
    } else if reference.authority.is_some() {
        (
            base.scheme,
            reference.authority,
            remove_base_dot_segments(reference.path),
            reference.query,
        )
    } else if reference.path.is_empty() {
        (
            base.scheme,
            base.authority,
            base.path.to_owned(),
            reference.query.or(base.query),
        )
    } else {
        let path = if reference.path.starts_with('/') {
            reference.path.to_owned()
        } else if base.authority.is_some() && base.path.is_empty() {
            format!("/{}", reference.path)
        } else {
            let cut = base.path.rfind('/').map_or(0, |index| index + 1);
            format!("{}{}", &base.path[..cut], reference.path)
        };
        (
            base.scheme,
            base.authority,
            remove_base_dot_segments(&path),
            reference.query,
        )
    };
    let mut result = String::new();
    if let Some(scheme) = scheme {
        result.push_str(scheme);
        result.push(':');
    }
    if let Some(authority) = authority {
        result.push_str("//");
        result.push_str(authority);
    }
    result.push_str(&path);
    if let Some(query) = query {
        result.push('?');
        result.push_str(query);
    }
    result
}

struct UriParts<'a> {
    scheme: Option<&'a str>,
    authority: Option<&'a str>,
    path: &'a str,
    query: Option<&'a str>,
}

impl<'a> UriParts<'a> {
    fn parse(uri: &'a str) -> Self {
        let without_fragment = uri.split_once('#').map_or(uri, |(head, _)| head);
        let (mut path, query) = without_fragment
            .split_once('?')
            .map_or((without_fragment, None), |(path, query)| {
                (path, Some(query))
            });
        let mut scheme = None;
        if let Some((candidate, remainder)) = path.split_once(':') {
            let mut chars = candidate.chars();
            if chars
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic())
                && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
            {
                scheme = Some(candidate);
                path = remainder;
            }
        }
        let authority = if let Some(rest) = path.strip_prefix("//") {
            let end = rest.find('/').unwrap_or(rest.len());
            path = &rest[end..];
            Some(&rest[..end])
        } else {
            None
        };
        Self {
            scheme,
            authority,
            path,
            query,
        }
    }
}

fn remove_base_dot_segments(path: &str) -> String {
    let absolute = path.starts_with('/');
    let trailing = path.ends_with('/') || matches!(path.rsplit('/').next(), Some("." | ".."));
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." if segments.last().is_some_and(|last| *last != "..") => {
                segments.pop();
            }
            ".." if !absolute => segments.push(segment),
            ".." => {}
            _ => segments.push(segment),
        }
    }
    let mut result = if absolute {
        format!("/{}", segments.join("/"))
    } else {
        segments.join("/")
    };
    if trailing && !result.is_empty() && !result.ends_with('/') {
        result.push('/');
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c14n11_inherits_only_language_and_space() {
        let doc = uppsala::parse(
            "<r xml:id='parent' xml:lang='en' xml:space='preserve' xml:custom='x'><leaf/></r>",
        )
        .unwrap();
        let leaf = doc.get_elements_by_tag_name("leaf")[0];
        let subset = NodeSet::tree_without_comments(leaf, &doc);
        let out = canonicalize_with_options(&doc, false, Some(&subset), true).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "<leaf xml:lang=\"en\" xml:space=\"preserve\"></leaf>"
        );
        let legacy = canonicalize_with_options(&doc, false, Some(&subset), false).unwrap();
        assert!(String::from_utf8(legacy)
            .unwrap()
            .contains("xml:id=\"parent\""));
    }

    #[test]
    fn c14n11_base_fixup_stops_at_visible_ancestor() {
        use ribergshamra_xml::nodeset::NodeSetType;
        let doc = uppsala::parse("<r xml:base='outer/path'><a xml:base='..'><b xml:base='..'><leaf xml:base='x'/></b></a></r>").unwrap();
        let root = doc.document_element().unwrap();
        let leaf = doc.get_elements_by_tag_name("leaf")[0];
        let subset = NodeSet::from_ids(
            [root.index(), leaf.index()].into_iter().collect(),
            NodeSetType::Normal,
        );
        let out = canonicalize_with_options(&doc, false, Some(&subset), true).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "<r xml:base=\"outer/path\"><leaf xml:base=\"../../x\"></leaf></r>"
        );
    }

    #[test]
    fn c14n11_base_join_preserves_relative_paths_and_components() {
        for (base, reference, expected) in [
            ("abc/", "../", ""),
            ("../", "../", "../../"),
            ("..", "..", "../../"),
            ("..", "", "../"),
            ("a/..", "?q", "a/../?q"),
            (
                "http://host/a/b?old",
                "../x?new#ignored",
                "http://host/x?new",
            ),
            ("http://host/a", "//other/x", "http://other/x"),
            ("http://host/a?old", "?new#ignored", "http://host/a?new"),
            ("http://host/a", "urn:example:x#ignored", "urn:example:x"),
            ("a//b/", "../x", "a/x"),
        ] {
            assert_eq!(
                resolve_uri_reference(base, reference),
                expected,
                "{base} + {reference}"
            );
        }
        let doc = uppsala::parse("<r xml:base='abc/'><a xml:base='../'><leaf/></a></r>").unwrap();
        let leaf = doc.get_elements_by_tag_name("leaf")[0];
        let subset = NodeSet::tree_without_comments(leaf, &doc);
        let out = canonicalize_with_options(&doc, false, Some(&subset), true).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "<leaf></leaf>");
    }

    #[test]
    fn test_simple_c14n() {
        let xml = r#"<root><a b="1" a="2"/></root>"#;
        let doc = uppsala::parse(xml).unwrap();
        let result = canonicalize(&doc, false, None).unwrap();
        let output = String::from_utf8(result).unwrap();
        // Attributes should be sorted by local name (no namespace)
        assert_eq!(output, r#"<root><a a="2" b="1"></a></root>"#);
    }

    #[test]
    fn test_namespace_rendering() {
        let xml = r#"<root xmlns:a="http://a" xmlns:b="http://b"><a:child/></root>"#;
        let doc = uppsala::parse(xml).unwrap();
        let result = canonicalize(&doc, false, None).unwrap();
        let output = String::from_utf8(result).unwrap();
        assert!(output.contains("xmlns:a=\"http://a\""));
        assert!(output.contains("xmlns:b=\"http://b\""));
    }

    #[test]
    fn test_text_escaping() {
        let xml = r#"<root>a &amp; b &lt; c</root>"#;
        let doc = uppsala::parse(xml).unwrap();
        let result = canonicalize(&doc, false, None).unwrap();
        let output = String::from_utf8(result).unwrap();
        assert_eq!(output, "<root>a &amp; b &lt; c</root>");
    }

    // --- W3C C14N 1.0 Spec Examples ---
    // From: https://www.w3.org/TR/2001/REC-xml-c14n-20010315#Examples

    #[test]
    fn test_w3c_example_3_1_without_comments() {
        // Example 3.1: PIs, Comments, and Outside of Document Element
        // The XML declaration and DTD are not reproduced.
        // Comments are stripped in the without-comments variant.
        // PIs are normalized (trailing spaces removed from PI without data).
        // Note: The DTD "<!DOCTYPE doc SYSTEM "doc.dtd">" is ignored by the parser.
        let input = "<?xml version=\"1.0\"?>\n\n\
            <?xml-stylesheet   href=\"doc.xsl\" type=\"text/xsl\"   ?>\n\n\
            <doc>Hello, world!<!-- Comment 1 --></doc>\n\n\
            <?pi-without-data     ?>\n\n\
            <!-- Comment 2 -->\n\n\
            <!-- Comment 3 -->";
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, false, None).unwrap();
        let output = String::from_utf8(result).unwrap();
        // Expected: PI normalized, doc element, PI without data normalized, no comments
        let expected = "<?xml-stylesheet href=\"doc.xsl\" type=\"text/xsl\"   ?>\n\
            <doc>Hello, world!</doc>\n\
            <?pi-without-data?>";
        assert_eq!(output, expected);
    }

    #[test]
    fn test_w3c_example_3_1_with_comments() {
        // Example 3.1 with comments preserved.
        let input = "<?xml version=\"1.0\"?>\n\n\
            <?xml-stylesheet   href=\"doc.xsl\" type=\"text/xsl\"   ?>\n\n\
            <doc>Hello, world!<!-- Comment 1 --></doc>\n\n\
            <?pi-without-data     ?>\n\n\
            <!-- Comment 2 -->\n\n\
            <!-- Comment 3 -->";
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, true, None).unwrap();
        let output = String::from_utf8(result).unwrap();
        let expected = "<?xml-stylesheet href=\"doc.xsl\" type=\"text/xsl\"   ?>\n\
            <doc>Hello, world!<!-- Comment 1 --></doc>\n\
            <?pi-without-data?>\n\
            <!-- Comment 2 -->\n\
            <!-- Comment 3 -->";
        assert_eq!(output, expected);
    }

    #[test]
    fn test_w3c_example_3_2_whitespace_in_content() {
        // Example 3.2: Whitespace in Document Content
        // Whitespace within elements is preserved as-is.
        let input = "<doc>\n\
            \x20\x20\x20<clean>   </clean>\n\
            \x20\x20\x20<dirty>   A   B   </dirty>\n\
            \x20\x20\x20<mixed>\n\
            \x20\x20\x20\x20\x20\x20A\n\
            \x20\x20\x20\x20\x20\x20<clean>   </clean>\n\
            \x20\x20\x20\x20\x20\x20B\n\
            \x20\x20\x20\x20\x20\x20<dirty>   A   B   </dirty>\n\
            \x20\x20\x20\x20\x20\x20C\n\
            \x20\x20\x20</mixed>\n\
            </doc>";
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, false, None).unwrap();
        let output = String::from_utf8(result).unwrap();
        // Output should be identical to input (whitespace is preserved in C14N)
        assert_eq!(output, input);
    }

    #[test]
    fn test_w3c_example_3_4_character_modifications() {
        // Example 3.4: Character Modifications and Character References
        // - Character references are replaced with the actual characters
        // - CDATA sections are replaced with their content (with escaping)
        // - Attribute values are normalized per XML spec
        // Note: DTD-driven attribute normalization (NMTOKENS) is NOT supported
        // by our parser, so normNames differs from the spec output.
        //
        // Modified test (same as Go library) - skip DTD-dependent normalizations.
        let input = "<doc>\n\
            \x20\x20\x20<text>First line&#x0d;&#10;Second line</text>\n\
            \x20\x20\x20<value>&#x32;</value>\n\
            \x20\x20\x20<compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n\
            \x20\x20\x20<compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n\
            \x20\x20\x20<norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n\
            \x20\x20\x20<normNames attr='   A   &#x20;&#13;&#xa;&#9;   B   '/>\n\
            </doc>";
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, false, None).unwrap();
        let output = String::from_utf8(result).unwrap();
        // Expected output per W3C spec, modified for no-DTD:
        // - &#x0d; -> &#xD; (CR in text)
        // - &#10; -> actual newline
        // - &#x32; -> "2"
        // - CDATA replaced with escaped text
        // - Attribute values use double quotes, entities escaped
        // - normNames NOT NMTOKENS-normalized (no DTD support)
        let expected = "<doc>\n\
            \x20\x20\x20<text>First line&#xD;\n\
            Second line</text>\n\
            \x20\x20\x20<value>2</value>\n\
            \x20\x20\x20<compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n\
            \x20\x20\x20<compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n\
            \x20\x20\x20<norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n\
            \x20\x20\x20<normNames attr=\"   A    &#xD;&#xA;&#x9;   B   \"></normNames>\n\
            </doc>";
        assert_eq!(output, expected);
    }

    #[test]
    fn test_w3c_example_3_6_utf8_encoding() {
        // Example 3.6: UTF-8 Encoding
        // The copyright character (©, U+00A9) encoded as ISO-8859-1 in the
        // XML declaration. C14N output is UTF-8 without XML declaration.
        // Note: Our parser handles UTF-8 input. The copyright sign is U+00A9
        // which is 0xC2 0xA9 in UTF-8.
        let input = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<doc>\u{00A9}</doc>";
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, false, None).unwrap();
        let output = String::from_utf8(result).unwrap();
        assert_eq!(output, "<doc>\u{00A9}</doc>");
    }

    #[test]
    fn test_comment_stripping() {
        // Multiple adjacent comments should all be stripped in without-comments mode.
        // Ported from Go signedxml GitHub Issue #50.
        let input = "<a><!-- comment0 --><!-- comment1 --><!-- comment2 --></a>";
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, false, None).unwrap();
        let output = String::from_utf8(result).unwrap();
        assert_eq!(output, "<a></a>");
    }

    #[test]
    fn test_comment_preservation() {
        // Multiple adjacent comments should all be preserved in with-comments mode.
        let input = "<a><!-- comment0 --><!-- comment1 --><!-- comment2 --></a>";
        let doc = uppsala::parse(input).unwrap();
        let result = canonicalize(&doc, true, None).unwrap();
        let output = String::from_utf8(result).unwrap();
        assert_eq!(
            output,
            "<a><!-- comment0 --><!-- comment1 --><!-- comment2 --></a>"
        );
    }
}
