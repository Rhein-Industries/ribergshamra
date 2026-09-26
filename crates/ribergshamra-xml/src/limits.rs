//! Finite resource budgets shared by XML security entrypoints.

use quick_xml::{events::Event, Reader};
use ribergshamra_core::{ns, Error};
use std::io::{self, Write};
use uppsala::{Document, NodeKind, QName};

/// Maximum source or intermediate XML/binary bytes accepted by security APIs.
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum accumulated output or expanded DOM content bytes.
pub const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
/// Maximum traversed document nodes.
pub const MAX_NODES: usize = 100_000;
/// Maximum element depth, including caller-built DOMs.
pub const MAX_DEPTH: usize = 128;
/// Maximum attributes plus namespace declarations on one element.
pub const MAX_ATTRIBUTES: usize = 128;
/// Maximum signatures, references, or embedded certificates in one document.
pub const MAX_SECURITY_ITEMS: usize = 64;
/// Maximum XPath/XPointer expression bytes.
pub const MAX_EXPRESSION_BYTES: usize = 16 * 1024;
/// Conservative node-times-reference/transform/expression work budget.
pub const MAX_WORK: usize = 10_000_000;

fn exceeded(resource: &str) -> Error {
    Error::XmlStructure(format!("XML security resource limit exceeded: {resource}"))
}

/// Check a source or intermediate buffer before cloning or parsing it.
pub fn validate_input_size(bytes: usize) -> Result<(), Error> {
    if bytes > MAX_INPUT_BYTES {
        return Err(exceeded("input bytes"));
    }
    Ok(())
}

/// Check output size before returning or reprocessing it.
pub fn validate_output_size(bytes: usize) -> Result<(), Error> {
    if bytes > MAX_OUTPUT_BYTES {
        return Err(exceeded("output bytes"));
    }
    Ok(())
}

/// Parse bounded XML and check its expanded DOM before security processing.
pub fn parse(xml: &str) -> Result<Document<'_>, Error> {
    validate_input_size(xml.len())?;
    validate_structure_before_parse(xml, MAX_NODES, MAX_DEPTH, MAX_ATTRIBUTES)?;
    let doc = uppsala::parse(xml).map_err(|error| Error::XmlParse(error.to_string()))?;
    validate_document(&doc)?;
    Ok(doc)
}

// Read borrowed lexical events before Uppsala allocates its DOM. Entity
// expansion remains Uppsala's responsibility and is checked again on the DOM.
fn validate_structure_before_parse(
    xml: &str,
    max_nodes: usize,
    max_depth: usize,
    max_attributes: usize,
) -> Result<(), Error> {
    let mut reader = Reader::from_str(xml);
    let mut nodes = 1usize; // Uppsala's document node.
    let mut depth = 0usize;
    let mut in_text = false;
    loop {
        let event = reader
            .read_event()
            .map_err(|error| Error::XmlParse(error.to_string()))?;
        match &event {
            Event::Start(element) | Event::Empty(element) => {
                nodes = nodes.saturating_add(1);
                if depth.saturating_add(1) > max_depth {
                    return Err(exceeded("depth"));
                }
                for (index, attribute) in element.attributes().with_checks(false).enumerate() {
                    if index >= max_attributes {
                        return Err(exceeded("attributes/namespaces"));
                    }
                    attribute.map_err(|error| Error::XmlParse(error.to_string()))?;
                }
                if matches!(event, Event::Start(_)) {
                    depth = depth.saturating_add(1);
                }
                in_text = false;
            }
            Event::End(_) => {
                depth = depth.saturating_sub(1);
                in_text = false;
            }
            // Uppsala coalesces adjacent text and entity references into one
            // text node; counting a lexical entity as a new node would reject
            // ordinary escaped text unnecessarily.
            Event::Text(_) | Event::GeneralRef(_) => {
                if !in_text {
                    nodes = nodes.saturating_add(1);
                    in_text = true;
                }
            }
            Event::CData(_) | Event::Comment(_) | Event::PI(_) => {
                nodes = nodes.saturating_add(1);
                in_text = false;
            }
            Event::Eof => return Ok(()),
            Event::Decl(_) | Event::DocType(_) => in_text = false,
        }
        if nodes > max_nodes {
            return Err(exceeded("nodes"));
        }
    }
}

/// Serialize a validated DOM while bounding the exact escaped output size.
///
/// Uses Uppsala's normal serializer, including namespace fixup, without first
/// allocating an unrestricted intermediate string.
///
/// # Errors
///
/// Returns an error if the document or serialized output exceeds the XML
/// security budgets, or if serialization fails.
pub fn serialize_document(doc: &Document<'_>) -> Result<String, Error> {
    validate_document(doc)?;
    serialize_document_with_limit(doc, MAX_OUTPUT_BYTES)
}

fn serialize_document_with_limit(doc: &Document<'_>, limit: usize) -> Result<String, Error> {
    struct BoundedWriter {
        bytes: Vec<u8>,
        limit: usize,
        exceeded: bool,
    }

    impl Write for BoundedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.exceeded || self.bytes.len().saturating_add(bytes.len()) > self.limit {
                self.exceeded = true;
                return Err(io::Error::other("XML output byte limit exceeded"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        limit,
        exceeded: false,
    };
    if let Err(error) = doc.write_to(&mut writer) {
        return Err(if writer.exceeded {
            exceeded("output bytes")
        } else {
            Error::XmlStructure(format!("XML serialization failed: {error}"))
        });
    }
    String::from_utf8(writer.bytes).map_err(|error| Error::XmlStructure(error.to_string()))
}

// Count exactly the text shape consumed by text_content_deep, stacklessly.
fn expression_text_bytes(
    doc: &Document<'_>,
    root: uppsala::NodeId,
    work: &mut usize,
) -> Result<usize, Error> {
    let mut current = doc.children_iter(root).next();
    let mut bytes = 0usize;
    while let Some(id) = current {
        *work = work.saturating_add(1);
        if *work > MAX_WORK {
            return Err(exceeded("expression traversal work"));
        }
        if let Some(NodeKind::Text(text) | NodeKind::CData(text)) = doc.node_kind(id) {
            bytes = bytes.saturating_add(text.len());
            if bytes > MAX_EXPRESSION_BYTES {
                return Err(exceeded("expression bytes"));
            }
        }
        if let Some(child) = doc.children_iter(id).next() {
            current = Some(child);
            continue;
        }
        let mut cursor = id;
        loop {
            if let Some(sibling) = doc.next_sibling(cursor) {
                current = Some(sibling);
                break;
            }
            match doc.parent(cursor) {
                Some(parent) if parent != root => cursor = parent,
                _ => {
                    current = None;
                    break;
                }
            }
        }
    }
    Ok(bytes)
}

/// Validate caller-built DOMs iteratively before recursive security consumers.
///
/// Budgets bound retained content and structural work; they are not a deadline
/// guarantee. Input parsing retains Uppsala's entity/depth protections.
pub fn validate_document(doc: &Document<'_>) -> Result<(), Error> {
    validate_document_with_budgets(doc, MAX_OUTPUT_BYTES, MAX_WORK)
}

fn qname_bytes(name: &QName<'_>) -> usize {
    name.local_name
        .len()
        .saturating_add(name.prefix.as_ref().map_or(0, |prefix| prefix.len()))
        .saturating_add(name.namespace_uri.as_ref().map_or(0, |uri| uri.len()))
}

fn validate_document_with_budgets(
    doc: &Document<'_>,
    max_bytes: usize,
    max_work: usize,
) -> Result<(), Error> {
    let mut current = Some(doc.root());
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut bytes = doc.doctype.as_ref().map_or(0, |doctype| doctype.len());
    if let Some(declaration) = &doc.xml_declaration {
        bytes = bytes
            .saturating_add(declaration.version.len())
            .saturating_add(
                declaration
                    .encoding
                    .as_ref()
                    .map_or(0, |encoding| encoding.len()),
            );
    }
    let mut signatures = 0usize;
    let mut references = 0usize;
    let mut certificates = 0usize;
    let mut transforms = 0usize;
    let mut expression_bytes = 0usize;
    let mut expression_work = 0usize;
    while let Some(id) = current {
        nodes += 1;
        if nodes > MAX_NODES {
            return Err(exceeded("nodes"));
        }
        if depth > MAX_DEPTH {
            return Err(exceeded("depth"));
        }
        match doc.node_kind(id) {
            Some(NodeKind::Element(element)) => {
                if element.attributes.len() + element.namespace_declarations.len() > MAX_ATTRIBUTES
                {
                    return Err(exceeded("attributes/namespaces"));
                }
                bytes = bytes.saturating_add(qname_bytes(&element.name));
                for attribute in &element.attributes {
                    bytes = bytes
                        .saturating_add(qname_bytes(&attribute.name))
                        .saturating_add(attribute.value.len());
                }
                for (prefix, uri) in &element.namespace_declarations {
                    bytes = bytes.saturating_add(prefix.len()).saturating_add(uri.len());
                }
                let namespace = element.name.namespace_uri.as_deref().unwrap_or("");
                let name = element.name.local_name.as_ref();
                if namespace == ns::DSIG {
                    match name {
                        "Signature" => signatures += 1,
                        "Reference" => references += 1,
                        _ => {}
                    }
                }
                // Inline certificate extraction accepts legacy unqualified and
                // local-name certificate children too; all share the cap.
                if name == "X509Certificate" {
                    certificates += 1;
                }
                // DSig transform dispatch accepts children by local name.
                if name == "Transform" {
                    transforms += 1;
                }
                if matches!(name, "XPath" | "XPointer") {
                    // Backend extraction consumes descendant text. Count it
                    // without allocating a deep string, including nested nodes.
                    let length = expression_text_bytes(doc, id, &mut expression_work)?;
                    expression_bytes = expression_bytes.saturating_add(length);
                }
            }
            Some(NodeKind::Text(text) | NodeKind::CData(text) | NodeKind::Comment(text)) => {
                bytes = bytes.saturating_add(text.len())
            }
            Some(NodeKind::ProcessingInstruction(pi)) => {
                bytes = bytes.saturating_add(pi.target.len());
                if let Some(data) = &pi.data {
                    bytes = bytes.saturating_add(data.len());
                }
            }
            _ => {}
        }
        if bytes > max_bytes {
            return Err(exceeded("expanded content bytes"));
        }
        if signatures > MAX_SECURITY_ITEMS
            || references > MAX_SECURITY_ITEMS
            || certificates > MAX_SECURITY_ITEMS
        {
            return Err(exceeded("signatures/references/certificates"));
        }
        if let Some(child) = doc.children_iter(id).next() {
            current = Some(child);
            depth += 1;
            continue;
        }
        let mut cursor = id;
        loop {
            if let Some(sibling) = doc.next_sibling(cursor) {
                current = Some(sibling);
                break;
            }
            if let Some(parent) = doc.parent(cursor) {
                cursor = parent;
                depth = depth.saturating_sub(1);
            } else {
                current = None;
                break;
            }
        }
    }
    let work = nodes.saturating_mul(
        references
            .saturating_add(transforms)
            .saturating_add(expression_bytes)
            .max(1),
    );
    if work > max_work {
        return Err(exceeded("reference/transform/expression work"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_structure_is_checked_before_dom_allocation() {
        assert!(validate_structure_before_parse("<r><a/></r>", 3, 2, 0).is_ok());
        let error = validate_structure_before_parse("<r><a/><b/>", 3, 2, 0).unwrap_err();
        assert!(error.to_string().contains("nodes"));
        let error = validate_structure_before_parse("<r><a><b/></a></r>", 4, 2, 0).unwrap_err();
        assert!(error.to_string().contains("depth"));
        assert!(validate_structure_before_parse("<r xmlns:p='urn:test' a='v'/>", 2, 1, 2).is_ok());
        let error =
            validate_structure_before_parse("<r xmlns:p='urn:test' a='v'/>", 2, 1, 1).unwrap_err();
        assert!(error.to_string().contains("attributes/namespaces"));
        assert!(validate_structure_before_parse("<r>A&amp;B&#32;C</r>", 3, 1, 0).is_ok());
    }

    #[test]
    fn all_qname_fields_and_document_metadata_share_the_content_budget() {
        for attribute in [false, true] {
            for namespace in [false, true] {
                let mut doc = uppsala::parse("<r a='v'/>").unwrap();
                let root = doc.document_element().unwrap();
                let element = doc.element_mut(root).unwrap();
                let name = if attribute {
                    &mut element.attributes[0].name
                } else {
                    &mut element.name
                };
                if namespace {
                    name.namespace_uri = Some("urn:longer:namespace".into());
                } else {
                    name.prefix = Some("longerPrefixThanBudget".into());
                }
                assert!(validate_document_with_budgets(&doc, 16, MAX_WORK)
                    .unwrap_err()
                    .to_string()
                    .contains("expanded content bytes"));
                assert!(validate_document_with_budgets(&doc, 64, MAX_WORK).is_ok());
            }
        }
        let doc = uppsala::parse("<!DOCTYPE r [<!ELEMENT r EMPTY>]><r/>").unwrap();
        assert!(validate_document_with_budgets(&doc, 16, MAX_WORK).is_err());
    }

    #[test]
    fn local_name_transforms_contribute_to_the_work_budget() {
        let doc =
            uppsala::parse("<r xmlns:t='urn:other'><t:Transform/><Transform/><n/></r>").unwrap();
        assert!(validate_document_with_budgets(&doc, MAX_OUTPUT_BYTES, 9)
            .unwrap_err()
            .to_string()
            .contains("work"));
        assert!(validate_document_with_budgets(&doc, MAX_OUTPUT_BYTES, 10).is_ok());
    }

    #[test]
    fn bounded_serialization_preserves_escaping_and_stops_at_the_exact_limit() {
        let doc = uppsala::parse("<r xmlns:p='urn:test' p:a='&amp;&quot;'>a&amp;b</r>").unwrap();
        let expected = doc.to_xml();
        assert_eq!(serialize_document(&doc).unwrap(), expected);
        assert_eq!(
            serialize_document_with_limit(&doc, expected.len()).unwrap(),
            expected
        );
        assert!(serialize_document_with_limit(&doc, expected.len() - 1)
            .unwrap_err()
            .to_string()
            .contains("output bytes"));
    }

    #[test]
    fn item_limits_apply_before_signature_processing() {
        let xml = format!(
            "<r xmlns:ds='{}'>{}</r>",
            ns::DSIG,
            "<ds:Reference/>".repeat(MAX_SECURITY_ITEMS + 1)
        );
        assert!(parse(&xml)
            .unwrap_err()
            .to_string()
            .contains("signatures/references/certificates"));
        let allowed = xml.replacen("<ds:Reference/>", "", 1);
        assert!(parse(&allowed).is_ok());
    }

    #[test]
    fn certificate_limit_covers_all_executed_namespaces_and_data_groups() {
        let xml = format!(
            "<r xmlns:x='urn:other'>{}</r>",
            "<X509Data><x:X509Certificate/></X509Data>".repeat(MAX_SECURITY_ITEMS + 1)
        );
        assert!(parse(&xml)
            .unwrap_err()
            .to_string()
            .contains("certificates"));
    }

    #[test]
    fn nested_expression_text_uses_the_same_byte_budget() {
        let xml = format!(
            "<r><XPath>A<part>{}</part>B</XPath></r>",
            "x".repeat(MAX_EXPRESSION_BYTES - 1)
        );
        assert!(parse(&xml)
            .unwrap_err()
            .to_string()
            .contains("expression bytes"));
        let xml = "<r><XPath>A<part>B<n>C</n>D</part>E</XPath></r>";
        let doc = parse(xml).unwrap();
        let xpath = doc
            .children_iter(doc.document_element().unwrap())
            .next()
            .unwrap();
        assert_eq!(expression_text_bytes(&doc, xpath, &mut 0).unwrap(), 5);
    }

    #[test]
    fn source_and_attribute_budgets_are_finite() {
        assert!(validate_input_size(MAX_INPUT_BYTES).is_ok());
        assert!(validate_input_size(MAX_INPUT_BYTES + 1).is_err());
        let attrs = (0..MAX_ATTRIBUTES + 1)
            .map(|n| format!(" a{n}='v'"))
            .collect::<String>();
        assert!(parse(&format!("<r{attrs}/> ")).is_err());
    }

    #[test]
    fn expression_work_budget_is_checked_without_execution() {
        let xml = format!(
            "<r><XPath>{}</XPath></r>",
            "x".repeat(MAX_EXPRESSION_BYTES + 1)
        );
        assert!(parse(&xml).is_err());
        let xml = format!(
            "<r><XPath>{}</XPath>{}</r>",
            "x".repeat(1000),
            "<n/>".repeat(10_001)
        );
        assert!(parse(&xml).unwrap_err().to_string().contains("work"));
    }
}
