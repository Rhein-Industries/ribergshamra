#![forbid(unsafe_code)]

//! Transform pipeline and trait definitions.

use ribergshamra_core::Error;
use ribergshamra_xml::NodeSet;
use std::borrow::Cow;

/// Default maximum number of transforms executed for one input.
///
/// This bounds the length of a transform chain. Individual transform work and
/// output size still depend on the transform implementation and input data.
pub const DEFAULT_MAX_TRANSFORMS: usize = 32;

/// Reject a transform chain whose length exceeds the selected limit.
///
/// A zero limit permits only an empty chain. XML signature and encryption
/// callers use this helper before applying document-selected transforms.
pub fn validate_transform_count(count: usize, limit: usize) -> Result<(), Error> {
    if count > limit {
        return Err(Error::Transform(format!(
            "transform count {count} exceeds limit {limit}"
        )));
    }
    Ok(())
}

/// Data flowing through the transform pipeline.
///
/// XML Signature transforms operate either on an XML node-set or on an octet
/// stream. XML node-set data carries the source XML plus an optional [`NodeSet`]
/// that restricts which parsed nodes are visible to XML-aware transforms.
///
/// The lifetime parameter lets same-document references borrow the caller's
/// input buffer instead of cloning a full XML string. Transforms that parse
/// binary data as XML use [`TransformData::xml_owned`] because the decoded
/// string must live with the returned transform data.
pub enum TransformData<'a> {
    /// XML node set (for XML-aware transforms like C14N).
    Xml {
        /// The source XML text that owns the bytes parsed by downstream XML
        /// transforms. Same-document references borrow the caller's XML buffer;
        /// binary-to-XML conversions own the decoded string.
        xml_text: Cow<'a, str>,
        /// Optional node-set subset selected by earlier transforms. `None`
        /// means the whole parsed document is visible.
        node_set: Option<NodeSet>,
    },
    /// Raw binary data.
    Binary(Vec<u8>),
}

impl<'a> TransformData<'a> {
    /// Create XML transform data that borrows an existing XML string.
    ///
    /// Use this for same-document references where the original XML buffer
    /// outlives the transform pipeline. No copy of the XML text is made.
    pub fn xml_borrowed(xml_text: &'a str, node_set: Option<NodeSet>) -> Self {
        Self::Xml {
            xml_text: Cow::Borrowed(xml_text),
            node_set,
        }
    }

    /// Create XML transform data that owns its XML string.
    ///
    /// Use this when a transform created XML text from owned bytes, for example
    /// after parsing a binary octet stream as UTF-8 XML.
    pub fn xml_owned(xml_text: String, node_set: Option<NodeSet>) -> Self {
        Self::Xml {
            xml_text: Cow::Owned(xml_text),
            node_set,
        }
    }

    /// Convert the transform data to binary bytes.
    ///
    /// Binary data is cloned and returned as-is. XML data is canonicalized with
    /// inclusive C14N without comments, matching the XML-DSig default conversion
    /// from node-set data to octets when the transform chain ends before an
    /// explicit C14N transform.
    pub fn to_binary(&self) -> Result<Vec<u8>, Error> {
        match self {
            TransformData::Binary(data) => Ok(data.clone()),
            TransformData::Xml { xml_text, node_set } => {
                // Default: inclusive C14N without comments
                let mode = ribergshamra_c14n::C14nMode::Inclusive;
                ribergshamra_c14n::canonicalize(
                    xml_text.as_ref(),
                    mode,
                    node_set.as_ref(),
                    &[] as &[String],
                )
            }
        }
    }
}

/// Trait for individual transforms.
pub trait Transform: Send {
    /// The algorithm URI for this transform.
    fn uri(&self) -> &str;

    /// Execute the transform on the given data.
    ///
    /// The returned value keeps the same XML lifetime as `input`: transforms may
    /// narrow node sets, convert XML to binary, or create owned XML from binary,
    /// but they must not return borrowed XML that outlives the input buffer.
    fn execute<'a>(&self, input: TransformData<'a>) -> Result<TransformData<'a>, Error>;
}

/// A pipeline of transforms executed in sequence.
pub struct TransformPipeline {
    transforms: Vec<Box<dyn Transform>>,
}

impl TransformPipeline {
    /// Create an empty pipeline.
    pub fn new() -> Self {
        Self {
            transforms: Vec::new(),
        }
    }

    /// Add a transform to the pipeline.
    pub fn push(&mut self, transform: Box<dyn Transform>) {
        self.transforms.push(transform);
    }

    /// Execute all transforms in order.
    ///
    /// Rejects chains longer than [`DEFAULT_MAX_TRANSFORMS`] before executing
    /// any transform. Trusted callers needing another chain length can use
    /// [`Self::execute_with_limit`].
    ///
    /// Borrowed XML input remains borrowed across the pipeline until a transform
    /// converts it to binary or creates a new owned XML buffer.
    pub fn execute<'a>(&self, input: TransformData<'a>) -> Result<TransformData<'a>, Error> {
        self.execute_with_limit(input, DEFAULT_MAX_TRANSFORMS)
    }

    /// Execute the pipeline after checking its length against `max_transforms`.
    ///
    /// The check happens before any transform runs. This count limit does not
    /// bound the work or output size of an individual transform.
    pub fn execute_with_limit<'a>(
        &self,
        input: TransformData<'a>,
        max_transforms: usize,
    ) -> Result<TransformData<'a>, Error> {
        validate_transform_count(self.transforms.len(), max_transforms)?;
        let mut data = input;
        validate_data_size(&data)?;
        for transform in &self.transforms {
            data = transform.execute(data)?;
            validate_data_size(&data)?;
        }
        Ok(data)
    }

    /// Number of transforms in the pipeline.
    pub fn len(&self) -> usize {
        self.transforms.len()
    }

    /// Check if pipeline is empty.
    pub fn is_empty(&self) -> bool {
        self.transforms.is_empty()
    }
}

fn validate_data_size(data: &TransformData<'_>) -> Result<(), Error> {
    let size = match data {
        TransformData::Xml { xml_text, .. } => xml_text.len(),
        TransformData::Binary(bytes) => bytes.len(),
    };
    ribergshamra_xml::limits::validate_output_size(size)
}

impl Default for TransformPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ── C14N Transform ───────────────────────────────────────────────────

/// A canonicalization transform.
pub struct C14nTransform {
    mode: ribergshamra_c14n::C14nMode,
    inclusive_prefixes: Vec<String>,
}

impl C14nTransform {
    /// Create a canonicalization transform for `mode`.
    ///
    /// `inclusive_prefixes` is used only for exclusive canonicalization, where
    /// it represents the `ec:InclusiveNamespaces` `PrefixList` entries. Pass an
    /// empty vector for inclusive C14N modes.
    pub fn new(mode: ribergshamra_c14n::C14nMode, inclusive_prefixes: Vec<String>) -> Self {
        Self {
            mode,
            inclusive_prefixes,
        }
    }
}

impl Transform for C14nTransform {
    fn uri(&self) -> &str {
        self.mode.uri()
    }

    fn execute<'a>(&self, input: TransformData<'a>) -> Result<TransformData<'a>, Error> {
        match input {
            TransformData::Xml { xml_text, node_set } => {
                let bytes = ribergshamra_c14n::canonicalize(
                    xml_text.as_ref(),
                    self.mode,
                    node_set.as_ref(),
                    &self.inclusive_prefixes,
                )?;
                Ok(TransformData::Binary(bytes))
            }
            TransformData::Binary(data) => {
                // Parse XML, canonicalize
                let bytes = ribergshamra_c14n::canonicalize(
                    std::str::from_utf8(&data)
                        .map_err(|e| Error::Transform(format!("invalid UTF-8: {e}")))?,
                    self.mode,
                    None,
                    &self.inclusive_prefixes,
                )?;
                Ok(TransformData::Binary(bytes))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct CountingTransform(Arc<AtomicUsize>);

    impl Transform for CountingTransform {
        fn uri(&self) -> &str {
            "urn:synthetic:counting-transform"
        }

        fn execute<'a>(&self, input: TransformData<'a>) -> Result<TransformData<'a>, Error> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(input)
        }
    }

    fn counting_pipeline(count: usize) -> (TransformPipeline, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut pipeline = TransformPipeline::new();
        for _ in 0..count {
            pipeline.push(Box::new(CountingTransform(Arc::clone(&calls))));
        }
        (pipeline, calls)
    }

    #[test]
    fn pipeline_accepts_default_limit_and_preserves_data() {
        let (pipeline, calls) = counting_pipeline(DEFAULT_MAX_TRANSFORMS);
        let output = pipeline
            .execute(TransformData::Binary(b"synthetic input".to_vec()))
            .expect("boundary count is allowed");
        assert_eq!(calls.load(Ordering::Relaxed), DEFAULT_MAX_TRANSFORMS);
        assert_eq!(output.to_binary().unwrap(), b"synthetic input");
    }

    #[test]
    fn pipeline_rejects_excess_count_before_any_transform_runs() {
        let (pipeline, calls) = counting_pipeline(DEFAULT_MAX_TRANSFORMS + 1);
        let result = pipeline.execute(TransformData::Binary(Vec::new()));
        assert!(matches!(result, Err(Error::Transform(_))));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn trusted_pipeline_can_select_an_explicit_larger_limit() {
        let count = DEFAULT_MAX_TRANSFORMS + 1;
        let (pipeline, calls) = counting_pipeline(count);
        let output = pipeline
            .execute_with_limit(TransformData::Binary(b"synthetic input".to_vec()), count)
            .expect("explicit limit is allowed");
        assert_eq!(calls.load(Ordering::Relaxed), count);
        assert_eq!(output.to_binary().unwrap(), b"synthetic input");
    }

    #[test]
    fn zero_transform_limit_permits_only_an_empty_chain() {
        assert!(validate_transform_count(0, 0).is_ok());
        assert!(matches!(
            validate_transform_count(1, 0),
            Err(Error::Transform(_))
        ));
    }
}
