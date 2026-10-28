//! Stream cached graph records before retaining the existing matcher projection.
//! The cache schema and the lossless node/edge records stay unchanged.
use super::{FileRecord, GraphEdge, GraphNode, IndexedFile, SemanticGraph, Unit};
use serde::{
    de::{DeserializeOwned, DeserializeSeed, Error, MapAccess, SeqAccess, Visitor},
    ser::SerializeMap, Deserializer, Serialize, Serializer,
};
use std::{fmt, io::Write, marker::PhantomData};


// Keep the historical Value serializer's sorted keys without allocating a
// second JSON tree (and copying every string/token) for each graph record.
pub(crate) trait GraphRecord {
    const KIND: &'static str;
    fn serialize_sorted<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>;
}
impl GraphRecord for GraphNode {
    const KIND: &'static str = "node";
    fn serialize_sorted<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(10))?;
        map.serialize_entry("end", &self.end)?;
        map.serialize_entry("file", &self.file)?;
        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("kind", &self.kind)?;
        map.serialize_entry("label", &self.label)?;
        map.serialize_entry("line", &self.line)?;
        map.serialize_entry("linkedSha256", &self.linked_sha256)?;
        map.serialize_entry("scope", &self.scope)?;
        map.serialize_entry("start", &self.start)?;
        map.serialize_entry("tokens", &self.tokens)?;
        map.end()
    }
}
impl GraphRecord for GraphEdge {
    const KIND: &'static str = "edge";
    fn serialize_sorted<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(4 + usize::from(self.label.is_some())))?;
        map.serialize_entry("dynamic", &self.dynamic)?;
        map.serialize_entry("kind", &self.kind)?;
        if let Some(label) = &self.label {
            map.serialize_entry("label", label)?;
        }
        map.serialize_entry("source", &self.source)?;
        map.serialize_entry("target", &self.target)?;
        map.end()
    }
}
struct SortedRecord<'a, T>(&'a T);
impl<T: GraphRecord> Serialize for SortedRecord<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize_sorted(serializer)
    }
}
struct RecordEnvelope<'a, T> {
    record: &'a T,
    side: &'a str,
}
impl<T: GraphRecord> Serialize for RecordEnvelope<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry(T::KIND, &SortedRecord(self.record))?;
        map.serialize_entry("recordType", T::KIND)?;
        map.serialize_entry("side", self.side)?;
        map.end()
    }
}
pub(crate) fn write_graph_record<T: GraphRecord>(
    sink: &mut dyn Write,
    side: &str,
    record: &T,
) -> serde_json::Result<()> {
    serde_json::to_writer(&mut *sink, &RecordEnvelope { record, side })?;
    sink.write_all(b"\n").map_err(serde_json::Error::io)
}

pub(crate) struct CacheSeed<'a> {
    pub nodes: &'a mut dyn Write,
    pub edges: &'a mut dyn Write,
    pub side: &'a str,
    pub compact: bool,
    pub retain_edges: bool,
}
impl<'de> DeserializeSeed<'de> for CacheSeed<'_> {
    type Value = IndexedFile;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for CacheSeed<'_> {
    type Value = IndexedFile;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an indexed file")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let (mut record, mut units, mut graph) = (None, None, None);
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "record" if record.is_none() => record = Some(map.next_value::<FileRecord>()?),
                "units" if units.is_none() => units = Some(map.next_value_seed(UnitRecords {
                    dependency: self.side == "dependency",
                })?),
                "graph" if graph.is_none() => {
                    graph = Some(map.next_value_seed(GraphSeed {
                        nodes: &mut *self.nodes,
                        edges: &mut *self.edges,
                        side: self.side,
                        compact: self.compact,
                        retain_edges: self.retain_edges,
                    })?)
                }
                "record" | "units" | "graph" => {
                    return Err(M::Error::custom("duplicate indexed file field"))
                }
                _ => {
                    let _ = map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
        }
        Ok(IndexedFile {
            record: record.ok_or_else(|| M::Error::missing_field("record"))?,
            units: units.ok_or_else(|| M::Error::missing_field("units"))?,
            graph: graph.ok_or_else(|| M::Error::missing_field("graph"))?,
        })
    }
}
// Dependency matching already discards these features after loading a file.
// Release them per record so a large cache never retains every unit's scratch.
struct UnitRecords {
    dependency: bool,
}
impl<'de> DeserializeSeed<'de> for UnitRecords {
    type Value = Vec<Unit>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for UnitRecords {
    type Value = Vec<Unit>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("indexed units")
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let mut units = Vec::new();
        while let Some(mut unit) = seq.next_element::<Unit>()? {
            if self.dependency {
                super::release_dependency_unit_features(std::slice::from_mut(&mut unit));
            }
            units.push(unit);
        }
        Ok(units)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dependency_unit_stream_preserves_identity_and_application_features() {
        let source = r#"[{"id":"unit","file":"npm/helper.js","kind":"Function","name":"helper","start":1,"end":9,"line":2,"origin":null,"nodesApprox":3,"strictSha256":"strict","linkedSha256":"linked","tokens":["one","two"],"features":{"shape":{"call":2},"ordered":{},"literals":{},"operators":{},"properties":{},"externals":{}}}]"#;
        let original: Vec<Unit> = serde_json::from_str(source).unwrap();
        for dependency in [false, true] {
            let actual = UnitRecords { dependency }
                .deserialize(&mut serde_json::Deserializer::from_str(source)).unwrap();
            let mut expected = original.clone();
            if dependency { super::super::release_dependency_unit_features(&mut expected); }
            assert_eq!(serde_json::to_value(actual).unwrap(), serde_json::to_value(expected).unwrap());
        }
    }
}
struct GraphSeed<'a> {
    nodes: &'a mut dyn Write,
    edges: &'a mut dyn Write,
    side: &'a str,
    compact: bool,
    retain_edges: bool,
}
impl<'de> DeserializeSeed<'de> for GraphSeed<'_> {
    type Value = SemanticGraph;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_map(self)
    }
}
fn keep_node(mut node: GraphNode) -> Option<GraphNode> {
    if (node.kind.ends_with("Site") && node.kind != "CallSite") || node.kind == "MemberAccess" {
        return None;
    }
    if !matches!(node.kind.as_str(), "Statement" | "Function" | "Arrow") {
        node.tokens.clear();
    }
    Some(node)
}
fn discard<T>(_: T) -> Option<T> { None }
fn identity<T>(record: T) -> Option<T> {
    Some(record)
}
impl<'de> Visitor<'de> for GraphSeed<'_> {
    type Value = SemanticGraph;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a semantic graph")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let (mut nodes, mut edges) = (None, None);
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "nodes" if nodes.is_none() => {
                    nodes = Some(map.next_value_seed(Records {
                        sink: &mut *self.nodes,
                        side: self.side,
                        project: if self.compact { keep_node } else { identity },
                        marker: PhantomData,
                    })?)
                }
                "edges" if edges.is_none() => {
                    edges = Some(map.next_value_seed(Records::<GraphEdge> {
                        sink: &mut *self.edges,
                        side: self.side,
                        project: if self.retain_edges { identity } else { discard },
                        marker: PhantomData,
                    })?)
                }
                "nodes" | "edges" => return Err(M::Error::custom("duplicate graph field")),
                _ => {
                    let _ = map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
        }
        let nodes = nodes.ok_or_else(|| M::Error::missing_field("nodes"))?;
        let edges = edges.ok_or_else(|| M::Error::missing_field("edges"))?;
        let mut graph = SemanticGraph { nodes, edges };
        if self.compact {
            super::compact_semantic_graph(&mut graph);
        }
        Ok(graph)
    }
}
struct Records<'a, T> {
    sink: &'a mut dyn Write,
    side: &'a str,
    project: fn(T) -> Option<T>,
    marker: PhantomData<T>,
}
impl<'de, T: DeserializeOwned + GraphRecord> DeserializeSeed<'de> for Records<'_, T> {
    type Value = Vec<T>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_seq(self)
    }
}
impl<'de, T: DeserializeOwned + GraphRecord> Visitor<'de> for Records<'_, T> {
    type Value = Vec<T>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("graph records")
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let mut kept = Vec::new();
        while let Some(record) = seq.next_element::<T>()? {
            write_graph_record(&mut *self.sink, self.side, &record)
                .map_err(S::Error::custom)?;
            if let Some(record) = (self.project)(record) {
                kept.push(record);
            }
        }
        Ok(kept)
    }
}
