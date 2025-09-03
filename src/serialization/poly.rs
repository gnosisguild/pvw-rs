//! Poly serialization helpers
//!
//! This module provides custom serde implementations for fhe-math Poly types
//! by embedding the necessary context information directly in the serialized data.

use fhe_math::rq::{Context, Poly, Representation};
use fhe_traits::{Serialize as FheSerialize, DeserializeWithContext};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{self, Visitor, SeqAccess, MapAccess};
use std::fmt;


/// Serializable representation of a Poly that includes context information
/// We need custom serialization logic because:
/// - We're extracting context info from the `Poly`
/// - We're converting `Representation` enum to string
/// - We need error handling for context reconstruction
#[derive(Debug, Clone)]
struct PolyData {
    /// Serialized polynomial bytes from poly.to_bytes()
    bytes: Vec<u8>,
    /// Moduli used to create the context
    moduli: Vec<u64>,
    /// Polynomial degree (must be power of 2)
    degree: usize,
    /// Representation type (PowerBasis or Ntt)
    representation: String,
}

impl Serialize for PolyData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        
        let mut state = serializer.serialize_struct("PolyData", 4)?;
        state.serialize_field("bytes", &self.bytes)?;
        state.serialize_field("moduli", &self.moduli)?;
        state.serialize_field("degree", &self.degree)?;
        state.serialize_field("representation", &self.representation)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PolyData {
    fn deserialize<D>(deserializer: D) -> Result<PolyData, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field { Bytes, Moduli, Degree, Representation }

        struct PolyDataVisitor;

        impl<'de> Visitor<'de> for PolyDataVisitor {
            type Value = PolyData;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct PolyData")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<PolyData, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let bytes = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let moduli = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let degree = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let representation = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                Ok(PolyData { bytes, moduli, degree, representation })
            }

            fn visit_map<V>(self, mut map: V) -> Result<PolyData, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut bytes = None;
                let mut moduli = None;
                let mut degree = None;
                let mut representation = None;
                
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Bytes => {
                            if bytes.is_some() {
                                return Err(de::Error::duplicate_field("bytes"));
                            }
                            bytes = Some(map.next_value()?);
                        }
                        Field::Moduli => {
                            if moduli.is_some() {
                                return Err(de::Error::duplicate_field("moduli"));
                            }
                            moduli = Some(map.next_value()?);
                        }
                        Field::Degree => {
                            if degree.is_some() {
                                return Err(de::Error::duplicate_field("degree"));
                            }
                            degree = Some(map.next_value()?);
                        }
                        Field::Representation => {
                            if representation.is_some() {
                                return Err(de::Error::duplicate_field("representation"));
                            }
                            representation = Some(map.next_value()?);
                        }
                    }
                }
                
                let bytes = bytes.ok_or_else(|| de::Error::missing_field("bytes"))?;
                let moduli = moduli.ok_or_else(|| de::Error::missing_field("moduli"))?;
                let degree = degree.ok_or_else(|| de::Error::missing_field("degree"))?;
                let representation = representation.ok_or_else(|| de::Error::missing_field("representation"))?;
                
                Ok(PolyData { bytes, moduli, degree, representation })
            }
        }

        const FIELDS: &'static [&'static str] = &["bytes", "moduli", "degree", "representation"];
        deserializer.deserialize_struct("PolyData", FIELDS, PolyDataVisitor)
    }
}

impl PolyData {
    /// Create PolyData from a Poly
    fn from_poly(poly: &Poly) -> Self {
        let representation = match poly.representation() {
            Representation::PowerBasis => "PowerBasis".to_string(),
            Representation::Ntt => "Ntt".to_string(),
            Representation::NttShoup => "NttShoup".to_string(),
        };
        
        Self {
            bytes: poly.to_bytes(),           // ← Uses fhe.rs serialization
            moduli: poly.ctx.moduli.to_vec(), // ← Extract context info
            degree: poly.ctx.degree,          // ← Extract context info
            representation,                   // ← Convert enum to string
        }
    }
    
    /// Reconstruct a Poly from PolyData
    fn to_poly(&self) -> Result<Poly, Box<dyn std::error::Error>> {
        // Reconstruct the context
        let context = Context::new_arc(&self.moduli, self.degree)?;
        
        // Deserialize the polynomial  
        let poly = Poly::from_bytes(&self.bytes, &context)?;
        
        Ok(poly)
    }
}

/// Custom serde implementation for Poly
pub struct PolyWithContext;

impl PolyWithContext {
    /// Serialize a single Poly
    pub fn serialize<S>(poly: &Poly, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = PolyData::from_poly(poly);
        data.serialize(serializer)
    }
    
    /// Deserialize a single Poly
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Poly, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data: PolyData = PolyData::deserialize(deserializer)?;
        data.to_poly().map_err(de::Error::custom)
    }
}

/// Custom serde implementation for Vec<Poly>
pub struct VecPolyWithContext;

impl VecPolyWithContext {
    /// Serialize a Vec<Poly>
    pub fn serialize<S>(polys: &Vec<Poly>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let poly_data: Vec<PolyData> = polys.iter().map(PolyData::from_poly).collect();
        poly_data.serialize(serializer)
    }
    
    /// Deserialize a Vec<Poly>
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Poly>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let poly_data: Vec<PolyData> = Vec::deserialize(deserializer)?;
        poly_data
            .into_iter()
            .map(|data| data.to_poly().map_err(de::Error::custom))
            .collect()
    }
}

/// Custom serde implementation for Vec<Vec<Poly>> (for Array2 matrices)
pub struct VecVecPolyWithContext;

impl VecVecPolyWithContext {
    /// Serialize a Vec<Vec<Poly>>
    pub fn serialize<S>(matrix: &Vec<Vec<Poly>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let matrix_data: Vec<Vec<PolyData>> = matrix
            .iter()
            .map(|row| row.iter().map(PolyData::from_poly).collect())
            .collect();
        matrix_data.serialize(serializer)
    }
    
    /// Deserialize a Vec<Vec<Poly>>
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<Poly>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let matrix_data: Vec<Vec<PolyData>> = Vec::deserialize(deserializer)?;
        matrix_data
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|data| data.to_poly().map_err(de::Error::custom))
                    .collect()
            })
            .collect()
    }
}
