use crate::config::EnrichmentConfig;
use anyhow::{Context, Result, ensure};
use maxminddb::{Reader, geoip2};
use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Default, PartialEq, Serialize)]
pub struct GeoInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,
}

impl GeoInfo {
    fn from_city(city: geoip2::City<'_>) -> Option<Self> {
        fn text(value: Option<&str>) -> Option<String> {
            value
                .filter(|s| !s.is_empty() && *s != "-")
                .map(str::to_owned)
        }
        let geo = Self {
            country_code: text(city.country.iso_code),
            country_name: text(city.country.names.english),
            region_name: text(city.subdivisions.first().and_then(|s| s.names.english)),
            city_name: text(city.city.names.english),
            latitude: city
                .location
                .latitude
                .filter(|v| v.is_finite() && (-90.0..=90.0).contains(v)),
            longitude: city
                .location
                .longitude
                .filter(|v| v.is_finite() && (-180.0..=180.0).contains(v)),
            postal_code: text(city.postal.code),
            time_zone: text(city.location.time_zone),
        };
        (geo != Self::default()).then_some(geo)
    }
}

pub struct Enricher {
    reader: Reader<Vec<u8>>,
}

impl Enricher {
    pub fn open(config: &EnrichmentConfig) -> Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }
        let reader = Reader::open_readfile(&config.database_path).with_context(|| {
            format!(
                "opening enrichment database {}",
                config.database_path.display()
            )
        })?;
        ensure!(
            reader.metadata().database_type.ends_with("-City"),
            "enrichment requires a City-schema MMDB, such as IP2LOCATION-LITE-DB11.MMDB"
        );
        Ok(Some(Self { reader }))
    }

    pub fn lookup(&self, ip: IpAddr) -> Result<Option<GeoInfo>> {
        if ip.is_ipv6() && self.reader.metadata().ip_version == 4 {
            return Ok(None);
        }
        let record = self
            .reader
            .lookup(ip)
            .with_context(|| format!("MMDB lookup for {ip}"))?;
        let city = record
            .decode::<geoip2::City>()
            .with_context(|| format!("decoding MMDB entry for {ip}"))?;
        Ok(city.and_then(GeoInfo::from_city))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_records_and_missing_values() {
        let city = serde_json::from_str(r#"{"country":{"iso_code":"US","names":{"en":"United States"}},"city":{"names":{"en":"-"}},"location":{"latitude":0,"longitude":0}}"#).unwrap();
        let geo = GeoInfo::from_city(city).unwrap();
        assert_eq!(geo.country_code.as_deref(), Some("US"));
        assert!(geo.city_name.is_none());
        assert_eq!(geo.latitude, Some(0.0));
        assert!(GeoInfo::from_city(geoip2::City::default()).is_none());
        let json = serde_json::to_value(geo).unwrap();
        assert!(json.get("city_name").is_none());
    }
}
