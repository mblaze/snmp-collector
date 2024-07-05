use std::{net::{IpAddr, SocketAddr}, collections::HashMap};

use serde::{de, Deserialize, Serialize, ser::SerializeStruct};
use warp::Filter;

use crate::snmp;

pub async fn serve() {
  let agent = warp::path("agents")
    .and(warp::path::param::<IpAddr>());
  let snmp_request = agent.and(warp::path("request"))
    .and(warp::post())
    .and(warp::body::json::<SnmpRequest>())
    .and_then(handle_snmp_request);
  let routes = snmp_request;
  warp::serve(routes).run(([127, 0, 0, 1], 8080)).await
}

async fn handle_snmp_request(
  ip_address: IpAddr,
  request: SnmpRequest,
) -> Result<warp::reply::Json, warp::reject::Rejection> {
  let target = snmp::Target::Community {
    address: SocketAddr::new(ip_address, 161),
    community: "vitalumos".into(),
  };
  let bindings = match request {
    SnmpRequest::Get { oids } => {
      snmp::get(&target, &oids)
        .await
        .map_err(|snmp_error| warp::reject::not_found())? // TODO: better error handling
    },
    SnmpRequest::GetBulk { oid } => {
      snmp::get_bulk(&target, &oid)
        .await
        .map_err(|snmp_error| warp::reject::not_found())? // TODO: better error handling
    },
  };
  let response: GetResponse = GetResponse(
    bindings.iter()
      .map(|snmp::VariableBinding { object_id, value }| (object_id.clone(), value.clone()))
      .collect::<HashMap<snmp::ObjectIdentifier, snmp::ObjectValue>>()
  );
  Ok(warp::reply::json(&response))
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "requestType")]
pub enum SnmpRequest {
  Get {
    // agent_configuration: String,
    oids: Vec<snmp::ObjectIdentifier>,
  },
  GetBulk {
    oid: snmp::ObjectIdentifier,
  },
}

#[derive(Serialize)]
struct GetResponse(HashMap<snmp::ObjectIdentifier, snmp::ObjectValue>);

impl Serialize for snmp::ObjectIdentifier {

  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer
  {
    serializer.serialize_str(self.to_string().as_str())
  }
}

impl<'de> Deserialize<'de> for snmp::ObjectIdentifier {

  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'de>
  {
    let oid_text = String::deserialize(deserializer)?;
    oid_text.parse().map_err(de::Error::custom)
  }
}

impl Serialize for snmp::ObjectValue {

  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer
  {
    let mut obj = serializer.serialize_struct("ObjectValue", 2)?;
    match self {
      snmp::ObjectValue::Integer(value) => {
        // obj.serialize_field("syntax", "Integer")?;
        // obj.serialize_field("value", value.to_bytes_be())?; // TODO: this might be wrong
      },
      snmp::ObjectValue::OctetString(value) => {
        obj.serialize_field("syntax", "OctetString")?;
        obj.serialize_field("value", &(String::from_utf8(value.to_vec()).unwrap()))?;
      },
      snmp::ObjectValue::ObjectIdentifier(value) => {
        obj.serialize_field("syntax", "ObjectIdentifier")?;
        obj.serialize_field("value", &(value.to_string()))?;
      },
      snmp::ObjectValue::Integer32(value) => {
        obj.serialize_field("syntax", "Integer32")?;
        obj.serialize_field("value", value)?;
      },
      snmp::ObjectValue::IpAddress(value) => {
        obj.serialize_field("syntax", "IpAddress")?;
        obj.serialize_field("value", &(value.to_string()))?;
      },
      snmp::ObjectValue::Counter32(value) => {
        obj.serialize_field("syntax", "Counter32")?;
        obj.serialize_field("value", value)?;
      },
      snmp::ObjectValue::Unsigned32(value) => {
        obj.serialize_field("syntax", "Unsigned32")?;
        obj.serialize_field("value", value)?;
      },
      snmp::ObjectValue::TimeTicks(value) => {
        obj.serialize_field("syntax", "TimeTicks")?;
        obj.serialize_field("value", value)?;
      },
      snmp::ObjectValue::Opaque(value) => {
        obj.serialize_field("syntax", "Opaque")?;
        obj.serialize_field("value", value)?;
      },
      snmp::ObjectValue::Counter64(value) => {
        obj.serialize_field("syntax", "Counter64")?;
        obj.serialize_field("value", value)?;
      },
    }
    obj.end()
  }
}
