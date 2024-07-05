use rasn_snmp as model;
use std::{net::{SocketAddr, Ipv4Addr}, str::FromStr, fmt::Display};
use tokio::net::UdpSocket;

pub use rasn::types::OctetString;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectIdentifier(rasn::types::ObjectIdentifier);

impl ObjectIdentifier {

  fn starts_with(&self, prefix: &ObjectIdentifier) -> bool {
    self.0.starts_with(prefix.0.as_ref())
  }
}

impl Display for ObjectIdentifier {

  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut first = true;
    for segment in self.0.iter() {
      if first {
        first = false;
        write!(f, "{}", segment)?;
      } else {
        write!(f, ".{}", segment)?;
      }
    }
    Ok(())
  }
}

impl FromStr for ObjectIdentifier {
  type Err = Error;

  // TODO: rewrite so that it is safe
  fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
    let x = s.split(".")
      .map(|segment| segment.parse::<u32>().unwrap())
      .collect::<Vec<u32>>();
    Ok(ObjectIdentifier(rasn::types::ObjectIdentifier::new_unchecked(x.into())))
  }
}

#[derive(Debug, Clone, Hash)]
pub enum ObjectValue {
  Integer(rasn::types::Integer),
  OctetString(rasn::types::OctetString),
  ObjectIdentifier(ObjectIdentifier),
  Integer32(i32),
  IpAddress(Ipv4Addr),
  Counter32(u32),
  Unsigned32(u32),
  TimeTicks(u32),
  Opaque(Vec<u8>),
  Counter64(u64),
}

pub struct VariableBinding {
  pub object_id: ObjectIdentifier,
  pub value: ObjectValue,
}

#[derive(Clone, Debug)]
pub enum Target {
  Community {
    address: SocketAddr,
    community: OctetString,
  },
}

impl Target {

  fn get_address(&self) -> &SocketAddr {
    match self {
      Target::Community { address, .. } => address,
    }
  }
}

#[derive(Debug)]
pub enum Error {
  Connection(),
  Serialization(),
}

impl Display for Error { // TODO: write better error descriptions

  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Error::Connection() => write!(f, "Connection problem."),
      Error::Serialization() => write!(f, "Serialization problem."),
    }
  }
}

pub async fn get(
  target: &Target,
  oids: &Vec<ObjectIdentifier>,
) -> Result<Vec<VariableBinding>> {
  let socket = UdpSocket::bind("[::]:0")
    .await
    .map_err(|io_error| Error::Connection())?;
  let message = match target {
    Target::Community { community, .. } => model::v2c::Message {
      version: 1.into(), // TODO
      community: community.clone(),
      data: model::v2::GetRequest(
        model::v2::Pdu {
          request_id: 1,
          error_status: model::v2::Pdu::ERROR_STATUS_NO_ERROR,
          error_index: 0,
          variable_bindings: oids.iter()
            .map(|oid| model::v2::VarBind {
              name: oid.0.clone(),
              value: model::v2::VarBindValue::Unspecified,
            })
            .collect(),
        }
      ),
    },
  };
  let serialized_message = rasn::ber::encode(&message)
    .map_err(|encode_error| Error::Serialization())?;
  socket.send_to(&serialized_message, target.get_address()) // TODO: check sent bytes count
    .await
    .map_err(|io_error| Error::Connection())?;
  let mut response_buffer = [0; 1024];
  let (byte_count, origin) = socket.recv_from(&mut response_buffer)
    .await
    .map_err(|io_error| Error::Connection())?;
  let response = match target {
    Target::Community { .. } => rasn::ber::decode::<model::v2c::Message<model::v2::Response>>(&response_buffer)
      .map_err(|decode_error| Error::Serialization())?,
  };
  Ok(
    response.data.0.variable_bindings.iter()
      .map(|binding| VariableBinding {
        object_id: ObjectIdentifier(binding.name.clone()),
        value: convert(&binding.value),
      })
      .collect()
  )
}

pub async fn get_bulk(
  target: &Target,
  oid: &ObjectIdentifier,
) -> Result<Vec<VariableBinding>> {
  let socket = UdpSocket::bind("[::]:0")
    .await
    .map_err(|io_error| Error::Connection())?;
  let message = match target {
    Target::Community { community, .. } => model::v2c::Message {
      version: 1.into(), // TODO
      community: community.clone(),
      data: model::v2::GetBulkRequest(
        model::v2::BulkPdu {
          request_id: 1,
          non_repeaters: 0,
          max_repetitions: 20, // TODO: should be configurable
          variable_bindings: vec![
            model::v2::VarBind {
              name: oid.0.clone(),
              value: model::v2::VarBindValue::Unspecified,
            },
          ],
        }
      ),
    },
  };
  println!("SNMP Request: {:?}", message);
  let serialized_message = rasn::ber::encode(&message)
    .map_err(|encode_error| Error::Serialization())?;
  socket.send_to(&serialized_message, target.get_address()) // TODO: check sent bytes count
    .await
    .map_err(|io_error| Error::Connection())?;
  let mut response_buffer = [0; 2048];
  let (byte_count, origin) = socket.recv_from(&mut response_buffer)
    .await
    .map_err(|io_error| Error::Connection())?;
  println!("Binary response [{:?}]: {:?}", byte_count, response_buffer);
  let response = match target {
    Target::Community { .. } => rasn::ber::decode::<model::v2c::Message<model::v2::Response>>(&response_buffer)
      .map_err(|decode_error| Error::Serialization())?,
  };
  println!("SNMP Response: {:?}", response);
  Ok(
    response.data.0.variable_bindings.iter()
      .map(|binding| VariableBinding {
        object_id: ObjectIdentifier(binding.name.clone()),
        value: convert(&binding.value),
      })
      .filter(|binding| binding.object_id.starts_with(oid))
      .collect()
  )
}

fn convert(value: &model::v2::VarBindValue) -> ObjectValue {
  match value {
    model::v3::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::Simple(value)) =>
      match value {
        rasn_smi::v2::SimpleSyntax::Integer(value) =>
          ObjectValue::Integer(value.clone()),
        rasn_smi::v2::SimpleSyntax::String(value) =>
          ObjectValue::OctetString(value.clone()),
        rasn_smi::v2::SimpleSyntax::ObjectId(value) =>
          ObjectValue::ObjectIdentifier(ObjectIdentifier(value.clone())),
      },
    model::v3::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::ApplicationWide(value)) =>
      match value {
        // TODO: find a proper way to do this
        rasn_smi::v2::ApplicationSyntax::Address(value) => {
          let [o0, o1, o2, o3] = value.0.map(|octet| octet);
          ObjectValue::IpAddress(Ipv4Addr::new(o0, o1, o2, o3))
        },
        rasn_smi::v2::ApplicationSyntax::Counter(value) =>
          ObjectValue::Counter32(value.0),
        rasn_smi::v2::ApplicationSyntax::Ticks(value) =>
          ObjectValue::TimeTicks(value.0),
        rasn_smi::v2::ApplicationSyntax::Arbitrary(value) =>
          ObjectValue::Opaque(value.as_ref().to_vec()),
        rasn_smi::v2::ApplicationSyntax::BigCounter(value) =>
          ObjectValue::Counter64(value.0),
        rasn_smi::v2::ApplicationSyntax::Unsigned(value) =>
          ObjectValue::Unsigned32(value.0),
      },
    model::v3::VarBindValue::Unspecified => todo!(),
    model::v3::VarBindValue::NoSuchObject => todo!(),
    model::v3::VarBindValue::NoSuchInstance => todo!(),
    model::v3::VarBindValue::EndOfMibView => todo!(),
}
}
