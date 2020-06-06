use clap::{App, Arg};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serialport::prelude::*;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::TcpStream;
use std::process::exit;
use std::time::Duration;

mod modbus;

enum DeviceConnection {
    TTY(String),
    TCP(Ipv4Addr, u16),
}

#[derive(Debug)]
pub enum MappingValue {
    Bitfield(HashMap<String, bool>),
    Boolean(bool),
    Decimal(String),
    Float(f32),
    UnsignedInteger(u16),
    SignedInteger(i16),
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "snake_case")]
pub enum MappingEndianness {
    Big,
    Little,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MappingScale {
    pub factor: String,
    pub offset: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MappingProperties {
    pub endianness: Option<MappingEndianness>,
    pub scale: Option<MappingScale>,
    pub signed: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BitfieldProperties {
    pub endianness: Option<MappingEndianness>,
    pub fields: HashMap<String, u16>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Mapping {
    Bitfield {
        address: u16,
        count: u16,
        key: String,
        table: String,
        properties: BitfieldProperties,
    },
    Boolean {
        address: u16,
        count: u16,
        key: String,
        table: String,
        properties: Option<MappingProperties>,
    },
    Decimal {
        address: u16,
        count: u16,
        key: String,
        table: String,
        properties: Option<MappingProperties>,
        unit: Option<String>,
    },
    Float {
        address: u16,
        count: u16,
        key: String,
        table: String,
        properties: Option<MappingProperties>,
        unit: Option<String>,
    },
    Integer {
        address: u16,
        count: u16,
        key: String,
        table: String,
        properties: Option<MappingProperties>,
        unit: Option<String>,
    },
}

fn main() {
    let matches = App::new("modbus")
        .version("0.1")
        .author("Gabriel Malkas <gabriel@beaverlabs.net>")
        .about("CLI for Modbus RTU and Modbus TCP")
        .arg(
            Arg::with_name("register_definition_file")
                .short("r")
                .long("rdf")
                .value_name("RDF")
                .help("Specify path to register definitions file")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sampling_interval")
                .short("s")
                .long("sampling")
                .value_name("SAMPLING_INTERVAL")
                .help("Specify how often the register values are refreshed")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("baud_rate")
                .short("b")
                .long("baud")
                .value_name("BAUD_RATE")
                .help("Specify the baud rate of the TTY device")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("unit_id")
                .short("u")
                .long("unitid")
                .value_name("UNITID")
                .help("Specify the Modbus unit ID")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("protocol")
                .short("p")
                .long("protocol")
                .value_name("PROTOCOL")
                .help("Specify the protocol to use")
                .possible_values(&["rtu", "tcp"])
                .required(true),
        )
        .arg(
            Arg::with_name("mode")
                .short("m")
                .long("mode")
                .value_name("MODE")
                .help("Specify the mode to use")
                .possible_values(&["master", "slave"])
                .required(true),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .arg(
            Arg::with_name("device_path")
                .help("Specify how to access the device. Can be IP:Port or a TTY device file path.")
                .required(true)
                .index(1),
        )
        .get_matches();

    let device_path = matches.value_of("device_path").unwrap();
    let device_connection = parse_device_path(device_path);
    let protocol = match matches.value_of("protocol").unwrap() {
        "rtu" => modbus::Protocol::RTU,
        "tcp" => modbus::Protocol::TCP,
        _ => unreachable!(),
    };

    let mode = match matches.value_of("mode").unwrap() {
        "master" => modbus::Mode::Master,
        "slave" => modbus::Mode::Slave,
        _ => unreachable!(),
    };

    let unit_id = clap::value_t!(matches.value_of("unit_id"), u8).unwrap();

    let baud_rate: Option<u32> = match mode {
        modbus::Mode::Master => clap::value_t!(matches.value_of("baud_rate"), u32)
            .map(|v| Some(v))
            .unwrap_or(None),
        _ => None,
    };

    let sampling_interval: u8 =
        clap::value_t!(matches.value_of("sampling_interval"), u8).unwrap_or(1);

    let rdf = matches.value_of("register_definition_file").unwrap();
    let content = std::fs::read_to_string(rdf).unwrap();
    let mappings = serde_json::from_str::<Vec<Mapping>>(&content).unwrap();

    match protocol {
        modbus::Protocol::RTU => {
            if let DeviceConnection::TTY(device_path) = device_connection {
                let port_settings = SerialPortSettings {
                    baud_rate: baud_rate.unwrap(),
                    data_bits: DataBits::Eight,
                    flow_control: FlowControl::None,
                    parity: Parity::None,
                    stop_bits: StopBits::One,
                    timeout: Duration::from_millis(1000),
                };

                match serialport::open_with_settings(&device_path, &port_settings) {
                    Ok(mut serial_port) => {
                        let values: Vec<MappingValue> = mappings
                            .iter()
                            .map(|mapping| read_rtu_mapping(&mut serial_port, unit_id, mapping))
                            .collect();

                        println!("{:?}", values);
                    }
                    Err(error) => {
                        eprintln!("{}: {}", device_path, error);
                        exit(1);
                    }
                }
            }
        }
        modbus::Protocol::TCP => match mode {
            modbus::Mode::Master => {
                if let DeviceConnection::TCP(ip_addr, port) = device_connection {
                    sample_via_tcp(ip_addr, port, unit_id, &mappings, sampling_interval)
                }
            }
            _ => (),
        },
    }
}

fn to_value(mapping: &Mapping, values: &[u16]) -> MappingValue {
    match mapping {
        Mapping::Bitfield { properties, .. } => {
            let mut flags: HashMap<String, bool> = HashMap::with_capacity(properties.fields.len());
            let value = values[0];

            for (key, bitmask) in properties.fields.iter() {
                flags.insert(key.to_string(), value ^ bitmask == 1);
            }

            MappingValue::Bitfield(flags)
        }
        Mapping::Boolean { .. } => MappingValue::Boolean(values[0] == 1),
        Mapping::Decimal { properties, .. } => {
            let signed = properties
                .as_ref()
                .map(|properties| properties.signed.unwrap_or(false))
                .unwrap_or(false);

            let scale = properties
                .as_ref()
                .map(|properties| properties.scale.as_ref());

            let factor = if let Some(Some(value)) = scale {
                &value.factor
            } else {
                "1"
            };

            let bytes = [(values[0] & 0xff00 >> 8) as u8, (values[0] & 0x00ff) as u8];

            let value = if signed {
                let value = i16::from_be_bytes(bytes);
                Decimal::new(value as i64, to_scale(factor))
            } else {
                let value = u16::from_be_bytes(bytes);
                Decimal::new(value as i64, to_scale(factor))
            };

            MappingValue::Decimal(format!("{}", value))
        }
        Mapping::Float { properties, .. } => {
            let endianness = properties
                .as_ref()
                .map(|properties| properties.endianness.unwrap_or(MappingEndianness::Big))
                .unwrap_or(MappingEndianness::Big);

            let (word_high, word_low) = match endianness {
                MappingEndianness::Big => (values[1], values[0]),
                MappingEndianness::Little => (values[0], values[1]),
            };

            let bytes = [
                (word_high & 0xff00 >> 8) as u8,
                (word_high & 0x00ff) as u8,
                (word_low & 0xff00 >> 8) as u8,
                (word_low & 0x00ff) as u8,
            ];

            MappingValue::Float(f32::from_be_bytes(bytes))
        }
        Mapping::Integer { properties, .. } => {
            let signed = properties
                .as_ref()
                .map(|properties| properties.signed.unwrap_or(false))
                .unwrap_or(false);

            let value = values[0];

            let bytes = [(value & 0xff00 >> 8) as u8, (value & 0x00ff) as u8];

            if signed {
                MappingValue::SignedInteger(i16::from_be_bytes(bytes))
            } else {
                MappingValue::UnsignedInteger(u16::from_be_bytes(bytes))
            }
        }
    }
}

fn read_rtu_mapping<T: std::io::Read + std::io::Write>(
    stream: &mut T,
    unit_id: u8,
    mapping: &Mapping,
) -> MappingValue {
    let request = modbus::Request::ReadHoldingRegisters {
        starting_address: mapping_address(mapping),
        register_count: mapping_register_count(mapping),
    };

    let rtu_request = modbus::rtu::Request { request, unit_id };
    let request_bytes = rtu_request.to_bytes();

    let bytes_count = stream.write(&request_bytes).unwrap();
    println!(
        "Wrote {} bytes: {:X?}",
        bytes_count.to_string(),
        request_bytes
    );

    let resp = read_rtu_response(stream, &rtu_request).unwrap();

    println!("Received {:?}", resp);

    let resp = modbus::rtu::Response::from_bytes(&resp).unwrap();

    println!("Decoded as {:?}", resp);

    match resp.response {
        modbus::Response::ReadHoldingRegisters { values, .. } => to_value(mapping, &values),
        response => {
            println!("Unexpected response: {:?}", response);
            exit(1)
        }
    }
}

fn read_tcp_mapping<T: std::io::Read + std::io::Write>(
    stream: &mut T,
    unit_id: u8,
    mapping: &Mapping,
) -> MappingValue {
    let request = modbus::Request::ReadHoldingRegisters {
        starting_address: mapping_address(mapping),
        register_count: mapping_register_count(mapping),
    };

    let tcp_request = modbus::tcp::Request::new(unit_id, 1, request);
    let request_bytes = tcp_request.to_bytes();

    let bytes_count = stream.write(&request_bytes).unwrap();
    println!(
        "Wrote {} bytes: {:X?}",
        bytes_count.to_string(),
        request_bytes
    );

    let resp = read_tcp_response(stream, &tcp_request).unwrap();

    println!("Received {:?}", resp);

    let resp = modbus::tcp::Response::from_bytes(&resp).unwrap();

    println!("Decoded as {:?}", resp);

    match resp.response {
        modbus::Response::ReadHoldingRegisters { values, .. } => to_value(mapping, &values),
        response => {
            println!("Unexpected response: {:?}", response);
            exit(1)
        }
    }
}

fn read_rtu_response<T: std::io::Read>(
    reader: &mut T,
    request: &modbus::rtu::Request,
) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::with_capacity(request.expected_response_len());

    let mut header = read_response_part(reader, 3).unwrap();
    println!("Read {} bytes: {:X?}", header.len(), header);
    buf.append(&mut header);

    let remaining_byte_count = buf[2] as usize;

    let mut rest = read_response_part(reader, remaining_byte_count + 2).unwrap();

    println!("Read {} bytes: {:X?}", rest.len(), rest);

    buf.append(&mut rest);

    Ok(buf)
}

fn read_tcp_response<T: std::io::Read>(
    reader: &mut T,
    request: &modbus::tcp::Request,
) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::with_capacity(request.expected_response_len());

    let mut header = read_response_part(reader, 6).unwrap();
    println!("Read {} bytes: {:X?}", header.len(), header);
    buf.append(&mut header);

    let remaining_byte_count: usize = u16::from_be_bytes([buf[4], buf[5]]) as usize;

    let mut rest = read_response_part(reader, remaining_byte_count).unwrap();

    println!("Read {} bytes: {:X?}", rest.len(), rest);

    buf.append(&mut rest);

    Ok(buf)
}

fn read_response_part<T: std::io::Read>(
    reader: &mut T,
    len: usize,
) -> Result<Vec<u8>, std::io::Error> {
    let mut raw_response: Vec<u8> = vec![0; len];

    match reader.read_exact(&mut raw_response) {
        Ok(()) => Ok(raw_response),
        Err(err) => Err(err),
    }
}

fn mapping_address(mapping: &Mapping) -> u16 {
    match mapping {
        Mapping::Bitfield { address, .. } => *address,
        Mapping::Boolean { address, .. } => *address,
        Mapping::Decimal { address, .. } => *address,
        Mapping::Float { address, .. } => *address,
        Mapping::Integer { address, .. } => *address,
    }
}

fn mapping_register_count(mapping: &Mapping) -> u16 {
    match mapping {
        Mapping::Bitfield { count, .. } => *count,
        Mapping::Boolean { count, .. } => *count,
        Mapping::Decimal { count, .. } => *count,
        Mapping::Float { count, .. } => *count,
        Mapping::Integer { count, .. } => *count,
    }
}

fn parse_device_path(device_path: &str) -> DeviceConnection {
    if device_path.contains(':') {
        let parts: Vec<&str> = device_path.split(':').collect();
        let ip_addr: Ipv4Addr = parts.get(0).unwrap().parse().unwrap();
        let port_number: u16 = parts.get(1).unwrap().parse().unwrap();

        DeviceConnection::TCP(ip_addr, port_number)
    } else {
        DeviceConnection::TTY(device_path.to_string())
    }
}

fn sample_via_tcp(
    ip_addr: Ipv4Addr,
    port: u16,
    unit_id: u8,
    mappings: &[Mapping],
    sampling_interval: u8,
) -> ! {
    let sleep_duration = std::time::Duration::from_secs(sampling_interval as u64);
    let mut stream = TcpStream::connect((ip_addr, port)).unwrap();

    loop {
        for mapping in mappings {
            read_tcp_mapping(&mut stream, unit_id, &mapping);
        }

        std::thread::sleep(sleep_duration);
    }
}

fn to_scale(factor: &str) -> u32 {
    if factor.contains('.') {
        factor.chars().filter(|c| *c == '0').count() as u32
    } else {
        1
    }
}
