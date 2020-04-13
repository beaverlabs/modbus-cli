use serialport::prelude::*;
use std::process::exit;
use std::time::Duration;

mod modbus {
    pub const FUNCTION_CODE_LEN: usize = 1;

    pub trait Request {
        fn expected_response_len(&self) -> usize;
        fn to_bytes(&self) -> Vec<u8>;
    }

    pub trait Response: std::fmt::Debug {}

    pub mod request {
        pub const FC_READ_HOLDING_REGISTERS: u8 = 0x03;

        pub struct ReadHoldingRegisters {
            pub starting_address: u16,
            pub register_count: u16,
        }

        impl super::Request for ReadHoldingRegisters {
            fn expected_response_len(&self) -> usize {
                super::FUNCTION_CODE_LEN + 1 + self.register_count as usize * 2
            }

            fn to_bytes(&self) -> Vec<u8> {
                let mut pdu = Vec::with_capacity(5);
                pdu.push(FC_READ_HOLDING_REGISTERS);
                pdu.append(&mut self.starting_address.to_be_bytes().to_vec());
                pdu.append(&mut self.register_count.to_be_bytes().to_vec());

                pdu
            }
        }
    }

    pub mod response {
        #[derive(Debug)]
        pub struct ReadHoldingRegistersResponse {
            pub byte_count: u8,
            pub values: Vec<u16>,
        }

        impl super::Response for ReadHoldingRegistersResponse {}

        impl ReadHoldingRegistersResponse {
            pub fn from_bytes(buf: &[u8]) -> Result<Self, String> {
                let buf_len = buf.len();
                let byte_count = buf[2];
                let mut values: Vec<u16> = Vec::with_capacity((byte_count / 2) as usize);

                buf[3..buf_len - 2]
                    .iter()
                    .fold(None, |current_item, value| match current_item {
                        None => Some(value),
                        Some(hi) => {
                            values.push(u16::from_be_bytes([*hi, *value]));
                            None
                        }
                    });

                let response = super::response::ReadHoldingRegistersResponse { byte_count, values };
                Ok(response)
            }
        }
    }

    pub mod rtu {
        pub mod crc;

        pub struct Request {
            pub unit_id: u8,
            pub request: Box<dyn super::Request>,
        }

        pub struct Response {
            pub unit_id: u8,
            pub response: Box<dyn super::Response>,
        }

        impl Request {
            pub fn expected_response_len(&self) -> usize {
                3 + self.request.expected_response_len()
            }

            pub fn to_bytes(&self) -> Vec<u8> {
                let mut pdu = self.request.to_bytes();
                let mut adu = Vec::with_capacity(3 + pdu.len());

                adu.push(self.unit_id);
                adu.append(&mut pdu);

                let mut crc = self::crc::crc(&adu).to_be_bytes().to_vec();
                adu.append(&mut crc);

                adu
            }
        }

        impl Response {
            pub fn from_vec(buf: &[u8]) -> Result<Self, String> {
                let unit_id = buf[0];
                let function_code = buf[1];
                let buf_len = buf.len();
                let crc_hi = buf[buf_len - 1];
                let crc_low = buf[buf_len - 2];
                let crc = u16::from_le_bytes([crc_hi, crc_low]);
                let expected_crc = crc::crc(&buf[..buf_len - 2]);

                if crc != expected_crc {
                    return Err(format!(
                        "CRC does not match, expected {:X} but found {:X}",
                        expected_crc, crc
                    ));
                }

                match function_code {
                    super::request::FC_READ_HOLDING_REGISTERS => {
                        let response = Box::new(
                            super::response::ReadHoldingRegistersResponse::from_bytes(buf)?,
                        );
                        Ok(Self { unit_id, response })
                    }

                    _ => {
                        unimplemented!();
                    }
                }
            }
        }

        impl std::fmt::Debug for Response {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
                write!(
                    f,
                    "Response {{ unit_id: {}, response: {:?} }}",
                    self.unit_id, self.response
                )
            }
        }
    }
}

fn main() {
    let device_path = std::env::args().nth(1).expect("<device> is required");
    let baud_rate = std::env::args()
        .nth(2)
        .expect("<baud_rate> is required")
        .parse::<u32>()
        .unwrap();
    let unit_id = std::env::args().nth(3).expect("<unit_id> is required");
    let mapping_path = std::env::args().nth(4).expect("<mapping_path> is required");
    let sampling_interval = std::env::args()
        .nth(5)
        .expect("<sampling_interval> is required");

    let port_settings = SerialPortSettings {
        baud_rate,
        data_bits: DataBits::Eight,
        flow_control: FlowControl::None,
        parity: Parity::None,
        stop_bits: StopBits::One,
        timeout: Duration::from_millis(1000),
    };

    match serialport::open_with_settings(&device_path, &port_settings) {
        Ok(mut serial_port) => {
            let request = Box::new(modbus::request::ReadHoldingRegisters {
                starting_address: 0,
                register_count: 10,
            });

            let rtu_request = modbus::rtu::Request {
                request,
                unit_id: 1,
            };

            let request_bytes = rtu_request.to_bytes();
            let bytes_count = serial_port.write(&request_bytes).unwrap();
            println!(
                "Wrote {} bytes: {:X?}",
                bytes_count.to_string(),
                request_bytes
            );

            let resp = read_response(&mut serial_port, &rtu_request).unwrap();

            println!("Received {:?}", resp);

            let resp = modbus::rtu::Response::from_vec(&resp);

            println!("Decoded as {:?}", resp);
        }
        Err(error) => {
            eprintln!("{}: {}", device_path, error);
            exit(1);
        }
    }
}

fn read_response<T: std::io::Read>(
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
