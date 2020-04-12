use serialport::prelude::*;
use std::process::exit;
use std::time::Duration;

enum ModbusTable {
    DiscretesInput,
    Coils,
    InputRegisters,
    HoldingRegisters,
}

struct Mapping {
    unit_id: u8,
    table: ModbusTable,
}

use crate::modbus::Request;

mod modbus {
    pub trait Request {
        fn to_bytes(&self) -> Vec<u8>;
    }

    pub mod request {
        const FC_READ_HOLDING_REGISTERS: u8 = 0x03;

        pub struct ReadHoldingRegisters {
            pub starting_address: u16,
            pub register_count: u16,
        }

        impl super::Request for ReadHoldingRegisters {
            fn to_bytes(&self) -> Vec<u8> {
                let mut pdu = Vec::with_capacity(5);
                pdu.push(FC_READ_HOLDING_REGISTERS);
                pdu.append(&mut self.starting_address.to_be_bytes().to_vec());
                pdu.append(&mut self.register_count.to_be_bytes().to_vec());

                pdu
            }
        }
    }

    pub mod rtu {
        pub mod crc;

        pub struct Request<'a> {
            pub unit_id: u8,
            pub request: &'a dyn super::Request,
        }

        impl Request<'_> {
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
    }
}

fn main() {
    let device_path = std::env::args().nth(1).expect("<device> is required");
    let baud_rate = std::env::args()
        .nth(2)
        .expect("<baud_rate> is required")
        .parse::<u32>()
        .unwrap();
    let unit_id = std::env::args().nth(3).expect("<unit_d> is required");
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
        timeout: Duration::from_millis(100),
    };

    match serialport::open_with_settings(&device_path, &port_settings) {
        Ok(mut serial_port) => {
            let request = modbus::request::ReadHoldingRegisters {
                starting_address: 0,
                register_count: 10,
            };

            let rtu_request = modbus::rtu::Request {
                request: &request,
                unit_id: 1,
            };

            let request_bytes = rtu_request.to_bytes();
            let bytes_count = serial_port.write(&request_bytes).unwrap();
            println!(
                "Wrote {} bytes: {:X?}",
                bytes_count.to_string(),
                request_bytes
            );
        }
        Err(error) => {
            eprintln!("{}: {}", device_path, error);
            exit(1);
        }
    }
}
