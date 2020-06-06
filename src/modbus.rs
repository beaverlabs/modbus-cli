pub const FUNCTION_CODE_LEN: usize = 1;

pub enum Protocol {
    RTU,
    TCP,
}

pub enum Mode {
    Master,
    Slave,
}

pub trait Request {
    fn expected_response_len(&self) -> usize;
    fn to_bytes(&self) -> Vec<u8>;
    fn len(&self) -> usize;
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

        fn len(&self) -> usize {
            super::FUNCTION_CODE_LEN
                + 2 // Starting Address
                + 2 // Quantity of Registers
        }

        fn to_bytes(&self) -> Vec<u8> {
            let mut pdu = Vec::with_capacity(5);
            pdu.push(FC_READ_HOLDING_REGISTERS);
            pdu.extend(&self.starting_address.to_be_bytes());
            pdu.extend(&self.register_count.to_be_bytes());

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

            let crc = self::crc::crc(&adu).to_be_bytes();
            adu.extend(&crc);

            adu
        }
    }

    impl Response {
        pub fn from_bytes(buf: &[u8]) -> Result<Self, String> {
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

pub mod tcp {
    use std::convert::TryInto;

    const PROTOCOL_ID: u16 = 0x0000;

    pub struct Request {
        pub transaction_id: u16,
        pub protocol_id: u16,
        pub length: u16,
        pub unit_id: u8,
        pub request: Box<dyn super::Request>,
    }

    pub struct Response {
        pub transaction_id: u16,
        pub protocol_id: u16,
        pub length: u16,
        pub unit_id: u8,
        pub response: Box<dyn super::Response>,
    }

    impl Request {
        pub fn new(unit_id: u8, tid: u16, request: Box<dyn super::Request>) -> Self {
            Self {
                length: request.len() as u16,
                transaction_id: tid,
                protocol_id: PROTOCOL_ID,
                request,
                unit_id,
            }
        }

        pub fn expected_response_len(&self) -> usize {
            3 + self.request.expected_response_len()
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            let mut pdu = self.request.to_bytes();
            let mut adu = Vec::with_capacity(3 + pdu.len());

            adu.extend_from_slice(&u16::to_be_bytes(self.transaction_id));
            adu.extend_from_slice(&u16::to_be_bytes(self.protocol_id));
            adu.extend_from_slice(&u16::to_be_bytes(self.length));
            adu.push(self.unit_id);
            adu.append(&mut pdu);

            adu
        }
    }

    impl Response {
        pub fn from_bytes(buf: &[u8]) -> Result<Self, String> {
            let transaction_id = u16::from_be_bytes(buf[0..2].try_into().unwrap());
            let protocol_id = u16::from_be_bytes(buf[2..4].try_into().unwrap());
            let length = u16::from_be_bytes(buf[4..6].try_into().unwrap());
            let unit_id = buf[6];
            let function_code = buf[7];

            match function_code {
                super::request::FC_READ_HOLDING_REGISTERS => {
                    let response = Box::new(
                        super::response::ReadHoldingRegistersResponse::from_bytes(buf)?,
                    );
                    Ok(Self {
                        transaction_id,
                        protocol_id,
                        length,
                        unit_id,
                        response,
                    })
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
