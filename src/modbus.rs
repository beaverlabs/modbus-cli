pub const FUNCTION_CODE_LEN: usize = 1;
pub const FC_READ_HOLDING_REGISTERS: u8 = 0x03;

pub enum Protocol {
    RTU,
    TCP,
}

pub enum Mode {
    Master,
    Slave,
}

#[derive(Debug)]
pub enum Request {
    ReadHoldingRegisters {
        starting_address: u16,
        register_count: u16,
    },
}

#[derive(Debug)]
pub enum Response {
    ReadHoldingRegistersResponse { byte_count: u8, values: Vec<u16> },
}

impl Request {
    fn expected_response_len(&self) -> usize {
        let body_size = match self {
            Request::ReadHoldingRegisters { register_count, .. } => register_count * 2,
        };

        FUNCTION_CODE_LEN + 1 + body_size as usize
    }

    fn len(&self) -> usize {
        let body_size: usize = match self {
            Request::ReadHoldingRegisters { .. } => 4,
        };

        FUNCTION_CODE_LEN + body_size
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut pdu = Vec::with_capacity(5);
        pdu.push(FC_READ_HOLDING_REGISTERS);

        match self {
            Request::ReadHoldingRegisters {
                register_count,
                starting_address,
            } => {
                pdu.extend(&starting_address.to_be_bytes());
                pdu.extend(&register_count.to_be_bytes());
            }
        };

        pdu
    }
}

impl Response {
    pub fn from_bytes(buf: &[u8]) -> Result<Self, String> {
        let function_code = buf[0];

        match function_code {
            FC_READ_HOLDING_REGISTERS => {
                let byte_count = buf[1];
                let mut values: Vec<u16> = Vec::with_capacity((byte_count / 2) as usize);

                buf[2..]
                    .iter()
                    .fold(None, |current_item, value| match current_item {
                        None => Some(value),
                        Some(hi) => {
                            values.push(u16::from_be_bytes([*hi, *value]));
                            None
                        }
                    });

                Ok(Response::ReadHoldingRegistersResponse { byte_count, values })
            }
            _ => Err(format!(
                "Unsupported function code in response: {}",
                function_code
            )),
        }
    }
}

pub mod rtu {
    pub mod crc;

    pub struct Request {
        pub unit_id: u8,
        pub request: super::Request,
    }

    pub struct Response {
        pub unit_id: u8,
        pub response: super::Response,
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

            let response = super::Response::from_bytes(&buf[1..buf_len - 2])?;
            Ok(Self { unit_id, response })
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
    const PROTOCOL_ID: u16 = 0x0000;

    pub struct Request {
        pub transaction_id: u16,
        pub protocol_id: u16,
        pub length: u16,
        pub unit_id: u8,
        pub request: super::Request,
    }

    pub struct Response {
        pub transaction_id: u16,
        pub protocol_id: u16,
        pub length: u16,
        pub unit_id: u8,
        pub response: super::Response,
    }

    impl Request {
        pub fn new(unit_id: u8, tid: u16, request: super::Request) -> Self {
            Self {
                length: request.len() as u16 + 1,
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
            let transaction_id = u16::from_be_bytes([buf[0], buf[1]]);
            let protocol_id = u16::from_be_bytes([buf[2], buf[3]]);
            let length = u16::from_be_bytes([buf[4], buf[5]]);
            let unit_id = buf[6];
            let response = super::Response::from_bytes(&buf[7..])?;

            Ok(Self {
                transaction_id,
                protocol_id,
                length,
                unit_id,
                response,
            })
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
