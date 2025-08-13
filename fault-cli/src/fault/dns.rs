use std::fmt;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use axum::http;
use bytes::Bytes;
use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::op::MessageType;
use hickory_resolver::proto::op::Query;
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::proto::rr::Record;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::proto::rr::rdata::A;
use http::HeaderMap;
use http::StatusCode;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::SmallRng;

use super::Bidirectional;
use super::FaultInjector;
use crate::config::DnsSettings;
use crate::config::FaultKind;
use crate::errors::ProxyError;
use crate::event::FaultEvent;
use crate::event::ProxyTaskEvent;
use crate::fault::BoxChunkStream;
use crate::fault::DatagramAction;
use crate::types::Direction;
use crate::types::DnsCase;
use crate::types::StreamSide;

#[derive(Debug)]
pub struct FaultyResolverInjector {
    settings: DnsSettings,
}

impl From<&DnsSettings> for FaultyResolverInjector {
    fn from(settings: &DnsSettings) -> Self {
        FaultyResolverInjector { settings: settings.clone() }
    }
}

impl fmt::Display for FaultyResolverInjector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dns")
    }
}

impl Clone for FaultyResolverInjector {
    fn clone(&self) -> Self {
        Self { settings: self.settings.clone() }
    }
}

#[async_trait]
impl FaultInjector for FaultyResolverInjector {
    /// Injects latency into a bidirectional stream.
    async fn inject(
        &self,
        stream: Box<dyn Bidirectional + 'static>,
        _event: Box<dyn ProxyTaskEvent>,
        _side: StreamSide,
    ) -> Result<
        Box<dyn Bidirectional + 'static>,
        (ProxyError, Box<dyn Bidirectional + 'static>),
    > {
        Ok(stream)
    }

    async fn apply_on_response(
        &self,
        resp: http::Response<Vec<u8>>,
        _event: Box<dyn ProxyTaskEvent>,
    ) -> Result<http::Response<Vec<u8>>, ProxyError> {
        Ok(resp)
    }

    async fn apply_on_request_builder(
        &self,
        builder: reqwest::ClientBuilder,
        _event: Box<dyn ProxyTaskEvent>,
    ) -> Result<reqwest::ClientBuilder, ProxyError> {
        Ok(builder)
    }

    async fn apply_on_request(
        &self,
        request: reqwest::Request,
        _event: Box<dyn ProxyTaskEvent>,
    ) -> Result<reqwest::Request, ProxyError> {
        Ok(request)
    }

    async fn apply_on_response_stream(
        &self,
        status: StatusCode,
        headers: HeaderMap,
        body: BoxChunkStream,
        _event: Box<dyn ProxyTaskEvent>,
    ) -> Result<(StatusCode, HeaderMap, BoxChunkStream), ProxyError> {
        Ok((status, headers, body))
    }

    async fn apply_on_datagram(
        &self,
        packet: Bytes,
        peer: SocketAddr,
        direction: Direction,
        event: Box<dyn ProxyTaskEvent>,
    ) -> Result<DatagramAction, ProxyError> {
        let settings = &self.settings;

        let _ = event.with_fault(FaultEvent::Dns {
            direction: Direction::Ingress,
            side: StreamSide::Server,
            case: format!("{:?}", settings.case),
            triggered: Some(true),
        });

        let slice: &[u8] = packet.as_ref();

        let req = Message::from_vec(slice)
            .map_err(|e| ProxyError::Other(e.to_string()))?;
        let id = req.id();
        let rd = req.recursion_desired();
        let q = req.queries().get(0).cloned();

        if matches!(settings.case, DnsCase::Timeout) {
            if let Some(delay_ms) = self.settings.delay_ms {
                tokio::time::sleep(delay_ms).await
            }

            let _ = event.on_applied(FaultEvent::Dns {
                direction: Direction::Ingress,
                side: StreamSide::Server,
                case: format!("{:?}", settings.case),
                triggered: Some(true),
            });

            return Ok(DatagramAction::Pass(packet));
        }

        let mut m = base_reply(id, rd, &q);

        match settings.case {
            DnsCase::Truncated => {
                if let Some(delay_ms) = self.settings.delay_ms {
                    tokio::time::sleep(delay_ms).await
                }
                m.set_truncated(true);
            }
            DnsCase::Refused => {
                if let Some(delay_ms) = self.settings.delay_ms {
                    tokio::time::sleep(delay_ms).await
                }
                m.set_response_code(ResponseCode::Refused);
            }
            DnsCase::ServFail => {
                if let Some(delay_ms) = self.settings.delay_ms {
                    tokio::time::sleep(delay_ms).await
                }
                m.set_response_code(ResponseCode::ServFail);
            }
            DnsCase::NxDomain => {
                if let Some(delay_ms) = self.settings.delay_ms {
                    tokio::time::sleep(delay_ms).await
                }
                m.set_response_code(ResponseCode::NXDomain);
            }
            DnsCase::EmptyAnswer => {
                if let Some(delay_ms) = self.settings.delay_ms {
                    tokio::time::sleep(delay_ms).await
                }
            }
            DnsCase::RandomA => {
                if let Some(delay_ms) = self.settings.delay_ms {
                    tokio::time::sleep(delay_ms).await
                }

                if let Some(query) = &q {
                    let mut rng = SmallRng::from_os_rng();

                    if query.query_type() == RecordType::A {
                        let ip = Ipv4Addr::new(
                            rng.random(),
                            rng.random(),
                            rng.random(),
                            rng.random(),
                        );
                        let rec = Record::from_rdata(
                            query.name().clone(),
                            30,
                            RData::A(A::from(ip)),
                        );
                        m.add_answer(rec);
                    }
                }
            }
            DnsCase::Delay => {
                if let Some(delay_ms) = self.settings.delay_ms {
                    tokio::time::sleep(delay_ms).await
                }

                let _ = event.on_applied(FaultEvent::Dns {
                    direction: Direction::Ingress,
                    side: StreamSide::Server,
                    case: format!("{:?}", settings.case),
                    triggered: Some(true),
                });

                return Ok(DatagramAction::Pass(packet));
            }
            DnsCase::Timeout => {
                if let Some(delay_ms) = self.settings.delay_ms {
                    tokio::time::sleep(delay_ms).await
                }

                let _ = event.on_applied(FaultEvent::Dns {
                    direction: Direction::Ingress,
                    side: StreamSide::Server,
                    case: format!("{:?}", settings.case),
                    triggered: Some(true),
                });

                return Ok(DatagramAction::Drop);
            }
        }

        let _ = event.on_applied(FaultEvent::Dns {
            direction: Direction::Ingress,
            side: StreamSide::Server,
            case: format!("{:?}", settings.case),
            triggered: Some(true),
        });

        let bytes = m.to_vec().map_err(|e| ProxyError::Other(e.to_string()))?;
        Ok(DatagramAction::Respond(Bytes::from(bytes)))
    }

    fn is_enabled(&self) -> bool {
        self.settings.enabled
    }

    fn kind(&self) -> FaultKind {
        FaultKind::Dns
    }

    fn enable(&mut self) {
        self.settings.enabled = true
    }

    fn disable(&mut self) {
        self.settings.enabled = false
    }

    fn clone_box(&self) -> Box<dyn FaultInjector> {
        Box::new(self.clone())
    }
}

//
// Private functions
//

fn base_reply(id: u16, rd: bool, q: &Option<Query>) -> Message {
    let mut m = Message::new();
    m.set_id(id);
    m.set_message_type(MessageType::Response);
    m.set_recursion_desired(rd);
    m.set_recursion_available(true);
    if let Some(q) = q {
        m.add_query(q.clone());
    }
    m
}
