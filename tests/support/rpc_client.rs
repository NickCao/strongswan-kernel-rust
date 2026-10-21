// SPDX-License-Identifier: GPL-2.0-or-later
//! Test-only JSON/stdin adapter for the existing Python kernel scenarios.
//! It uses tarpc's generated request/response types and the production codec;
//! JSON is never sent to the daemon.
use kernel_rust_protocol::{transport, KernelRequest, KernelResponse};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::{self, BufRead, Write},
    os::unix::net::UnixStream,
    sync::Arc,
    time::Duration,
};
use tarpc::{client, context};
use tokio::{sync::mpsc, task::JoinHandle};

type Channel = client::Channel<KernelRequest, KernelResponse>;
struct Connection {
    channel: Channel,
    signal: Arc<transport::EventSignal>,
    socket: UnixStream,
    sender: mpsc::UnboundedSender<Value>,
    receiver: mpsc::UnboundedReceiver<Value>,
    tasks: Vec<JoinHandle<()>>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
        for task in &self.tasks {
            task.abort();
        }
    }
}
fn response(method: &str, response: KernelResponse) -> Value {
    let value = serde_json::to_value(response).unwrap();
    let result = value.as_object().unwrap().values().next().unwrap();
    if let Some(error) = result.get("Err") {
        return match error.get("Kernel") {
            Some(errno) => json!({"error":"Kernel", "parameters":{"errno":errno}}),
            None => json!({"error":error.as_str().unwrap()}),
        };
    }
    let value = result.get("Ok").unwrap().clone();
    let parameters = match method {
        "AllocateSpi" => json!({"spi":value}),
        "AllocateCpi" => json!({"cpi":value}),
        "QueryPolicy" => json!({"last_use":value}),
        "GetSourceAddress" => json!({"address":value}),
        "GetInterface" => json!({"interface":value}),
        "ListAddresses" => json!({"addresses":value}),
        "ListSubnets" => json!({"subnets":value}),
        _ if value.is_null() => json!({}),
        _ => value,
    };
    json!({"parameters":parameters})
}
async fn dispatch(command: Value, connections: &mut HashMap<u64, Connection>) -> Value {
    let id = command["connection"].as_u64().unwrap();
    match command["operation"].as_str().unwrap() {
        "connect" => {
            let reused = command["reuse"].as_u64().map(|id| &connections[&id]);
            let socket = match reused.map_or_else(
                || UnixStream::connect(command["path"].as_str().unwrap()),
                |connection| connection.socket.try_clone(),
            ) {
                Ok(socket) => socket,
                Err(error) => return json!({"connect_error":error.to_string()}),
            };
            socket.set_nonblocking(true).unwrap();
            let (channel, signal) = if let Some(connection) = reused {
                (connection.channel.clone(), connection.signal.clone())
            } else {
                let stream = tokio::net::UnixStream::from_std(socket.try_clone().unwrap()).unwrap();
                let signal = Arc::new(transport::EventSignal::default());
                (
                    client::new(
                        client::Config::default(),
                        transport::client(stream, signal.clone()),
                    )
                    .spawn(),
                    signal,
                )
            };
            let (sender, receiver) = mpsc::unbounded_channel();
            connections.insert(
                id,
                Connection {
                    channel,
                    signal,
                    socket,
                    sender,
                    receiver,
                    tasks: Vec::new(),
                },
            );
            json!({})
        }
        "close" => {
            connections.remove(&id);
            json!({})
        }
        "receive" => {
            let connection = connections.get_mut(&id).unwrap();
            let timeout = Duration::from_secs_f64(command["timeout"].as_f64().unwrap());
            match tokio::time::timeout(timeout, connection.receiver.recv()).await {
                Ok(Some(value)) => value,
                Ok(None) => json!({"eof":true}),
                Err(_) => json!({"timeout":true}),
            }
        }
        "send" => {
            let connection = connections.get_mut(&id).unwrap();
            let method = command["method"].as_str().unwrap().to_owned();
            let mut parameters = command["parameters"].clone();
            if method == "WatchEvents" {
                let channel = connection.channel.clone();
                let signal = connection.signal.clone();
                let sender = connection.sender.clone();
                connection.tasks.push(tokio::spawn(async move {
                    let _ = sender.send(json!({"parameters":{"event":{"kind":"ready"}}}));
                    let mut first = true;
                    loop {
                        if !first {
                            signal.notified().await;
                        }
                        first = false;
                        signal.take();
                        loop {
                            let mut ctx = context::current();
                            ctx.deadline = std::time::Instant::now() + Duration::from_secs(60);
                            match channel.call(ctx, KernelRequest::NextEvents {}).await {
                                Ok(KernelResponse::NextEvents(Ok(events))) => {
                                    if events.is_empty() {
                                        break;
                                    }
                                    for event in events {
                                        let mut event = serde_json::to_value(event).unwrap();
                                        event["kind"] =
                                            event["kind"].as_str().unwrap().to_lowercase().into();
                                        if sender
                                            .send(json!({"parameters":{"event":event}}))
                                            .is_err()
                                        {
                                            return;
                                        }
                                    }
                                }
                                _ => {
                                    let _ = sender.send(json!({"eof":true}));
                                    return;
                                }
                            }
                        }
                    }
                }));
            } else {
                if method == "OpenSession" {
                    parameters = json!({"config":parameters});
                }
                if (method == "QuerySa" || method == "RemoveSa") && parameters.get("cpi").is_none()
                {
                    parameters["cpi"] = json!(0);
                }
                let request =
                    serde_json::from_value::<KernelRequest>(json!({method.clone():parameters}));
                match request {
                    Ok(request) => {
                        let channel = connection.channel.clone();
                        let sender = connection.sender.clone();
                        connection.tasks.push(tokio::spawn(async move {
                            let reply = match channel.call(context::current(), request).await {
                                Ok(reply) => response(&method, reply),
                                Err(_) => json!({"eof":true}),
                            };
                            let _ = sender.send(reply);
                        }));
                    }
                    Err(_) => {
                        let _ = connection.sender.send(json!({"error":"InvalidRequest"}));
                    }
                }
            }
            json!({})
        }
        _ => panic!("unknown test adapter command"),
    }
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let mut connections = HashMap::new();
    for line in io::stdin().lock().lines() {
        let command: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let reply = dispatch(command, &mut connections).await;
        println!("{reply}");
        io::stdout().flush().unwrap();
    }
}
