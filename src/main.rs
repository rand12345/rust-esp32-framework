#![allow(unused_imports)]
#![allow(clippy::single_component_path_imports)]
//#![feature(backtrace)]

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Condvar, Mutex};
use std::{cell::RefCell, env, sync::atomic::*, sync::Arc, thread, time::*};

use anyhow::bail;

use embedded_svc::mqtt::client::utils::ConnState;
use esp_idf_svc::ws::client;
use log::*;

use url;
mod solax_x1_air;
use solax_x1_air::*;

use smol;

use embedded_hal::adc::OneShot;
use embedded_hal::blocking::delay::DelayMs;
use embedded_hal::digital::v2::OutputPin;
use embedded_hal::prelude::*;

use embedded_svc::eth;
use embedded_svc::eth::{Eth, TransitionalState};
use embedded_svc::httpd::registry::*;
use embedded_svc::httpd::*;
use embedded_svc::io;
use embedded_svc::ipv4;
use embedded_svc::mqtt::client::{Client, Connection, MessageImpl, Publish, QoS};
use embedded_svc::ping::Ping;
use embedded_svc::sys_time::SystemTime;
use embedded_svc::timer::TimerService;
use embedded_svc::timer::*;
use embedded_svc::wifi::*;

use esp_idf_svc::eth::*;
use esp_idf_svc::eventloop::*;
use esp_idf_svc::eventloop::*;
use esp_idf_svc::httpd as idf;
use esp_idf_svc::httpd::ServerRegistry;
use esp_idf_svc::mqtt::client::*;
use esp_idf_svc::netif::*;
use esp_idf_svc::nvs::*;
use esp_idf_svc::ping;
use esp_idf_svc::sntp;
use esp_idf_svc::sysloop::*;
use esp_idf_svc::systime::EspSystemTime;
use esp_idf_svc::timer::*;
use esp_idf_svc::wifi::*;

use esp_idf_hal::adc;
use esp_idf_hal::delay;
use esp_idf_hal::gpio;
use esp_idf_hal::i2c;
use esp_idf_hal::prelude::*;
use esp_idf_hal::spi;
use esp_idf_hal::{peripherals::Peripherals, units::FromValueType};

use esp_idf_sys::{self, c_types};
use esp_idf_sys::{esp, EspError};

use display_interface_spi::SPIInterfaceNoCS;

use embedded_graphics::mono_font::{ascii::FONT_10X20, MonoTextStyle};
use embedded_graphics::pixelcolor::*;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::*;
use embedded_graphics::text::*;

use ssd1306;
use ssd1306::mode::DisplayConfig;
extern crate dotenv;
use dotenv::dotenv;

// use std::env;
#[macro_use]
extern crate dotenv_codegen;

// #[allow(dead_code)]
// #[cfg(not(feature = "qemu"))]
// const SSID: &str = env!("RUST_ESP32_STD_DEMO_WIFI_SSID");
// #[allow(dead_code)]
// #[cfg(not(feature = "qemu"))]
// const PASS: &str = env!("RUST_ESP32_STD_DEMO_WIFI_PASS");

thread_local! {
    static TLS: RefCell<u32> = RefCell::new(13);
}

fn main() -> Result<()> {
    esp_idf_sys::link_patches();

    // let SSID = dotenv!("SSID");
    // let PASS = dotenv!("PASS");

    test_print();

    test_atomics();

    test_threads();

    #[cfg(not(esp_idf_version = "4.3"))]
    test_fs()?;

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    // Get backtraces from anyhow; only works for Xtensa arch currently
    // TODO: No longer working with ESP-IDF 4.3.1+
    //#[cfg(target_arch = "xtensa")]
    //env::set_var("RUST_BACKTRACE", "1");

    #[allow(unused)]
    let peripherals = Peripherals::take().unwrap();
    #[allow(unused)]
    let pins = peripherals.pins;

    #[allow(unused)]
    let netif_stack = Arc::new(EspNetifStack::new()?);
    #[allow(unused)]
    let sys_loop_stack = Arc::new(EspSysLoopStack::new()?);
    #[allow(unused)]
    let default_nvs = Arc::new(EspDefaultNvs::new()?);

    #[allow(clippy::redundant_clone)]
    #[cfg(not(feature = "qemu"))]
    #[allow(unused_mut)]
    let mut wifi = wifi(
        netif_stack.clone(),
        sys_loop_stack.clone(),
        default_nvs.clone(),
    )?;

    // test_tcp()?;

    // test_tcp_bind()?;

    let _sntp = sntp::EspSntp::new_default()?;
    info!("SNTP initialized");

    let (eventloop, _subscription) = test_eventloop()?;

    let mqtt_client = test_mqtt_client()?;

    // let _timer = test_timer(eventloop, mqtt_client)?;
    // For UART 1 **************************** (good for RS485)
    let config = esp_idf_hal::serial::config::Config::default().baudrate(Hertz(9_600));
    let userial = esp_idf_hal::serial::Serial::new(
        peripherals.uart1,
        esp_idf_hal::serial::Pins {
            tx: pins.gpio19,
            rx: pins.gpio18,
            cts: None,
            rts: None,
        },
        config,
    )?;
    let inverter = SolaxX1Air::new(userial);
    let _poller = poll_inverter(eventloop, mqtt_client, inverter)?;

    // #[cfg(feature = "experimental")]
    // experimental::test()?;

    #[cfg(not(feature = "qemu"))]
    #[cfg(esp_idf_config_lwip_ipv4_napt)]
    enable_napt(&mut wifi)?;

    // let mutex = Arc::new((Mutex::new(None), Condvar::new()));

    // let httpd = httpd(mutex.clone())?;

    // let mut _wait = mutex.0.lock().unwrap();

    loop {
        println!("We are ok");
        thread::sleep(Duration::from_secs(1));
    }

    for s in 0..3 {
        info!("Shutting down in {} secs", 3 - s);
        thread::sleep(Duration::from_secs(1));
    }

    // drop(httpd);
    // info!("Httpd stopped");

    #[cfg(not(feature = "qemu"))]
    {
        drop(wifi);
        info!("Wifi stopped");
    }

    Ok(())
}

fn poll_inverter(
    mut eventloop: EspBackgroundEventLoop,
    mut client: EspMqttClient<ConnState<MessageImpl, EspError>>,
    mut inverter: SolaxX1Air,
    // wifi: Box<EspWifi>,
) -> anyhow::Result<EspTimer> {
    use embedded_svc::event_bus::Postbox;
    use solax_x1_air::Status::*;

    info!("About to schedule a periodic inverter poll every five seconds");
    let mut periodic_timer = EspTimerService::new()?.timer(move || {
        info!("Tick from periodic timer");

        let now = EspSystemTime {}.now();

        eventloop.post(&EventLoopMessage::new(now), None).unwrap();

        match inverter.status {
            Offline | Unregistered | Registered => {
                if inverter.init_inverter().is_err() {
                    println!("Inverter comms error, check hardware");
                    // thread::sleep(Duration::from_secs(60))
                } else {
                    info!("Inverter is Ok but not Online")
                }
            }
            Online => {
                if inverter.poll_data().is_ok() {
                    // update frequency (min from Solax v1.7 spec)
                    let message = &inverter.data.livedata.active_power;
                    if client
                        .publish(
                            "X1/active_power",
                            QoS::AtMostOnce,
                            true,
                            format!("{}", message).as_bytes(),
                        )
                        .is_err()
                    {
                        panic!("MQTT Watts failed")
                    }
                    info!("X1 {}W", message);
                } else {
                    error!("Inverter is not Ok")
                }
            }
        }
    })?;

    periodic_timer.every(Duration::from_secs(5))?;

    Ok(periodic_timer)
}

#[allow(clippy::vec_init_then_push)]
fn test_print() {
    // Start simple
    println!("Hello from Rust!");

    // Check collections
    let mut children = vec![];

    children.push("foo");
    children.push("bar");
    println!("More complex print {:?}", children);
}

#[allow(deprecated)]
fn test_atomics() {
    let a = AtomicUsize::new(0);
    let v1 = a.compare_and_swap(0, 1, Ordering::SeqCst);
    let v2 = a.swap(2, Ordering::SeqCst);

    let (r1, r2) = unsafe {
        // don't optimize our atomics out
        let r1 = core::ptr::read_volatile(&v1);
        let r2 = core::ptr::read_volatile(&v2);

        (r1, r2)
    };

    println!("Result: {}, {}", r1, r2);
}

fn test_threads() {
    let mut children = vec![];

    println!("Rust main thread: {:?}", thread::current());

    TLS.with(|tls| {
        println!("Main TLS before change: {}", *tls.borrow());
    });

    TLS.with(|tls| *tls.borrow_mut() = 42);

    TLS.with(|tls| {
        println!("Main TLS after change: {}", *tls.borrow());
    });

    for i in 0..5 {
        // Spin up another thread
        children.push(thread::spawn(move || {
            println!("This is thread number {}, {:?}", i, thread::current());

            TLS.with(|tls| *tls.borrow_mut() = i);

            TLS.with(|tls| {
                println!("Inner TLS: {}", *tls.borrow());
            });
        }));
    }

    println!(
        "About to join the threads. If ESP-IDF was patched successfully, joining will NOT crash"
    );

    for child in children {
        // Wait for the thread to finish. Returns a result.
        let _ = child.join();
    }

    TLS.with(|tls| {
        println!("Main TLS after threads: {}", *tls.borrow());
    });

    thread::sleep(Duration::from_secs(2));

    println!("Joins were successful.");
}

#[cfg(not(esp_idf_version = "4.3"))]
fn test_fs() -> Result<()> {
    assert_eq!(fs::canonicalize(PathBuf::from("."))?, PathBuf::from("/"));
    assert_eq!(
        fs::canonicalize(
            PathBuf::from("/")
                .join("foo")
                .join("bar")
                .join(".")
                .join("..")
                .join("baz")
        )?,
        PathBuf::from("/foo/baz")
    );

    Ok(())
}

fn test_tcp() -> Result<()> {
    info!("About to open a TCP connection to 1.1.1.1 port 80");

    let mut stream = TcpStream::connect("one.one.one.one:80")?;

    let err = stream.try_clone();
    if let Err(err) = err {
        info!(
            "Duplication of file descriptors does not work (yet) on the ESP-IDF, as expected: {}",
            err
        );
    }

    stream.write_all("GET / HTTP/1.0\n\n".as_bytes())?;

    let mut result = Vec::new();

    stream.read_to_end(&mut result)?;

    info!(
        "1.1.1.1 returned:\n=================\n{}\n=================\nSince it returned something, all is OK",
        std::str::from_utf8(&result)?);

    Ok(())
}

fn test_tcp_bind() -> Result<()> {
    fn test_tcp_bind_accept() -> Result<()> {
        info!("About to bind a simple echo service to port 8080");

        let listener = TcpListener::bind("0.0.0.0:8080")?;

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    info!("Accepted client");

                    thread::spawn(move || {
                        test_tcp_bind_handle_client(stream);
                    });
                }
                Err(e) => {
                    error!("Error: {}", e);
                }
            }
        }

        unreachable!()
    }

    fn test_tcp_bind_handle_client(mut stream: TcpStream) {
        // read 20 bytes at a time from stream echoing back to stream
        loop {
            let mut read = [0; 128];

            match stream.read(&mut read) {
                Ok(n) => {
                    if n == 0 {
                        // connection was closed
                        break;
                    }
                    stream.write_all(&read[0..n]).unwrap();
                }
                Err(err) => {
                    panic!("{}", err);
                }
            }
        }
    }

    thread::spawn(|| test_tcp_bind_accept().unwrap());

    Ok(())
}

fn test_timer(
    mut eventloop: EspBackgroundEventLoop,
    mut client: EspMqttClient<ConnState<MessageImpl, EspError>>,
) -> Result<EspTimer> {
    use embedded_svc::event_bus::Postbox;

    info!("About to schedule a one-shot timer for after 2 seconds");
    let mut once_timer = EspTimerService::new()?.timer(|| {
        info!("One-shot timer triggered");
    })?;

    once_timer.after(Duration::from_secs(2))?;

    thread::sleep(Duration::from_secs(3));

    info!("About to schedule a periodic timer every five seconds");
    let mut periodic_timer = EspTimerService::new()?.timer(move || {
        info!("Tick from periodic timer");

        let now = EspSystemTime {}.now();

        eventloop.post(&EventLoopMessage::new(now), None).unwrap();

        client
            .publish(
                "rust-esp32-std-demo",
                QoS::AtMostOnce,
                false,
                format!("Now is {:?}", now).as_bytes(),
            )
            .unwrap();
    })?;

    periodic_timer.every(Duration::from_secs(5))?;

    Ok(periodic_timer)
}

#[derive(Copy, Clone, Debug)]
struct EventLoopMessage(Duration);

impl EventLoopMessage {
    pub fn new(duration: Duration) -> Self {
        Self(duration)
    }
}

impl EspTypedEventSource for EventLoopMessage {
    fn source() -> *const c_types::c_char {
        b"DEMO-SERVICE\0".as_ptr() as *const _
    }
}

impl EspTypedEventSerializer<EventLoopMessage> for EventLoopMessage {
    fn serialize<R>(
        event: &EventLoopMessage,
        f: impl for<'a> FnOnce(&'a EspEventPostData) -> R,
    ) -> R {
        f(&unsafe { EspEventPostData::new(Self::source(), Self::event_id(), event) })
    }
}

impl EspTypedEventDeserializer<EventLoopMessage> for EventLoopMessage {
    fn deserialize<R>(
        data: &EspEventFetchData,
        f: &mut impl for<'a> FnMut(&'a EventLoopMessage) -> R,
    ) -> R {
        f(unsafe { data.as_payload() })
    }
}

fn test_eventloop() -> Result<(EspBackgroundEventLoop, EspBackgroundSubscription)> {
    use embedded_svc::event_bus::EventBus;

    info!("About to start a background event loop");
    let mut eventloop = EspBackgroundEventLoop::new(&Default::default())?;

    info!("About to subscribe to the background event loop");
    let subscription = eventloop.subscribe(|message: &EventLoopMessage| {
        info!("Got message from the event loop: {:?}", message.0);
    })?;

    Ok((eventloop, subscription))
}

fn test_mqtt_client() -> Result<EspMqttClient<ConnState<MessageImpl, EspError>>> {
    info!("About to start MQTT client");

    let conf = MqttClientConfiguration {
        client_id: Some(dotenv!("MQTT_CLIENT")),
        crt_bundle_attach: Some(esp_idf_sys::esp_crt_bundle_attach),

        ..Default::default()
    };

    let (mut client, mut connection) = EspMqttClient::new_with_conn(dotenv!("MQTT_SERVER"), &conf)?;

    info!("MQTT client started");

    // Need to immediately start pumping the connection for messages, or else subscribe() and publish() below will not work
    // Note that when using the alternative constructor - `EspMqttClient::new` - you don't need to
    // spawn a new thread, as the messages will be pumped with a backpressure into the callback you provide.
    // Yet, you still need to efficiently process each message in the callback without blocking for too long.
    //
    // Note also that if you go to http://tools.emqx.io/ and then connect and send a message to topic
    // "rust-esp32-std-demo", the client configured here should receive it.
    thread::spawn(move || {
        info!("MQTT Listening for messages");

        while let Some(msg) = connection.next() {
            match msg {
                Err(e) => info!("MQTT Message ERROR: {}", e),
                Ok(msg) => info!("MQTT Message: {:?}", msg),
            }
        }

        info!("MQTT connection loop exit");
    });

    client.subscribe("rust-esp32-std-demo", QoS::AtMostOnce)?;

    info!("Subscribed to all topics (rust-esp32-std-demo)");

    client.publish(
        "rust-esp32-std-demo",
        QoS::AtMostOnce,
        false,
        "Hello from rust-esp32-std-demo!".as_bytes(),
    )?;

    info!("Published a hello message to topic \"rust-esp32-std-demo\"");

    Ok(client)
}

#[cfg(feature = "experimental")]
mod experimental {
    use super::{thread, TcpListener, TcpStream};
    use log::info;

    use esp_idf_sys::c_types;

    pub fn test() -> anyhow::Result<()> {
        #[cfg(not(esp_idf_version = "4.3"))]
        test_tcp_bind_async()?;

        test_https_client()?;

        Ok(())
    }

    #[cfg(not(esp_idf_version = "4.3"))]
    fn test_tcp_bind_async() -> anyhow::Result<()> {
        async fn test_tcp_bind() -> smol::io::Result<()> {
            /// Echoes messages from the client back to it.
            async fn echo(stream: smol::Async<TcpStream>) -> smol::io::Result<()> {
                smol::io::copy(&stream, &mut &stream).await?;
                Ok(())
            }

            // Create a listener.
            let listener = smol::Async::<TcpListener>::bind(([0, 0, 0, 0], 8081))?;

            // Accept clients in a loop.
            loop {
                let (stream, peer_addr) = listener.accept().await?;
                info!("Accepted client: {}", peer_addr);

                // Spawn a task that echoes messages from the client back to it.
                smol::spawn(echo(stream)).detach();
            }
        }

        info!("About to bind a simple echo service to port 8081 using async (smol-rs)!");

        #[allow(clippy::needless_update)]
        {
            esp_idf_sys::esp!(unsafe {
                esp_idf_sys::esp_vfs_eventfd_register(&esp_idf_sys::esp_vfs_eventfd_config_t {
                    max_fds: 5,
                    ..Default::default()
                })
            })?;
        }

        thread::Builder::new().stack_size(4096).spawn(move || {
            smol::block_on(test_tcp_bind()).unwrap();
        })?;

        Ok(())
    }

    fn test_https_client() -> anyhow::Result<()> {
        use embedded_svc::http::{self, client::*, status, Headers, Status};
        use embedded_svc::io::Bytes;
        use esp_idf_svc::http::client::*;

        let url = String::from("https://google.com");

        info!("About to fetch content from {}", url);

        let mut client = EspHttpClient::new(&EspHttpClientConfiguration {
            crt_bundle_attach: Some(esp_idf_sys::esp_crt_bundle_attach),

            ..Default::default()
        })?;

        let response = client.get(&url)?.submit()?;

        let body: Result<Vec<u8>, _> = Bytes::<_, 64>::new(response.reader()).take(3084).collect();

        let body = body?;

        info!(
            "Body (truncated to 3K):\n{:?}",
            String::from_utf8_lossy(&body).into_owned()
        );

        Ok(())
    }
}

#[allow(unused_variables)]
fn httpd(mutex: Arc<(Mutex<Option<u32>>, Condvar)>) -> Result<idf::Server> {
    let server = idf::ServerRegistry::new()
        .at("/")
        .get(|_| Ok("Hello from Rust!".into()))?
        .at("/foo")
        .get(|_| bail!("Boo, something happened!"))?
        .at("/bar")
        .get(|_| {
            Response::new(403)
                .status_message("No permissions")
                .body("You have no permissions to access this page".into())
                .into()
        })?
        .at("/panic")
        .get(|_| panic!("User requested a panic!"))?;

    #[cfg(esp32s2)]
    let server = httpd_ulp_endpoints(server, mutex)?;

    server.start(&Default::default())
}

#[cfg(not(feature = "qemu"))]
#[allow(dead_code)]
fn wifi(
    netif_stack: Arc<EspNetifStack>,
    sys_loop_stack: Arc<EspSysLoopStack>,
    default_nvs: Arc<EspDefaultNvs>,
) -> Result<Box<EspWifi>> {
    let SSID = dotenv!("SSID");
    let PASS = dotenv!("PASS");
    let mut wifi = Box::new(EspWifi::new(netif_stack, sys_loop_stack, default_nvs)?);

    info!("Wifi created, about to scan");

    let ap_infos = wifi.scan()?;

    let ours = ap_infos.into_iter().find(|a| a.ssid == SSID);

    let channel = if let Some(ours) = ours {
        info!(
            "Found configured access point {} on channel {}",
            SSID, ours.channel
        );
        Some(ours.channel)
    } else {
        info!(
            "Configured access point {} not found during scanning, will go with unknown channel",
            SSID
        );
        None
    };

    wifi.set_configuration(&Configuration::Mixed(
        ClientConfiguration {
            ssid: SSID.into(),
            password: PASS.into(),
            channel,
            ..Default::default()
        },
        AccessPointConfiguration {
            ssid: "aptest".into(),
            channel: channel.unwrap_or(1),
            ..Default::default()
        },
    ))?;

    info!("Wifi configuration set, about to get status");

    wifi.wait_status_with_timeout(Duration::from_secs(20), |status| !status.is_transitional())
        .map_err(|e| anyhow::anyhow!("Unexpected Wifi status: {:?}", e))?;

    let status = wifi.get_status();

    if let Status(
        ClientStatus::Started(ClientConnectionStatus::Connected(ClientIpStatus::Done(ip_settings))),
        ApStatus::Started(ApIpStatus::Done),
    ) = status
    {
        info!("Wifi connected");

        ping(&ip_settings)?;
    } else {
        bail!("Unexpected Wifi status: {:?}", status);
    }

    Ok(wifi)
}

#[cfg(any(feature = "qemu", feature = "w5500", feature = "ip101"))]
fn eth_configure<HW>(mut eth: Box<EspEth<HW>>) -> Result<Box<EspEth<HW>>> {
    info!("Eth created");

    eth.set_configuration(&eth::Configuration::Client(Default::default()))?;

    info!("Eth configuration set, about to get status");

    eth.wait_status_with_timeout(Duration::from_secs(10), |status| !status.is_transitional())
        .map_err(|e| anyhow::anyhow!("Unexpected Eth status: {:?}", e))?;

    let status = eth.get_status();

    if let eth::Status::Started(eth::ConnectionStatus::Connected(eth::IpStatus::Done(Some(
        ip_settings,
    )))) = status
    {
        info!("Eth connected");

        ping(&ip_settings)?;
    } else {
        bail!("Unexpected Eth status: {:?}", status);
    }

    Ok(eth)
}

fn ping(ip_settings: &ipv4::ClientSettings) -> Result<()> {
    info!("About to do some pings for {:?}", ip_settings);

    let ping_summary =
        ping::EspPing::default().ping(ip_settings.subnet.gateway, &Default::default())?;
    if ping_summary.transmitted != ping_summary.received {
        bail!(
            "Pinging gateway {} resulted in timeouts",
            ip_settings.subnet.gateway
        );
    }

    info!("Pinging done");

    Ok(())
}

#[cfg(not(feature = "qemu"))]
#[cfg(esp_idf_config_lwip_ipv4_napt)]
fn enable_napt(wifi: &mut EspWifi) -> Result<()> {
    wifi.with_router_netif_mut(|netif| netif.unwrap().enable_napt(true));

    info!("NAPT enabled on the WiFi SoftAP!");

    Ok(())
}
