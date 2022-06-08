// #![allow(unused_imports)]
// #![allow(clippy::single_component_path_imports)]
#![feature(backtrace)]

use core::{fmt::Write as _, time::Duration};

// use embedded_hal::blocking::delay::DelayMs;
use embedded_hal::digital::v2::OutputPin;

use embedded_svc::sys_time::SystemTime;
use embedded_svc::timer::TimerService;
use embedded_svc::timer::*;
use embedded_svc::wifi::*;

use esp_idf_hal::prelude::Hertz;
use esp_idf_hal::serial;
use esp_idf_hal::{i2c, peripherals::Peripherals, units::FromValueType};

use esp_idf_svc::eventloop::*;
use esp_idf_svc::sysloop::*;
use esp_idf_svc::systime::EspSystemTime;
use esp_idf_svc::timer::*;
use esp_idf_svc::wifi::EspWifi;
use esp_idf_svc::{netif::EspNetifStack, nvs::EspDefaultNvs, sysloop::EspSysLoopStack};
use esp_idf_sys::{self, c_types};
use esp_idf_sys::{esp, EspError};

use log::*;
use ssd1306::{prelude::*, I2CDisplayInterface, Ssd1306};
use std::net::TcpStream;
// use std::sync::Arc;
// use std::thread::{self};
use std::{cell::RefCell, env, sync::atomic::*, sync::Arc, thread, time::*};
mod led_strip;
mod mqtt_esp32;
mod solax_x1_air;
mod wifi_init;
use crate::led_strip::{Led, LedState};
use crate::mqtt_esp32::*;
use solax_x1_air::{Status::*, *};

const SSID: &str = "iot";
const SSID2: &str = "Darryn's Wi-Fi Network";
const PASS: &str = "Greyrrs2014!";
const PASS2: &str = "Greyrrs2014!";

const MQTT_ADDR: &str = "10.0.1.72:1883"; // host:port
const MQTT_USERNAME: &str = "evse";
const MQTT_PASSWORD: &str = "Nokiae71!";
const MQTT_CLIENT_ID: &str = "M5Stamp";
const MQTT_TOPIC_NAME: &str = "X1";
const LOOP_DELAY: Duration = Duration::from_millis(1000);
const LOOP_MAX_COUNT: u32 = 60;

thread_local! {
    static TLS: std::cell::RefCell<u32>  = std::cell::RefCell::new(13);
}
/*
Need to qualify MQTT publish with a check on wifi status
Maybe add a state
*/
#[derive(Debug, Default)]
pub struct Device {
    mac: [u8; 6],
    ip: String,
    ssid: String,
    state: String,
}

fn main() -> anyhow::Result<()> {
    // Temporary. Will disappear once ESP-IDF 4.4 is released, but for now it is necessary to call this function once,
    // or else some patches to the runtime implemented by esp-idf-sys might not link properly.
    esp_idf_sys::link_patches();
    let mut device = Device::default();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    #[allow(unused)]
    let netif_stack = Arc::new(EspNetifStack::new()?);
    #[allow(unused)]
    let sys_loop_stack = Arc::new(EspSysLoopStack::new()?);
    #[allow(unused)]
    let default_nvs = Arc::new(EspDefaultNvs::new()?);

    // GPIO setup ****************************

    let peripherals = Peripherals::take().expect("Problem aquiring Peripherals::take()");

    // external LED (on  = low)
    let mut led_green = peripherals.pins.gpio9.into_output()?;
    led_green.set_drive_strength(esp_idf_hal::gpio::DriveStrength::I5mA)?;
    led_green.set_high()?;

    // For UART 1 **************************** (good for RS485)
    let config = serial::config::Config::default().baudrate(Hertz(9_600));
    let userial = serial::Serial::new(
        peripherals.uart1,
        serial::Pins {
            tx: peripherals.pins.gpio19,
            rx: peripherals.pins.gpio18,
            cts: None,
            rts: None,
        },
        config,
    )
    .unwrap();

    // 1306 I2C Display ****************************
    let scl = peripherals
        .pins
        .gpio4
        .into_output()
        .expect("Issue with gpio4 scl pin assignment");
    let sda = peripherals
        .pins
        .gpio5
        .into_input_output()
        .expect("Issue with gpio5 sda pin assignment");

    let _cfg = i2c::config::MasterConfig::new().baudrate(400.kHz().into());

    let i2c = i2c::Master::new(peripherals.i2c0, i2c::MasterPins { sda, scl }, _cfg)
        .expect("Failed to create I2C master");

    let interface = I2CDisplayInterface::new(i2c);
    let mut display =
        Ssd1306::new(interface, DisplaySize128x32, DisplayRotation::Rotate0).into_terminal_mode();

    display
        .init()
        .expect("I2C display init failed, check configuration");

    display.clear().unwrap();
    display
        .set_brightness(ssd1306::prelude::Brightness::DIM)
        .unwrap();

    // LED reworked ****************************
    let mut led = Led::new(
        esp_idf_sys::rmt_channel_t_RMT_CHANNEL_0,
        esp_idf_sys::gpio_num_t_GPIO_NUM_2,
    )?;
    led.set_color(LedState::Off, LedState::Off, LedState::Off)?;

    // Init WiFi network ****************************
    let wifi_test = wifi_init::wifi(
        netif_stack.clone(),
        sys_loop_stack.clone(),
        default_nvs.clone(),
        SSID,
        PASS,
    );

    let wifi = match wifi_test {
        Ok(wifi_good) => {
            writeln!(display, "WiFi: {}", SSID).expect("Failed to write to oled");
            led.set_color(LedState::NC, LedState::On, LedState::NC)?;
            wifi_good
        }
        Err(_) => {
            writeln!(display, "WiFi: {}", SSID2).expect("Failed to write to oled");
            led.set_color(LedState::NC, LedState::On, LedState::NC)?;
            wifi_init::wifi(
                netif_stack.clone(),
                sys_loop_stack.clone(),
                default_nvs.clone(),
                SSID2,
                PASS2,
            )?
        }
    };
    let config = wifi.get_configuration().unwrap();
    println!("WIFI CONFIG:\n{:?}", config);

    //WIFI CONFIG:
    //Client(ClientConfiguration { ssid: "iot", bssid: None, auth_method: WPA2Personal, password: "Greyrrs2014!", channel: None, ip_conf: Some(DHCP(DHCPClientSettings { hostname: None })) })

    // device.ssid = wifi
    //     .get_configuration()
    //     .unwrap()
    //     .as_client_conf_ref()
    //     .unwrap()
    //     .ssid
    //     .to_string();
    // // device.ip = config.as_client_conf_ref().unwrap().ip_conf.;
    // device.mac = wifi.with_router_netif(|w| w.unwrap().get_mac().unwrap());

    // Init MQTT https://github.com/zonyitoo/mqtt-rs
    let mut mqtt_stream = mqtt_esp32::mqtt_connect(
        &wifi,
        MQTT_ADDR,
        MQTT_CLIENT_ID,
        MQTT_USERNAME,
        MQTT_PASSWORD,
    )
    .expect("MQTT not connected");

    let message = format!(
        "Alive on SSID {} at {} with uuid {:?}",
        device.ssid, device.ip, device.mac
    );
    if mqtt_publish(&mut mqtt_stream, MQTT_TOPIC_NAME, &message, 1).is_err() {
        panic!("Init MQTT send failed")
    };

    let mut inverter = SolaxX1Air::new(userial);

    test_atomics();

    test_threads();
    let (eventloop, _subscription) = test_eventloop()?;
    let _timer = test_timer(eventloop, mqtt_stream, inverter, wifi)?;
    loop {}
    /*
    loop {
        if loop_counter % 2 == 0 {
            led_green.set_low()?;
        } else {
            led_green.set_high()?;
        }
        info!("Loop counter at {}", loop_counter);
    */

    /*
        // Main routine goes here
        match inverter.status {
            Offline | Unregistered | Registered => {
                if inverter.init_inverter().is_err() {
                    println!("Inverter comms error, check hardware (recheck in 60 seconds)");
                    thread::sleep(Duration::from_secs(60))
                }
            }
            Online => {
                if inverter.poll_data().is_ok() {
                    // update frequency (min from Solax v1.7 spec)
                    let message = &inverter.data.livedata.active_power.to_string();
                    if wifi_init::check_state(&wifi).is_ok()
                        && mqtt_esp32::mqtt_publish(&mut mqtt_stream, "X1/active_power", message, 0)
                            .is_err()
                    {
                        panic!("MQTT Watts failed")
                    }
                    writeln!(display, "{}W", message).expect("Failed to write to oled");
    */

    //                 if loop_counter >= LOOP_MAX_COUNT {
    //                     // let mqtt_stream_mutex = Arc::clone(&mqtt_stream_arc);
    //                     // let mut mqtt_stream = mqtt_stream_mutex.lock();
    //                     if wifi_init::check_state(&wifi).is_ok() {
    //                         if mqtt_esp32::mqtt_publish(
    //                             &mut mqtt_stream,
    //                             "X1/energy_today",
    //                             &(inverter.data.livedata.energy_today as f32 * 0.1).to_string(),
    //                             0,
    //                         )
    //                         .is_err()
    //                         {
    //                             panic!("MQTT energy_today failed")
    //                         };
    //                         writeln!(
    //                             display,
    //                             "{} * 0.1 kWh",
    //                             &inverter.data.livedata.energy_today
    //                         )
    //                         .expect("Failed to write to oled");

    //                         if mqtt_esp32::mqtt_publish(
    //                             &mut mqtt_stream,
    //                             "X1/temperature",
    //                             &inverter.data.livedata.temperature.to_string(),
    //                             0,
    //                         )
    //                         .is_err()
    //                         {
    //                             panic!("MQTT temp failed")
    //                         };
    //                         writeln!(display, "{} celsius", &inverter.data.livedata.temperature)
    //                             .expect("Failed to write to oled");
    //                     }
    //                 }
    //             }
    //         }
    //     }
    //     // Main routine ends here

    //     if loop_counter == LOOP_MAX_COUNT {
    //         loop_counter = 0;
    //     }
    //     loop_counter += 1;
    //     thread::sleep(LOOP_DELAY);
    // }
}

fn poll_inverter(
    mut eventloop: EspBackgroundEventLoop,
    mut mqtt_stream: TcpStream,
    mut inverter: SolaxX1Air,
    wifi: Box<EspWifi>,
) -> anyhow::Result<EspTimer> {
    use embedded_svc::event_bus::Postbox;

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
                }
            }
            Online => {
                if inverter.poll_data().is_ok() {
                    // update frequency (min from Solax v1.7 spec)
                    let message = &inverter.data.livedata.active_power.to_string();
                    if wifi_init::check_state(&wifi).is_ok()
                        && mqtt_esp32::mqtt_publish(&mut mqtt_stream, "X1/active_power", message, 0)
                            .is_err()
                    {
                        panic!("MQTT Watts failed")
                    }
                    // writeln!(display, "{}W", message).expect("Failed to write to oled");
                }
            }
        }
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

fn test_eventloop() -> anyhow::Result<(EspBackgroundEventLoop, EspBackgroundSubscription)> {
    use embedded_svc::event_bus::EventBus;

    info!("About to start a background event loop");
    let mut eventloop = EspBackgroundEventLoop::new(&Default::default())?;

    info!("About to subscribe to the background event loop");
    let subscription = eventloop.subscribe(|message: &EventLoopMessage| {
        info!("Got message from the event loop: {:?}", message.0);
    })?;

    Ok((eventloop, subscription))
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
