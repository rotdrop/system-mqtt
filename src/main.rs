use anyhow::{bail, Context, Result};
use argh::FromArgs;
use mqtt_async_client::client::{Client as MqttClient, Publish};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    os::unix::prelude::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};
use sysinfo::{CpuExt, DiskExt, System, SystemExt};
use tokio::{fs, signal, time};
use url::Url;

use battery::units::electric_potential::volt;
use battery::units::electric_current::ampere;
use battery::units::energy::watt_hour;
use battery::units::power::watt;
use battery::units::ratio::percent;
use battery::units::thermodynamic_temperature::degree_celsius;
use battery::units::time::second;
/// use battery::units::Unit;
/// use battery::State;

use inflector::cases::titlecase::to_title_case;
use inflector::cases::snakecase::to_snake_case;

const KEYRING_SERVICE_NAME: &str = "system-mqtt";

#[derive(FromArgs)]
/// Push system statistics to an mqtt server.
struct Arguments {
    /// the configuration file we are to use.
    #[argh(option, default = "PathBuf::from(\"/etc/system-mqtt.yaml\")")]
    config_file: PathBuf,

    #[argh(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Run(RunArguments),
    SetPassword(SetPasswordArguments),
}

#[derive(FromArgs, PartialEq, Debug)]
/// Run the daemon.
#[argh(subcommand, name = "run")]
struct RunArguments {
    /// log to stderr instead of systemd's journal.
    #[argh(switch)]
    log_to_stderr: bool,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Set the password used to log into the mqtt client.
#[argh(subcommand, name = "set-password")]
struct SetPasswordArguments {}

#[derive(Serialize, Deserialize)]
struct DriveConfig {
    path: PathBuf,
    name: String,
}

#[derive(Serialize, Deserialize)]
enum PasswordSource {
    #[serde(rename = "keyring")]
    Keyring,

    #[serde(rename = "secret_file")]
    SecretFile(PathBuf),
}

impl Default for PasswordSource {
    fn default() -> Self {
        Self::Keyring
    }
}

#[derive(Serialize, Deserialize)]
struct Config {
    /// The URL of the mqtt server.
    mqtt_server: Url,

    /// Set the username to connect to the mqtt server, if required.
    /// The password will be fetched from the OS keyring.
    username: Option<String>,

    /// Where the password for the MQTT server can be found.
    /// If a username is not specified, this field is ignored.
    /// If not specified, this field defaults to the keyring.
    #[serde(default)]
    password_source: PasswordSource,

    /// The interval to update at.
    update_interval: Duration,

    /// The names of drives, or the paths to where they are mounted.
    drives: Vec<DriveConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mqtt_server: Url::parse("mqtt://localhost").expect("Failed to parse default URL."),
            username: None,
            password_source: PasswordSource::Keyring,
            update_interval: Duration::from_secs(30),
            drives: vec![DriveConfig {
                path: PathBuf::from("/"),
                name: String::from("root"),
            }],
        }
    }
}

#[tokio::main]
async fn main() {
    let arguments: Arguments = argh::from_env();

    match load_config(&arguments.config_file).await {
        Ok(config) => match arguments.command {
            SubCommand::Run(arguments) => {
                if arguments.log_to_stderr {
                    simple_logger::SimpleLogger::new()
                        .env()
                        .init()
                        .expect("Failed to setup log.");
                } else {
                    systemd_journal_logger::init().expect("Failed to setup log.");
                }

                log::set_max_level(log::LevelFilter::Info);

                while let Err(error) = application_trampoline(&config).await {
                    log::error!("Fatal error: {}", error);
                }
            }
            SubCommand::SetPassword(_arguments) => {
                if let Err(error) = set_password(config).await {
                    eprintln!("Fatal error: {}", error);
                }
            }
        },
        Err(error) => {
            eprintln!("Failed to load config file: {}", error);
        }
    }
}

async fn load_config(path: &Path) -> Result<Config> {
    if path.is_file() {
        // It's a readable file we can load.

        let config: Config = serde_yaml::from_str(&fs::read_to_string(path).await?)
            .context("Failed to deserialize config file.")?;

        Ok(config)
    } else {
        log::info!("No config file present. A default one will be written.");
        // Doesn't exist yet. We'll create it.
        let config = Config::default();

        // Write it to a file for next time we load.
        fs::write(path, serde_yaml::to_string(&config)?).await?;

        Ok(config)
    }
}

async fn set_password(config: Config) -> Result<()> {
    if let Some(username) = config.username {
        let password = rpassword::prompt_password("Password: ")
            .context("Failed to read password from TTY.")?;

        let keyring = keyring::Entry::new(KEYRING_SERVICE_NAME, &username)
            .context("Failed to find password entry in keyring.")?;
        keyring.set_password(&password).context("Keyring error.")?;

        Ok(())
    } else {
        bail!("You must set the username for login with the mqtt server before you can set the user's password")
    }
}

async fn application_trampoline(config: &Config) -> Result<()> {
    log::info!("Application start.");

    let mut client_builder = MqttClient::builder();
    client_builder.set_url_string(config.mqtt_server.as_str())?;

    // If credentials are provided, use them.
    if let Some(username) = &config.username {
        // TODO make TLS mandatory when using a password.

        let password = match &config.password_source {
            PasswordSource::Keyring => {
                log::info!("Using system keyring for MQTT password source.");
                let keyring = keyring::Entry::new(KEYRING_SERVICE_NAME, username)
                    .context("Failed to find password entry in keyring.")?;
                keyring
                    .get_password()
                    .context("Failed to get password from keyring. If you have not yet set the password, run `system-mqtt set-password`.")?
            }
            PasswordSource::SecretFile(file_path) => {
                log::info!("Using hidden file for MQTT password source.");
                let metadata = file_path
                    .metadata()
                    .context("Failed to get password file metadata.")?;

                // It's not even an encrypted file, so we need to keep the permission settings pretty tight.
                // The only time I can really enforce that is when reading the password.
                if metadata.mode() & 0o777 == 0o600 {
                    if metadata.uid() == users::get_current_uid() {
                        if metadata.gid() == users::get_current_gid() {
                            let pass: String = fs::read_to_string(file_path)
                                .await
                                .context("Failed to read password file.")?;
                            pass.as_str().trim_end().to_string()
                        } else {
                            bail!("Password file must be owned by the current group.");
                        }
                    } else {
                        bail!("Password file must be owned by the current user.");
                    }
                } else {
                    bail!("Permission bits for password file must be set to 0o600 (only owner can read and write)");
                }
            }
        };

        client_builder.set_username(Some(username.into()));
        client_builder.set_password(Some(password.as_bytes().to_vec()));
    }

    let mut client = client_builder.build()?;
    client
        .connect()
        .await
        .context("Failed to connect to MQTT server.")?;

    let manager = battery::Manager::new().context("Failed to initalize battery monitoring.")?;

    let mut system = System::new_all();

    let hostname = system
        .host_name()
        .context("Could not get system hostname.")?;

    let mut home_assistant = HomeAssistant {
        client,
        hostname,
        registered_topics: HashSet::new(),
    };

    // Register the various sensor topics and include the details about that sensor

    //    TODO - create a new register_topic to register binary_sensor so we can make availability a real binary sensor. In the
    //    meantime, create it as a normal analog sensor with two values, and a template can be used to make it a binary.

    home_assistant
        .register_topic(
            "sensor",
            None,
            None,
	    None,
            Some("available"),
            None,
            Some("mdi:check-network-outline"),
        )
        .await
        .context("Failed to register availability topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            None,
            Some("measurement"),
	    None,
            Some("uptime"),
            Some("seconds"),
            Some("mdi:timer-sand"),
        )
        .await
        .context("Failed to register uptime topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            None,
            Some("measurement"),
	    Some("Central Processing Unit"),
            Some("cpu"),
            Some("%"),
            Some("mdi:gauge"),
        )
        .await
        .context("Failed to register CPU usage topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            None,
            Some("measurement"),
	    None,
            Some("memory"),
            Some("%"),
            Some("mdi:gauge"),
        )
        .await
        .context("Failed to register memory usage topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            None,
            Some("measurement"),
	    None,
            Some("swap"),
            Some("%"),
            Some("mdi:gauge"),
        )
        .await
        .context("Failed to register swap usage topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            Some("battery"),
            Some("measurement"),
            Some("battery level"),
	    None,
            Some("%"),
            Some("mdi:battery"),
        )
        .await
        .context("Failed to register battery level topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            Some("battery"),
            Some("measurement"),
            Some("battery health"),
	    None,
            Some("%"),
            Some("mdi:battery-alert"),
        )
        .await
        .context("Failed to register battery health topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            Some("battery"),
            Some("measurement"),
            Some("battery voltage"),
	    None,
            Some("V"),
            Some("mdi:sine-wave"),
        )
        .await
        .context("Failed to register battery voltage topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            Some("current"),
            Some("measurement"),
            Some("battery current"),
	    None,
            Some("A"),
            Some("mdi:current-dc"),
        )
        .await
        .context("Failed to register battery current topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            Some("power"),
            Some("measurement"),
            Some("battery power"),
	    None,
            Some("W"),
            Some("mdi:flash"),
        )
        .await
        .context("Failed to register battery power topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            Some("energy"),
            Some("measurement"),
            Some("battery energy"),
	    None,
            Some("Wh"),
            Some("mdi:lightning-bolt"),
        )
        .await
        .context("Failed to register battery current energy topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            Some("energy"),
            Some("measurement"),
            Some("battery energy full"),
	    None,
            Some("Wh"),
            Some("mdi:lightning-bolt"),
        )
        .await
        .context("Failed to register battery last full energy topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            Some("energy"),
            Some("measurement"),
            Some("battery energy full design"),
	    None,
            Some("Wh"),
            Some("mdi:lightning-bolt"),
        )
        .await
        .context("Failed to register battery full design energy topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            None,
            Some("measurement"),
            Some("battery time to full"),
	    None,
            Some("seconds"),
            Some("mdi:timer-sand"),
        )
        .await
        .context("Failed to register battery time to full topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            None,
            Some("measurement"),
            Some("battery time to empty"),
	    None,
            Some("seconds"),
            Some("mdi:timer-sand"),
        )
        .await
        .context("Failed to register battery time to empty topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            Some("temperature"),
            Some("measurement"),
            Some("battery temperature"),
	    None,
            Some("°C"),
            Some("mdi:thermometer"),
        )
        .await
        .context("Failed to register battery temperature topic.")?;
    home_assistant
        .register_topic(
            "sensor",
            None,
            None,
            Some("battery state"),
	    None,
            None,
            Some("mdi:battery"),
        )
        .await
        .context("Failed to register battery state topic.")?;

    // Register the sensors for filesystems
    for drive in &config.drives {
        home_assistant
            .register_topic(
                "sensor",
                None,
                Some("total"),
                Some(&drive.name),
		None,
                Some("%"),
                Some("mdi:folder"),
            )
            .await
            .context("Failed to register a filesystem topic.")?;
    }

    home_assistant.set_available(true).await?;

    let result = availability_trampoline(&home_assistant, &mut system, config, manager).await;

    if let Err(error) = home_assistant.set_available(false).await {
        // I don't want this error hiding whatever happened in the main loop.
        log::error!("Error while disconnecting from home assistant: {:?}", error);
    }

    result?;

    home_assistant.disconnect().await?;

    Ok(())
}

async fn availability_trampoline(
    home_assistant: &HomeAssistant,
    system: &mut System,
    config: &Config,
    manager: battery::Manager,
) -> Result<()> {
    let drive_list: HashMap<PathBuf, String> = config
        .drives
        .iter()
        .map(|drive_config| (drive_config.path.clone(), drive_config.name.clone()))
        .collect();

    system.refresh_disks();
    system.refresh_memory();
    system.refresh_cpu();

    loop {
        tokio::select! {
            _ = time::sleep(config.update_interval) => {
                system.refresh_disks();
                system.refresh_memory();
                system.refresh_cpu();

                // Report uptime.
                let uptime = system.uptime(); //  as f32 / 60.0 / 60.0 / 24.0; // Convert from seconds to days.
                home_assistant.publish("uptime", format!("{}", uptime)).await;

                // Report CPU usage.
                let cpu_usage = (system.cpus().iter().map(|cpu| cpu.cpu_usage()).sum::<f32>()) / (system.cpus().len() as f32 * 100.0);
                home_assistant.publish("cpu", (cpu_usage * 100.0).to_string()).await;

                // Report memory usage.
                let memory_percentile = (system.total_memory() - system.available_memory()) as f64 / system.total_memory() as f64;
                home_assistant.publish("memory", (memory_percentile.clamp(0.0, 1.0)* 100.0).to_string()).await;

                // Report swap usage.
                let swap_percentile = system.used_swap() as f64 / system.free_swap() as f64;
                home_assistant.publish("swap", (swap_percentile.clamp(0.0, 1.0) * 100.0).to_string()).await;

                // Report filesystem usage.
                for drive in system.disks() {
                    if let Some(drive_name) = drive_list.get(drive.mount_point()) {
                        let drive_percentile = (drive.total_space() - drive.available_space()) as f64 / drive.total_space() as f64;

                        home_assistant.publish(drive_name, (drive_percentile.clamp(0.0, 1.0) * 100.0).to_string()).await;
                    }
                }

                // TODO we should probably combine the battery charges, but for now we're just going to use the first detected battery.
                if let Some(battery) = manager.batteries().context("Failed to read battery info.")?.flatten().next() {
                    use battery::State;

                    let battery_state = match battery.state() {
                        State::Charging => "charging",
                        State::Discharging => "discharging",
                        State::Empty => "empty",
                        State::Full => "full",
                        _ => "None",
                    };
                    home_assistant.publish("battery_state", battery_state.to_string()).await;

		    let battery_level = battery.state_of_charge().get::<percent>();
		    let battery_health = battery.state_of_health().get::<percent>();

		    let battery_voltage = battery.voltage().get::<volt>();
		    let battery_current = battery.current().get::<ampere>();

		    let battery_power = battery.energy_rate().get::<watt>();
                    let battery_energy = battery.energy().get::<watt_hour>();
                    let battery_energy_full = battery.energy_full().get::<watt_hour>();
                    let battery_energy_full_design = battery.energy_full().get::<watt_hour>();

		    let battery_time_to_full = match battery.time_to_full() {
			Some(time) => time.get::<second>().to_string(),
			None => "None".to_string(),
		    };
		    let battery_time_to_empty = match  battery.time_to_empty() {
			Some(time) => time.get::<second>().to_string(),
			None => "None".to_string(),
		    };

 		    let battery_temperature = match battery.temperature() {
			Some(value) => value.get::<degree_celsius>().to_string(),
			None => "None".to_string(),
		    };

                    home_assistant.publish("battery_level", format!("{:03}", battery_level)).await;
                    home_assistant.publish("battery_health", format!("{:03}", battery_health)).await;

		    home_assistant.publish("battery_voltage", format!("{:03}", battery_voltage)).await;
		    home_assistant.publish("battery_current", format!("{:03}", battery_current)).await;

                    home_assistant.publish("battery_power", format!("{:03}", battery_power)).await;
		    home_assistant.publish("battery_energy", format!("{:03}", battery_energy)).await;
		    home_assistant.publish("battery_energy_full", format!("{:03}", battery_energy_full)).await;
		    home_assistant.publish("battery_energy_full_design", format!("{:03}", battery_energy_full_design)).await;

                    home_assistant.publish("battery_time_to_empty", battery_time_to_empty).await;
                    home_assistant.publish("battery_time_to_full", battery_time_to_full).await;

                    home_assistant.publish("battery_temperature", battery_temperature).await;
		}
            }
            _ = signal::ctrl_c() => {
                log::info!("Terminate signal has been received.");
                break;
            }
        }
    }

    Ok(())
}

pub struct HomeAssistant {
    client: MqttClient,
    hostname: String,
    registered_topics: HashSet<String>,
}

impl HomeAssistant {
    pub async fn set_available(&self, available: bool) -> Result<()> {
        self.client
            .publish(
                Publish::new(
                    format!("system-mqtt/{}/availability", self.hostname),
                    if available { "online" } else { "offline" }.into(),
                )
                .set_retain(true),
            )
            .await
            .context("Failed to publish availability topic.")
    }

    pub async fn register_topic(
        &mut self,
        topic_class: &str,
        device_class: Option<&str>,
        state_class: Option<&str>,
	display_name: Option<&str>,
	topic_name: Option<&str>,
        unit_of_measurement: Option<&str>,
        icon: Option<&str>,
    ) -> Result<()> {
        #[derive(Serialize)]
	struct TopicDeviceConfig {
	    identifiers: Vec<String>,
	    name: String,
	    model: String,
	    manufacturer: String,
	}

        #[derive(Serialize)]
        struct TopicConfig {
            name: String,
	    unique_id: String,
	    object_id: String,
	    device: TopicDeviceConfig,

            #[serde(skip_serializing_if = "Option::is_none")]
            device_class: Option<String>,
            state_class: Option<String>,
            state_topic: String,
            unit_of_measurement: Option<String>,
            icon: Option<String>,
        }

	let display_name = match display_name {
	    Some(value) => value,
	    None => {
		match topic_name {
		    Some(topic) => topic,
		    None => {
			log::error!("Display name and topic name are both None, one of them must be given.");
			return Ok(())
		    }
		}
	    }
	};
	let topic_name = to_snake_case(match topic_name {
	    Some(value) => value,
	    None => display_name,
	}.as_ref());

        log::info!("Registering topic `{}`.", topic_name);

        let message = serde_json::ser::to_string(&TopicConfig {
            name: to_title_case(format!("{} {}", self.hostname, display_name).as_ref()),
	    unique_id: format!("system_mqtt_{}_{}", self.hostname, topic_name),
	    object_id: format!("system_mqtt_{}_{}", self.hostname, topic_name),
            device_class: device_class.map(str::to_string),
            state_class: state_class.map(str::to_string),
            state_topic: format!("system-mqtt/{}/{}", self.hostname, topic_name),
            unit_of_measurement: unit_of_measurement.map(str::to_string),
            icon: icon.map(str::to_string),
	    device: TopicDeviceConfig {
		name: format!("System MQTT {}", to_title_case(self.hostname.as_ref())),
		identifiers: vec![format!("system_mqtt_{}", self.hostname)],
		model: "Linux Computer".to_string(),
		manufacturer: "Open Source Community".to_string(),
	    },
        })
        .context("Failed to serialize topic information.")?;
        let mut publish = Publish::new(
            format!(
                "homeassistant/{}/system-mqtt-{}/{}/config",
                topic_class, self.hostname, topic_name
            ),
            message.into(),
        );
        publish.set_retain(true);
        self.client
            .publish(&publish)
            .await
            .context("Failed to publish topic to MQTT server.")?;

        self.registered_topics.insert(topic_name.to_string());

        log::info!("Registered topic `{}`.", format!(
            "homeassistant/{}/system-mqtt-{}/{}/config",
            topic_class, self.hostname, topic_name
        ));

        Ok(())
    }

    pub async fn publish(&self, topic_name: &str, value: String) {
	let topic_name: String = to_snake_case(topic_name);

        log::debug!("PUBLISH `{}` TO `{}`", value, topic_name);

	let mqtt_topic = format!("system-mqtt/{}/{}", self.hostname, topic_name);

        if self.registered_topics.contains::<String>(&topic_name) {
	    log::info!("Publish {} to `{}`.",  value, mqtt_topic);
            let mut publish = Publish::new(mqtt_topic.into(), value.into());
            publish.set_retain(false);

            if let Err(error) = self.client.publish(&publish).await {
                log::error!("Failed to publish topic `{}`: {:?}", topic_name, error);
            }
        } else {
            log::error!(
                "Attempt to publish topic `{}`, which was never registered with Home Assistant.",
                topic_name
            );
        }
    }

    pub async fn disconnect(mut self) -> Result<()> {
        self.set_available(false).await?;
        self.client.disconnect().await?;

        Ok(())
    }
}
