use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    ConfigCheck,
    TestLogin,
    SyncUsers,
    ClearState,
}

fn parse_command(arguments: &[String]) -> Result<Command, &'static str> {
    match arguments {
        [config, check] if config == "config" && check == "check" => Ok(Command::ConfigCheck),
        [command] if command == "test-login" => Ok(Command::TestLogin),
        [command] if command == "sync-users" => Ok(Command::SyncUsers),
        [command] if command == "clear-state" => Ok(Command::ClearState),
        _ => Err("usage: himmelcloak-cli <config check|test-login|sync-users|clear-state>"),
    }
}

fn parse_config(contents: &str) -> Result<(), toml::de::Error> {
    toml::from_str::<toml::Value>(contents).map(|_| ())
}

fn check_config(path: &Path) -> Result<(), String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;

    parse_config(&contents).map_err(|error| format!("invalid {}: {error}", path.display()))
}

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();

    match parse_command(&arguments) {
        Ok(Command::ConfigCheck) => match check_config(Path::new("himmelcloak.toml")) {
            Ok(()) => {
                println!("himmelcloak-cli: himmelcloak.toml is valid");
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("himmelcloak-cli: {message}");
                ExitCode::FAILURE
            }
        },
        Ok(Command::TestLogin) => {
            println!("himmelcloak-cli: test-login is not implemented yet");
            ExitCode::SUCCESS
        }
        Ok(Command::SyncUsers) => {
            println!("himmelcloak-cli: sync-users is not implemented yet");
            ExitCode::SUCCESS
        }
        Ok(Command::ClearState) => {
            println!("himmelcloak-cli: clear-state is not implemented yet");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
