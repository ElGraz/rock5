use configparser::ini::Ini;
use dirs::config_dir;
use std::path::PathBuf;

const CFG_PATH: &str = "rock5/config.ini";
const MAIN_CFG: &str = "config";

#[derive(Debug)]
pub struct Config {
    host: String,
    port: i32,
}

impl Config{
    pub fn get_host_str (&mut self)-> String {format!("{}:{}", self.host, self.port)}    
}

pub fn get_config() -> Config {
    let mut port: i32 = 1080;
    let mut host: String = "0.0.0.0".to_string();
    let cfg_opt = config_dir();
    let mut cfg_path: PathBuf;
    match cfg_opt {
        None => {
            cfg_path = PathBuf::new();
        }
        Some(path) => {
            cfg_path = path;
        }
    }
    cfg_path = cfg_path.join(CFG_PATH);
    println!(" -> Trying to read config form {cfg_path:?}");

    let mut config = Ini::new();
    let map_res = config.load(cfg_path);

    match map_res {
        Ok(res) => {
            let gco = res.get(MAIN_CFG);
            if let Some(gc) = gco {
                // Port
                let kpo = gc.get("port");
                if let Some(ppo) = kpo {
                    if let Some(pstr) = ppo {
                        let pparse = pstr.parse::<i32>();
                        match pparse {
                            Ok(pval) => {
                                port = pval;
                            }
                            Err(e) => panic!("invalid port in config: '{port:?}' ({e:?})"),
                        }
                    }
                }
                // Host
                let kho = gc.get("host");
                if let Some(hco) = kho {
                    if let Some(h) = hco {
                        host = h.to_string();
                    }
                }
            }
        }
        Err(e) => println!("invalid config: {e:?}"),
    }

    return Config {
        port: port,
        host: host,
    };
}
