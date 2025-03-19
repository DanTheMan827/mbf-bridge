use tokio::net::TcpListener;

pub struct ServerInfo {
    pub listener: Option<TcpListener>,
    pub assigned_ip: String,
    pub assigned_port: u16,
    pub assigned_url: String,
}

impl ServerInfo {
    pub async fn new(create_listener: bool, assigned_ip: String, assigned_port: Option<u16>) -> Self {
        let assigned_port = assigned_port.unwrap_or(0);
        let listener: Option<TcpListener> = if create_listener {
            Some(TcpListener::bind(format!("{}:{}", assigned_ip, assigned_port)).await.unwrap())
        } else {
            None
        };

        let assigned_url:String = if let Some(ref listener) = listener {
            let local_addr = listener.local_addr().unwrap();
            let assigned_port = local_addr.port();

            format!("http://{}:{}", assigned_ip, assigned_port)
        } else {
            format!("http://{}:{}", assigned_ip, assigned_port)
        };

        Self {
            listener: listener,
            assigned_ip,
            assigned_port,
            assigned_url,
        }
    }
}
