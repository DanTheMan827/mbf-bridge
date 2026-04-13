pub struct InternalWindowConfig {
    pub width: f64,
    pub height: f64,
    pub min_width: f64,
    pub min_height: f64,
    pub resizable: bool,
    pub devtools: bool,
    pub title: String,
    pub modifier_key: String,
    pub init_script: String,
}

impl Default for InternalWindowConfig {
    #[allow(dead_code)]
    fn default() -> Self {
        Self {
            width: 1024.0,
            height: 768.0,
            min_width: 1024.0,
            min_height: 768.0,
            resizable: true,
            devtools: cfg!(debug_assertions),
            title: "".into(),
            modifier_key: "".into(),
            init_script: "".into(),
        }
    }
}

impl InternalWindowConfig {
    #[allow(dead_code)]
    fn get_title(&self) -> String {
        if self.title.is_empty() {
            format!("{}", self.title)
        } else {
            format!("ModsBeforeFriday Bridge – {}", self.title)
        }
    }
    
    #[allow(dead_code)]
    pub fn set_size(&mut self, width: f64, height: f64) -> &mut Self {
        self.width = width;
        self.height = height;
        
        self
    }
    
    #[allow(dead_code)]
    pub fn set_min_size(&mut self, min_width: f64, min_height: f64) -> &mut Self {
        self.min_width = min_width;
        self.min_height = min_height;
        
        self
    }
    
    #[allow(dead_code)]
    pub fn set_resizable(&mut self, resizable: bool) -> &mut Self {
        self.resizable = resizable;
        
        self
    }
    
    #[allow(dead_code)]
    pub fn set_devtools(&mut self, devtools: bool) -> &mut Self {
        self.devtools = devtools;
        
        self
    }
    
    #[allow(dead_code)]
    pub fn set_title(&mut self, title: &str) -> &mut Self {
        self.title = title.into();
        
        self
    }
    
    #[allow(dead_code)]
    pub fn set_modifier_key(&mut self, modifier_key: &str) -> &mut Self {
        self.modifier_key = modifier_key.into();
        
        self
    }
    
    #[allow(dead_code)]
    pub fn set_init_script(&mut self, init_script: &str) -> &mut Self {
        self.init_script = init_script.into();
        
        self
    }
}

pub mod internal_pages {
    pub const SHIFT: &str = "mbf://localhost/shift";
    pub const HELP: &str = "mbf://localhost/help";
    pub const TEST: &str = "mbf://localhost/test";
}

/// Creates the launch-options window (label = `"shift"`).
#[cfg(not(target_os = "android"))]
pub fn create_internal_window(
    app: &tauri::App,
    url: &str,
    config: &InternalWindowConfig,
) -> tauri::Result<tauri::WebviewWindow> {
    let mut init_script: Vec<String> = Vec::new();
    
    if !config.modifier_key.is_empty() {
        let modifier_key_json = serde_json::to_string(&config.modifier_key).unwrap_or("null".to_string());
        init_script.push(format!("window.__mbfModifierKey={};", modifier_key_json));
    }
    
    if !config.init_script.is_empty() {
        init_script.push(config.init_script.to_string());
    }
    
    let builder = tauri::WebviewWindowBuilder::new(
        app,
        "shift",
        tauri::WebviewUrl::CustomProtocol(
            url::Url::parse(url).unwrap(),
        ),
    )
    .title(config.get_title().clone())
    .inner_size(config.width, config.height)
    .min_inner_size(config.min_width, config.min_height)
    .resizable(config.resizable)
    .devtools(config.devtools);
    
    let builder = if init_script.is_empty() {
        builder
    } else {
        let init_script = init_script.join("");
        builder.initialization_script(&init_script)
    };
    
    return builder.build();
}

#[cfg(not(target_os = "android"))]
pub fn create_shift_window(
    app: &tauri::App,
    modifier_key: &str,
) {
    let mut config = InternalWindowConfig::default();
    let config = config
        .set_title("Launch Options")
        .set_modifier_key(modifier_key);

    let _ = create_internal_window(app, internal_pages::SHIFT, config);
}

#[cfg(not(target_os = "android"))]
pub fn create_help_window(app: &tauri::App) {
    let mut config = InternalWindowConfig::default();
    let config = config
        .set_title("Help");

    let _ = create_internal_window(app, internal_pages::HELP, config);
}

#[cfg(not(target_os = "android"))]
pub fn create_test_window(app: &tauri::App) {
    let mut config = InternalWindowConfig::default();
    let config = config
        .set_title("Test");

    let _ = create_internal_window(app, internal_pages::TEST, config);
}