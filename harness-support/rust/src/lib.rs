use models::Limbo;

pub mod models;

pub fn load_limbo() -> Limbo {
    #[cfg(not(debug_assertions))]
    {
        serde_json::from_reader(std::io::stdin()).unwrap()
    }
    #[cfg(debug_assertions)]
    {
        use std::fs::File;
        use std::path::Path;
        let f = File::open(Path::new("limbo_small.json")).unwrap();
        serde_json::from_reader(f).unwrap()
    }
}
