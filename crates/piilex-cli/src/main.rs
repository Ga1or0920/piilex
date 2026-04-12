mod app;
mod commands;
mod output;

use anyhow::Result;

fn main() -> Result<()> {
    app::run()
}
